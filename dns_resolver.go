package redirdns

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const (
	// Default DNS lookup timeout per request
	defaultDnsLookupTimeout = 2 * time.Second

	// Maximum allowed DNS lookup timeout — guards against goroutine accumulation
	// since lookups run on context.Background() and are not bounded by request lifetime
	maxLookupTimeout = 30 * time.Second

	// Default DNS TXT cache TTL
	defaultDnsCacheTTL = 30 * time.Second

	// Default DNS TXT negative cache TTL (applied to failed/NXDOMAIN lookups)
	defaultNegativeCacheTTL = 5 * time.Second

	// Default maximum number of DNS TXT cache entries
	defaultMaxCacheSize = 10_000
)

// errNoTXTRecord is returned by the resolver when a DNS query succeeds but returns
// no TXT records. It is also cached so that repeat lookups for non-existent records
// do not hammer the upstream resolver.
var errNoTXTRecord = errors.New("no TXT DNS record found")

// dnsCacheEntry holds the result of a DNS TXT lookup together with its expiry time.
// Both successful results and errors are cached so that repeated lookups for
// non-existent or broken records do not hammer the upstream resolver.
type dnsCacheEntry struct {
	txt       []string
	err       error
	cachedAt  time.Time // when the entry was stored; used to compute Cache-Control max-age and Age
	expiresAt time.Time
}

// lookupTXT returns the DNS TXT records for query, serving from the in-memory cache
// when a fresh entry exists. Concurrent requests for the same query are coalesced by
// singleflight so that only one upstream DNS lookup is issued regardless of how many
// requests arrive simultaneously. The returned bool is true when the result was served
// directly from the outer cache (i.e. no upstream lookup was triggered by this call).
func (rd *RedirDns) lookupTXT(query string) ([]string, error, bool) {
	now := time.Now()
	if txt, err, found := rd.cachedLookup(query, now); found {
		return txt, err, true
	}

	value, _, _ := rd.dnsCache.group.Do(query, func() (any, error) {
		// re-check the cache inside the singleflight closure: a previous call for the
		// same key may have populated it between the outer cache miss and acquiring the
		// singleflight slot
		checkNow := time.Now()
		if txt, err, found := rd.cachedLookup(query, checkNow); found {
			return dnsCacheEntry{txt: txt, err: err}, nil
		}

		// DNS lookups run on context.Background() with a fixed timeout, deliberately
		// decoupled from the request context so that cancellation of one caller's
		// request does not abort the lookup for all other waiting callers
		lookupCtx, cancel := context.WithTimeout(context.Background(), rd.lookupMax)
		defer cancel()
		var (
			txt    []string
			dnsTTL time.Duration
			err    error
		)
		if rd.lookupFunc != nil {
			txt, dnsTTL, err = rd.lookupFunc(lookupCtx, query)
		} else {
			txt, err = rd.resolver.LookupTXT(lookupCtx, query)
			// net.Resolver does not expose TTL; dnsTTL remains 0 so the
			// configured cache_ttl is used unchanged
		}
		if err == nil && len(txt) == 0 {
			err = errNoTXTRecord
		}

		// failed lookups use the (shorter) negative cache TTL; successful lookups
		// honour the DNS record TTL when it is larger than the configured cache TTL
		var cacheTTL time.Duration
		if err != nil {
			cacheTTL = rd.negativeLookupTTL
		} else {
			cacheTTL = rd.lookupTTL
			if dnsTTL > cacheTTL {
				cacheTTL = dnsTTL
			}
		}
		entry := dnsCacheEntry{
			txt:       txt, // fresh slice from lookupFunc/resolver; copied on read in cachedLookup and on return below
			err:       err,
			cachedAt:  checkNow,
			expiresAt: checkNow.Add(cacheTTL),
		}
		rd.storeLookup(query, entry)

		return entry, nil
	})

	// two-value assertion: if the singleflight call returned a zero value (e.g. due
	// to an unexpected panic in a concurrent caller), entry is the zero dnsCacheEntry
	// which is treated as a cache miss rather than crashing the server
	entry, _ := value.(dnsCacheEntry)
	return append([]string(nil), entry.txt...), entry.err, false
}

// remainingCacheTTL returns the time until the cached entry for query expires.
// Returns (0, false) when no live entry exists in the cache.
func (rd *RedirDns) remainingCacheTTL(query string) (time.Duration, bool) {
	now := time.Now()
	rd.dnsCache.mu.RLock()
	entry, ok := rd.dnsCache.entries[query]
	rd.dnsCache.mu.RUnlock()
	if !ok || now.After(entry.expiresAt) {
		return 0, false
	}
	return entry.expiresAt.Sub(now), true
}

// cacheTiming returns the full cache TTL (max-age = expiresAt − cachedAt) and the
// elapsed time since the entry was stored (age = now − cachedAt) for query.
// Returns (0, 0, false) when no live entry exists in the cache.
func (rd *RedirDns) cacheTiming(query string) (maxAge, age time.Duration, ok bool) {
	now := time.Now()
	rd.dnsCache.mu.RLock()
	entry, exists := rd.dnsCache.entries[query]
	rd.dnsCache.mu.RUnlock()
	if !exists || now.After(entry.expiresAt) {
		return 0, 0, false
	}
	return entry.expiresAt.Sub(entry.cachedAt), now.Sub(entry.cachedAt), true
}

// cachedLookup returns the cached TXT records for query if a non-expired entry exists.
// Expired entries are removed under a write lock using a double-checked pattern: the
// entry is read under a read lock first, then re-examined under a write lock before
// deletion so that a concurrent writer that already refreshed the entry is not evicted.
func (rd *RedirDns) cachedLookup(query string, now time.Time) ([]string, error, bool) {
	rd.dnsCache.mu.RLock()
	entry, ok := rd.dnsCache.entries[query]
	rd.dnsCache.mu.RUnlock()
	if !ok {
		return nil, nil, false
	}
	if now.After(entry.expiresAt) {
		// upgrade to write lock and re-check before deleting to avoid racing with
		// a concurrent lookup that may have already stored a fresh entry
		rd.dnsCache.mu.Lock()
		if current, exists := rd.dnsCache.entries[query]; exists && now.After(current.expiresAt) {
			delete(rd.dnsCache.entries, query)
		}
		rd.dnsCache.mu.Unlock()
		return nil, nil, false
	}

	return append([]string(nil), entry.txt...), entry.err, true
}

// storeLookup writes entry into the cache under the write lock, evicting one existing
// entry first if the cache is at capacity and query is not already present.
func (rd *RedirDns) storeLookup(query string, entry dnsCacheEntry) {
	rd.dnsCache.mu.Lock()
	defer rd.dnsCache.mu.Unlock()
	if _, exists := rd.dnsCache.entries[query]; !exists && len(rd.dnsCache.entries) >= rd.maxCacheSize {
		rd.evictOneCacheEntry(time.Now())
	}
	rd.dnsCache.entries[query] = entry
}

// maxCNAMEDepth is the maximum number of CNAME hops the miekg lookup will
// follow before giving up, guarding against infinite CNAME loops.
const maxCNAMEDepth = 10

// newMiekgLookupFunc returns a lookupFunc that queries the given resolvers using
// a miekg/dns client. Resolvers must already be in host:port form. Each resolver
// is tried in order; the first successful response is returned. NXDOMAIN is treated as
// terminal and short-circuits the remaining resolvers. CNAME chains are followed
// explicitly up to maxCNAMEDepth hops so that lookups succeed regardless of whether
// the configured resolver returns a fully-resolved answer in a single response or
// only the next CNAME hop. A single dns.Client is shared across all calls (it is
// safe for concurrent use).
func newMiekgLookupFunc(resolvers []string, logger *zap.Logger) func(context.Context, string) ([]string, time.Duration, error) {
	client := &dns.Client{}

	// queryOnce issues a single TXT query for name. On success it returns the TXT
	// records and their minimum TTL. When the answer contains a CNAME but no TXT
	// records, cname is set to the target name so the caller can follow the chain
	// with an explicit second query rather than relying on the resolver to include
	// the final TXT records in the same response.
	queryOnce := func(ctx context.Context, name string) (records []string, ttl time.Duration, cname string, err error) {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
		msg.RecursionDesired = true

		var lastErr error
		for _, ns := range resolvers {
			if c := logger.Check(zap.DebugLevel, "miekg TXT query"); c != nil {
				c.Write(zap.String("name", name), zap.String("resolver", ns))
			}
			resp, rtt, exchErr := client.ExchangeContext(ctx, msg, ns)
			if exchErr != nil {
				if c := logger.Check(zap.DebugLevel, "miekg exchange error"); c != nil {
					c.Write(zap.String("name", name), zap.String("resolver", ns), zap.Error(exchErr))
				}
				lastErr = exchErr
				continue
			}
			if c := logger.Check(zap.DebugLevel, "miekg TXT response"); c != nil {
				rrTypes := make([]string, 0, len(resp.Answer))
				for _, rr := range resp.Answer {
					rrTypes = append(rrTypes, rr.String())
				}
				c.Write(
					zap.String("name", name),
					zap.String("resolver", ns),
					zap.String("rcode", dns.RcodeToString[resp.Rcode]),
					zap.Duration("rtt", rtt),
					zap.Strings("answer", rrTypes),
				)
			}
			if resp.Rcode == dns.RcodeNameError {
				// NXDOMAIN — record does not exist; no point querying remaining servers
				return nil, 0, "", errNoTXTRecord
			}
			if resp.Rcode != dns.RcodeSuccess {
				lastErr = fmt.Errorf("resolver %s returned rcode %s", ns, dns.RcodeToString[resp.Rcode])
				continue
			}
			var (
				recs   []string
				target string
				minTTL = uint32(math.MaxUint32)
			)
			for _, rr := range resp.Answer {
				switch v := rr.(type) {
				case *dns.TXT:
					// a single TXT resource record may contain multiple character-strings;
					// RFC 1035 §3.3.14 specifies they are concatenated without separator
					recs = append(recs, strings.Join(v.Txt, ""))
					if v.Hdr.Ttl < minTTL {
						minTTL = v.Hdr.Ttl
					}
				case *dns.CNAME:
					if target == "" {
						target = v.Target
					}
				}
			}
			if len(recs) > 0 {
				return recs, time.Duration(minTTL) * time.Second, "", nil
			}
			if target != "" {
				return nil, 0, target, nil
			}
			return nil, 0, "", errNoTXTRecord
		}
		if lastErr != nil {
			return nil, 0, "", lastErr
		}
		return nil, 0, "", errNoTXTRecord
	}

	return func(ctx context.Context, query string) ([]string, time.Duration, error) {
		name := query
		for depth := 0; depth < maxCNAMEDepth; depth++ {
			records, ttl, cname, err := queryOnce(ctx, name)
			if err != nil {
				if c := logger.Check(zap.DebugLevel, "miekg lookup failed"); c != nil {
					c.Write(zap.String("query", query), zap.String("name", name), zap.Int("depth", depth), zap.Error(err))
				}
				return nil, 0, err
			}
			if len(records) > 0 {
				if c := logger.Check(zap.DebugLevel, "miekg lookup resolved"); c != nil {
					c.Write(zap.String("query", query), zap.String("name", name), zap.Int("depth", depth), zap.Strings("records", records), zap.Duration("ttl", ttl))
				}
				return records, ttl, nil
			}
			// No TXT records but a CNAME was returned — follow the chain.
			if c := logger.Check(zap.DebugLevel, "miekg following CNAME"); c != nil {
				c.Write(zap.String("query", query), zap.String("from", name), zap.String("to", cname), zap.Int("depth", depth))
			}
			name = cname
		}
		return nil, 0, fmt.Errorf("CNAME chain exceeded %d hops", maxCNAMEDepth)
	}
}

// evictOneCacheEntry removes a single cache entry. It must be called with cacheMu write lock held.
// It prefers evicting an already-expired entry; if none exist it evicts the entry with the
// soonest expiry (i.e. the one that would expire next).
func (rd *RedirDns) evictOneCacheEntry(now time.Time) {
	var soonestKey string
	var soonestExpiry time.Time
	for k, e := range rd.dnsCache.entries {
		if now.After(e.expiresAt) {
			delete(rd.dnsCache.entries, k)
			return
		}
		if soonestKey == "" || e.expiresAt.Before(soonestExpiry) {
			soonestKey = k
			soonestExpiry = e.expiresAt
		}
	}
	if soonestKey != "" {
		delete(rd.dnsCache.entries, soonestKey)
	}
}

// classifyLookupError returns a short, log-safe string describing the category of a
// DNS lookup error. Used to populate the "reason" field in debug log messages without
// including raw error text that could contain resolver-supplied data.
func classifyLookupError(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, errNoTXTRecord) {
		return "not_found"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return "nxdomain"
		}
		if dnsErr.IsTimeout {
			return "timeout"
		}
		if dnsErr.IsTemporary {
			return "temporary_dns_error"
		}
		return "dns_error"
	}

	return "lookup_error"
}
