package redirdns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	// Default DNS TXT record prefix
	defaultDnsPrefix = "_redirdns"

	// Default HTTP response status code
	defaultStatusCode = 302

	// Default DNS lookup timeout per request
	defaultDnsLookupTimeout = 500 * time.Millisecond

	// Maximum allowed DNS lookup timeout — guards against goroutine accumulation
	// since lookups run on context.Background() and are not bounded by request lifetime
	maxLookupTimeout = 30 * time.Second

	// Default DNS TXT cache TTL
	defaultDnsCacheTTL = 30 * time.Second

	// Default per-client window for unique host tracking
	defaultRateLimitWindow = time.Minute

	// Default maximum unique hosts per client in a window
	defaultMaxUniqueHostsPerClient = 50

	// Default maximum number of DNS TXT cache entries
	defaultMaxCacheSize = 10_000

	// Default maximum number of tracked rate-limit clients
	defaultMaxClients = 100_000

	// Default HTTP response template
	defaultResponseTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{.Title}}</title>
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
</head>
<body style="font-family:sans-serif;text-align:center;padding-top:10vh;">
  <h1>{{.Title}}</h1>
  <p>{{.Msg}}</p>
</body>
</html>`
)

var (
	errNoTXTRecord = errors.New("no TXT DNS record found")
	txtPrefixRegex = regexp.MustCompile(`^[_a-zA-Z0-9]([_a-zA-Z0-9-]{0,61}[_a-zA-Z0-9])?$`)
)

// StringOrInt is a config field type that accepts both a bare JSON number (e.g. 302)
// and a quoted string (e.g. "302" or "{env.STATUS_CODE}"). Values are stored as a
// string so that Caddy environment-variable placeholders can be expanded in Provision
// before the integer is parsed. JSON serialisation round-trips numeric strings back
// to bare numbers for backward compatibility.
type StringOrInt string

func (s *StringOrInt) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*s = StringOrInt(strconv.Itoa(n))
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return fmt.Errorf("cannot unmarshal %s into StringOrInt", b)
	}
	*s = StringOrInt(str)
	return nil
}

func (s StringOrInt) MarshalJSON() ([]byte, error) {
	if _, err := strconv.Atoi(string(s)); err == nil {
		return []byte(string(s)), nil
	}
	return json.Marshal(string(s))
}

type dnsCacheEntry struct {
	txt       []string
	err       error
	expiresAt time.Time
}

// RedirDns is a Caddy module implementing HTTP redirects stored in DNS TXT records
type RedirDns struct {
	// The target URL to redirect when an error occurs. Default: none
	DefaultTarget string `json:"default_target,omitempty"`
	// DNS TXT record prefix where the redirect information is stored. Default: "_redirdns"
	DnsPrefix string `json:"dns_prefix,omitempty"`
	// The HTTP status code returned by the redirect response. Default: 302
	// Accepts a bare integer (302) or a quoted string ("{env.STATUS_CODE}").
	StatusCode StringOrInt `json:"status_code,omitempty"`
	// Maximum time to wait for DNS TXT lookups before falling back. Default: 500ms
	// Accepts a Go duration string or a Caddy placeholder (e.g. "{env.LOOKUP_TIMEOUT}").
	LookupTimeout string `json:"lookup_timeout,omitempty"`
	// TTL for in-memory DNS TXT lookup cache entries. Default: 30s
	// Accepts a Go duration string or a Caddy placeholder (e.g. "{env.CACHE_TTL}").
	CacheTTL string `json:"cache_ttl,omitempty"`
	// Sliding window used to track per-client unique hosts. Default: 1m
	// Accepts a Go duration string or a Caddy placeholder (e.g. "{env.RATE_WINDOW}").
	RateWindow string `json:"rate_window,omitempty"`
	// Maximum unique hosts allowed per client within rate_window. Default: 50
	// Accepts a bare integer or a quoted string (e.g. "{env.MAX_HOSTS}").
	MaxUniqueHostsPerClient StringOrInt `json:"max_unique_hosts_per_client,omitempty"`
	// Maximum number of DNS TXT records held in the in-memory cache. Default: 10000
	// Accepts a bare integer or a quoted string (e.g. "{env.MAX_CACHE_SIZE}").
	MaxCacheSize StringOrInt `json:"max_cache_size,omitempty"`
	// Maximum number of per-client rate-limit entries tracked in memory. Default: 100000
	// Accepts a bare integer or a quoted string (e.g. "{env.MAX_CLIENTS}").
	MaxClients StringOrInt `json:"max_clients,omitempty"`
	// Trusted proxy CIDRs or IPs allowed to supply client IP via X-Forwarded-For
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	// The HTML response document served when the redirect cannot be completed
	responseTpl  *template.Template
	logger       *zap.Logger
	statusCode   int
	replacer     *strings.Replacer
	resolver     *net.Resolver
	lookupTTL    time.Duration
	lookupMax    time.Duration
	lookupFunc   func(context.Context, string) ([]string, error)
	cacheMu      sync.RWMutex
	cache        map[string]dnsCacheEntry
	maxCacheSize int
	lookupGroup  singleflight.Group
	rlMu         sync.Mutex
	clients      map[string]*clientHostTracker
	maxClients   int
	rateWindow   time.Duration
	maxHosts     int
	trustedNets  []netip.Prefix
}

func New() *RedirDns {
	// create and return new RedirDns struct with default values
	rd := RedirDns{
		DnsPrefix:               defaultDnsPrefix,
		StatusCode:              StringOrInt(strconv.Itoa(defaultStatusCode)),
		LookupTimeout:           defaultDnsLookupTimeout.String(),
		CacheTTL:                defaultDnsCacheTTL.String(),
		RateWindow:              defaultRateLimitWindow.String(),
		MaxUniqueHostsPerClient: StringOrInt(strconv.Itoa(defaultMaxUniqueHostsPerClient)),
		MaxCacheSize:            StringOrInt(strconv.Itoa(defaultMaxCacheSize)),
		MaxClients:              StringOrInt(strconv.Itoa(defaultMaxClients)),
		resolver:                net.DefaultResolver,
		statusCode:              defaultStatusCode,
		lookupTTL:               defaultDnsCacheTTL,
		lookupMax:               defaultDnsLookupTimeout,
		cache:                   make(map[string]dnsCacheEntry),
		maxCacheSize:            defaultMaxCacheSize,
		clients:                 make(map[string]*clientHostTracker),
		maxClients:              defaultMaxClients,
		rateWindow:              defaultRateLimitWindow,
		maxHosts:                defaultMaxUniqueHostsPerClient,
	}
	return &rd
}

// CaddyModule returns the Caddy module information
func (*RedirDns) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.redir_dns",
		New: func() caddy.Module {
			return New()
		},
	}
}

// ServeHTTP implements caddyhttp.MiddlewareHandler. The next handler is never
// called because this module always terminates the request with either a
// redirect response or an error page — it is designed as a terminal handler,
// not a pass-through middleware.
func (rd *RedirDns) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	// extract the host name from the request
	reqHost, err := normalizeRequestHost(r.Host)
	if err != nil {
		rd.logger.Debug("Request cannot be processed for DNS redirect because the Host header is invalid",
			zap.String("host", r.Host), zap.Error(err))
		if rd.DefaultTarget != "" {
			// redirect to default target if supplied
			return writeRedirectResponse(w, rd.statusCode, rd.DefaultTarget)
		}
		return rd.writeHtmlResponse(w, http.StatusNotFound,
			"Redirect Failed", "Unable to process request hostname")
	}

	// check if client should be rate-limited
	if rd.isClientHostRateLimited(r, reqHost, time.Now()) {
		rd.logger.Debug("DNS lookup skipped because client exceeded unique host rate limit in active window",
			zap.String("host", reqHost),
			zap.Duration("window", rd.rateWindow),
			zap.Int("max_unique_hosts", rd.maxHosts))
		return rd.writeHtmlResponse(w, http.StatusTooManyRequests,
			"Too Many Requests", "Too many unique hostnames requested in a short period")
	}

	// create DNS TXT query and perform lookup
	txtQuery := rd.DnsPrefix + "." + reqHost
	txtRecord, err := rd.lookupTXT(txtQuery)

	// check if the DNS lookup returned a response
	if err != nil || len(txtRecord) == 0 {
		rd.logger.Debug("DNS TXT lookup did not return redirect data; applying fallback behavior",
			zap.String("host", reqHost),
			zap.String("query", txtQuery),
			zap.String("reason", classifyLookupError(err)))
		// DNS lookup returned no / invalid response
		if rd.DefaultTarget != "" {
			// redirect to default target if supplied
			return writeRedirectResponse(w, rd.statusCode, rd.DefaultTarget)
		}
		return rd.writeHtmlResponse(w, http.StatusNotFound,
			"Redirect Failed", "Unable to load TXT DNS record")
	}

	// iterate over each TXT record in the response
	for i, txt := range txtRecord {
		// parse the TXT record to extract redirect location
		targetUrl, statusCode := rd.parseTxtRecord(reqHost, txt, r)
		rd.logger.Debug("Evaluated DNS TXT redirect candidate",
			zap.String("host", reqHost),
			zap.Int("txt_index", i),
			zap.Bool("accepted", targetUrl != ""),
			zap.Int("status_code", statusCode))
		if targetUrl != "" {
			// output HTTP redirect response
			return writeRedirectResponse(w, statusCode, targetUrl)
		}
	}

	// none of the TXT records contained a valid redirect
	if rd.DefaultTarget != "" {
		// redirect to default target if supplied
		return writeRedirectResponse(w, rd.statusCode, rd.DefaultTarget)
	}

	return rd.writeHtmlResponse(w, http.StatusNotFound,
		"Redirect Failed", "Unable to determine redirect target")
}

func writeRedirectResponse(w http.ResponseWriter, statusCode int, location string) error {
	w.Header().Set("Location", location)
	w.WriteHeader(statusCode)

	return nil
}

func (rd *RedirDns) writeHtmlResponse(w http.ResponseWriter, statusCode int, title, msg string) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	data := map[string]string{
		"Title": title,
		"Msg":   msg,
	}

	return rd.responseTpl.Execute(w, data)
}

func (rd *RedirDns) parseTxtRecord(reqHost string, record string, r *http.Request) (string, int) {
	// expand and replace shortcode placeholder values
	replaced := rd.replacer.Replace(record)
	replVal := r.Context().Value(caddy.ReplacerCtxKey)
	repl, ok := replVal.(*caddy.Replacer)
	if !ok || repl == nil {
		rd.logger.Debug("Dynamic placeholder expansion skipped because request replacer context is unavailable")
	} else {
		replaced, _ = repl.ReplaceFunc(replaced, func(key string, val any) (any, error) {
			// hostname component labels (seperated by dots)
			if strings.HasPrefix(key, "http.request.host.labels.") {
				key = strings.Replace(key, "http.request.host.labels.", "labels.", 1)
			}
			if strings.HasPrefix(key, "labels.") {
				idx, err := strconv.Atoi(key[len("labels."):])
				if err != nil || idx < 0 {
					return "", nil
				}
				components := strings.Split(reqHost, ".")
				if idx >= len(components) {
					return "", nil
				}
				return strings.ToLower(components[len(components)-idx-1]), nil
			}
			// for security reasons, only replace the following placeholders
			switch key {
			case "http.request.scheme",
				"http.request.host",
				"http.request.hostport",
				"http.request.port",
				"http.request.uri",
				"http.request.uri_escaped",
				"http.request.uri.path",
				"http.request.uri.path_escaped",
				"http.request.uri.path.dir",
				"http.request.uri.path.file",
				"http.request.uri.query",
				"http.request.uri.query_escaped",
				"http.request.uri.prefixed_query":
				return val, nil
			default:
				return "", nil
			}
		})
	}
	// set default return values
	targetUrl := ""
	statusCode := rd.statusCode
	// split the expanded record on whitespace
	parts := strings.Fields(replaced)
	// First part (manditory) should be the target URL
	if len(parts) > 0 {
		if isValidAbsoluteURL(parts[0]) && !containsNonPrintableASCII(parts[0]) {
			targetUrl = parts[0]
		} else {
			rd.logger.Debug("Rejected DNS TXT redirect candidate because target is not a valid absolute HTTP/HTTPS URL")
		}
	}
	// Second part (optional) could be the status code
	if len(parts) > 1 {
		switch parts[1] {
		case "permanent":
			statusCode = 301
		case "temporary":
			statusCode = 302
		default:
			code, err := strconv.Atoi(parts[1])
			if err == nil && isSupportedStatusCode(code) {
				statusCode = code
			} else {
				rd.logger.Debug("Ignored TXT status token because it is not a supported redirect status",
					zap.String("status_token", parts[1]))
			}
		}
	}

	return targetUrl, statusCode
}

func (rd *RedirDns) lookupTXT(query string) ([]string, error) {
	now := time.Now()
	if txt, err, found := rd.cachedLookup(query, now); found {
		return txt, err
	}

	value, _, _ := rd.lookupGroup.Do(query, func() (any, error) {
		checkNow := time.Now()
		if txt, err, found := rd.cachedLookup(query, checkNow); found {
			return dnsCacheEntry{txt: txt, err: err}, nil
		}

		lookupCtx, cancel := context.WithTimeout(context.Background(), rd.lookupMax)
		defer cancel()
		var (
			txt []string
			err error
		)
		if rd.lookupFunc != nil {
			txt, err = rd.lookupFunc(lookupCtx, query)
		} else {
			txt, err = rd.resolver.LookupTXT(lookupCtx, query)
		}
		if err == nil && len(txt) == 0 {
			err = errNoTXTRecord
		}

		entry := dnsCacheEntry{
			txt:       append([]string(nil), txt...),
			err:       err,
			expiresAt: checkNow.Add(rd.lookupTTL),
		}
		rd.storeLookup(query, entry)

		return entry, nil
	})

	entry, _ := value.(dnsCacheEntry)
	return append([]string(nil), entry.txt...), entry.err
}

func (rd *RedirDns) cachedLookup(query string, now time.Time) ([]string, error, bool) {
	rd.cacheMu.RLock()
	entry, ok := rd.cache[query]
	rd.cacheMu.RUnlock()
	if !ok {
		return nil, nil, false
	}
	if now.After(entry.expiresAt) {
		rd.cacheMu.Lock()
		if current, exists := rd.cache[query]; exists && now.After(current.expiresAt) {
			delete(rd.cache, query)
		}
		rd.cacheMu.Unlock()
		return nil, nil, false
	}

	return append([]string(nil), entry.txt...), entry.err, true
}

func (rd *RedirDns) storeLookup(query string, entry dnsCacheEntry) {
	rd.cacheMu.Lock()
	defer rd.cacheMu.Unlock()
	if _, exists := rd.cache[query]; !exists && len(rd.cache) >= rd.maxCacheSize {
		rd.evictOneCacheEntry(time.Now())
	}
	rd.cache[query] = entry
}

// evictOneCacheEntry removes a single cache entry. It must be called with cacheMu write lock held.
// It prefers evicting an already-expired entry; if none exist it evicts the entry with the
// soonest expiry (i.e. the one that would expire next).
func (rd *RedirDns) evictOneCacheEntry(now time.Time) {
	for k, e := range rd.cache {
		if now.After(e.expiresAt) {
			delete(rd.cache, k)
			return
		}
	}
	var soonestKey string
	var soonestExpiry time.Time
	for k, e := range rd.cache {
		if soonestKey == "" || e.expiresAt.Before(soonestExpiry) {
			soonestKey = k
			soonestExpiry = e.expiresAt
		}
	}
	if soonestKey != "" {
		delete(rd.cache, soonestKey)
	}
}

func normalizeRequestHost(host string) (string, error) {
	reqHost, _, err := net.SplitHostPort(host)
	if err != nil {
		reqHost = host
	}
	reqHost = strings.TrimSpace(strings.Trim(reqHost, "[]"))
	reqHost = strings.TrimSuffix(reqHost, ".")
	if reqHost == "" {
		return "", fmt.Errorf("empty host header")
	}
	if ip := net.ParseIP(reqHost); ip != nil {
		return "", fmt.Errorf("host is an IP address")
	}
	if !isValidDNSHost(reqHost) {
		return "", fmt.Errorf("invalid hostname %q", reqHost)
	}

	return strings.ToLower(reqHost), nil
}

func isValidDNSHost(host string) bool {
	if len(host) > 253 {
		return false
	}
	for label := range strings.SplitSeq(host, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}

// containsNonPrintableASCII reports whether s contains any byte outside the
// printable ASCII range (0x20–0x7E).
//
// HTTP header values, including Location, must be ASCII per RFC 7230 §3.2.6.
// Non-ASCII characters (e.g. in IRIs) must be percent-encoded before being
// placed in a redirect URL — at which point they become plain printable ASCII
// by definition. Accepting raw non-ASCII bytes would silently rely on Go's
// net/http stripping them at write time; we enforce the constraint explicitly
// so the rejection is visible in logs rather than a silent sanitisation.
//
// Rejected ranges:
//   - 0x00–0x1F: ASCII C0 controls (\r, \n, \t, NUL, …) — classic header-injection vector
//   - 0x7F:      DEL — non-printable, no role in a URL
//   - 0x80–0xFF: non-ASCII bytes — must be percent-encoded in a Location value
func containsNonPrintableASCII(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c < 0x20 || c >= 0x7f {
			return true
		}
	}
	return false
}

func isValidAbsoluteURL(location string) bool {
	parsedUrl, err := url.Parse(location)
	if err != nil {
		return false
	}
	// restrict to HTTP/HTTPS only
	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return false
	}
	// reject credential-bearing URLs — redirecting to https://user:pass@host
	// leaks credentials in browser history and Referer headers
	if parsedUrl.User != nil {
		return false
	}
	// must have a non-empty host
	return parsedUrl.Host != ""
}

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

func isSupportedStatusCode(code int) bool {
	// Only allow well-defined redirect codes. 300 (Multiple Choices), 304 (Not Modified),
	// 305 (Use Proxy, deprecated) and 306 (Switch Proxy, obsolete) are intentionally excluded.
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*RedirDns)(nil)
