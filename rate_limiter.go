package redirdns

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
)

const (
	// Default per-client window for unique host tracking
	defaultHostLimitWindow = time.Minute

	// Default maximum unique hosts per client in a window
	defaultMaxHostsPerClient = 50

	// Default maximum number of tracked rate-limit clients
	defaultMaxTrackedClients = 100_000

	// Maximum number of bytes examined in an X-Forwarded-For header. The
	// right-to-left walk only needs the tail of the header (the most recently
	// appended entries), so any prefix beyond this limit is discarded before
	// parsing to bound per-request CPU cost.
	maxXFFBytes = 1024
)

// hostTracker records the set of distinct hostnames a single client has triggered DNS
// lookups for within the current host-limit window, together with the time each was
// last seen. lastSeen is updated on every request and is used by the background cleanup
// goroutine to identify trackers idle for longer than hostLimitWindow.
type hostTracker struct {
	hosts    map[string]time.Time // hostname → time last requested
	lastSeen time.Time
}

// startHostLimitCleanup starts a background goroutine that periodically purges
// expired host-limit state. It shuts down when the provisioning context is
// cancelled (i.e. when Caddy replaces or stops this module instance).
func (rd *RedirDns) startHostLimitCleanup(ctx caddy.Context) {
	go func() {
		ticker := time.NewTicker(rd.hostLimitWindow)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				rd.hostLimitMu.Lock()
				rd.cleanupHostLimitState(now)
				rd.hostLimitMu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// exceedsPerClientHostLimit reports whether the client that sent r has triggered DNS
// lookups for more distinct hostnames than maxHostsPerClient within hostLimitWindow.
// Returns true (limit exceeded) when:
//   - the client's remote address cannot be parsed (fail-closed)
//   - the client has already triggered DNS lookups for maxHostsPerClient distinct
//     hostnames within hostLimitWindow
//
// A hostname the client has looked up before is always allowed through and its
// timestamp is refreshed — only first-time lookups within the window consume a slot.
// Returns false (no limit) when maxHostsPerClient or hostLimitWindow is not positive.
func (rd *RedirDns) exceedsPerClientHostLimit(r *http.Request, host string, now time.Time) bool {
	if rd.maxHostsPerClient <= 0 || rd.hostLimitWindow <= 0 {
		return false
	}
	clientID := rd.clientIDFromRequest(r)
	if clientID == "" {
		return true // fail-closed: unparseable remote address
	}
	if len(rd.bypassNets) > 0 {
		if addr, err := netip.ParseAddr(clientID); err == nil && rd.isRateLimitBypassed(addr) {
			return false
		}
	}

	rd.hostLimitMu.Lock()
	defer rd.hostLimitMu.Unlock()

	tracker, ok := rd.hostTrackers[clientID]
	if !ok {
		// evict one entry before inserting a new one to keep the map within maxTrackedClients
		if len(rd.hostTrackers) >= rd.maxTrackedClients {
			rd.evictOneHostTracker()
		}
		tracker = &hostTracker{
			hosts: make(map[string]time.Time),
		}
		rd.hostTrackers[clientID] = tracker
	}

	// sweep expired host entries for this client on the request path; the background
	// goroutine handles full cleanup periodically, but this keeps per-client state
	// accurate without waiting for the next tick
	for h, seenAt := range tracker.hosts {
		if now.Sub(seenAt) > rd.hostLimitWindow {
			delete(tracker.hosts, h)
		}
	}
	tracker.lastSeen = now

	if _, exists := tracker.hosts[host]; exists {
		// client has visited this host before within the window — refresh and allow
		tracker.hosts[host] = now
		return false
	}
	if len(tracker.hosts) >= rd.maxHostsPerClient {
		return true
	}
	tracker.hosts[host] = now

	return false
}

// evictOneHostTracker removes an arbitrary client to make room when the map is at
// capacity. Must be called with hostLimitMu held. The background goroutine already
// prunes idle trackers on every tick, so remaining entries at capacity are all
// recently active; any eviction strategy is equivalent in practice.
// A single map iteration is O(1) amortised and avoids an O(n) scan.
func (rd *RedirDns) evictOneHostTracker() {
	for id := range rd.hostTrackers {
		delete(rd.hostTrackers, id)
		return
	}
}

// cleanupHostLimitState purges expired host entries and idle trackers.
// Must be called with hostLimitMu held.
func (rd *RedirDns) cleanupHostLimitState(now time.Time) {
	for clientID, tracker := range rd.hostTrackers {
		for host, seenAt := range tracker.hosts {
			if now.Sub(seenAt) > rd.hostLimitWindow {
				delete(tracker.hosts, host)
			}
		}
		if len(tracker.hosts) == 0 && now.Sub(tracker.lastSeen) > rd.hostLimitWindow {
			delete(rd.hostTrackers, clientID)
		}
	}
}

// clientIDFromRequest derives a stable client identifier (an IP address string) from r.
// When the direct peer is not a trusted proxy the peer's IP is used directly.
// When the direct peer is trusted, X-Forwarded-For is walked right-to-left to find
// the rightmost non-trusted address; X-Real-IP is tried as a fallback if XFF is absent.
// Returns an empty string if r.RemoteAddr cannot be parsed; callers treat this as
// rate-limited (fail-closed).
func (rd *RedirDns) clientIDFromRequest(r *http.Request) string {
	remoteIP, ok := parseRemoteAddr(r.RemoteAddr)
	if !ok {
		// Return empty string to signal an unparseable peer; the caller treats
		// this as rate-limited (fail-closed) rather than falling back to a shared
		// "unknown" bucket that could conflate unrelated clients.
		return ""
	}
	if !rd.isTrustedProxy(remoteIP) {
		return remoteIP.String()
	}

	// Peer is a trusted proxy — walk X-Forwarded-For right-to-left to find the
	// rightmost non-trusted address. Walking without Split avoids a slice
	// allocation on every trusted-proxy request.
	//
	// Private/loopback addresses are intentionally accepted: the right-to-left
	// walk already defeats spoofing (a correctly-behaving proxy appends the real
	// peer IP, so injected entries are never the rightmost non-trusted one).
	// Rejecting private IPs would break all-internal deployments where clients
	// and proxies all reside on RFC-1918 space.
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		if len(xff) > maxXFFBytes {
			xff = xff[len(xff)-maxXFFBytes:]
			// The truncation point may fall mid-address; skip the partial leading
			// entry so the right-to-left walk only sees complete IP strings.
			if idx := strings.Index(xff, ","); idx >= 0 {
				xff = xff[idx+1:]
			} else {
				xff = "" // entire kept portion is a single (possibly partial) entry
			}
		}
		for xff != "" {
			var part string
			if idx := strings.LastIndex(xff, ","); idx >= 0 {
				part = strings.TrimSpace(xff[idx+1:])
				xff = xff[:idx]
			} else {
				part = xff
				xff = ""
			}
			candidateIP, valid := parseIPFromAddrPortOrLiteral(part)
			if !valid {
				continue
			}
			if rd.isTrustedProxy(candidateIP) {
				continue
			}
			return candidateIP.String()
		}
	}

	// Fall back to X-Real-IP (set by nginx and some other proxies instead of
	// or in addition to X-Forwarded-For).
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if candidateIP, valid := parseIPFromAddrPortOrLiteral(xri); valid {
			if !rd.isTrustedProxy(candidateIP) {
				return candidateIP.String()
			}
		}
	}

	return remoteIP.String()
}

// isTrustedProxy reports whether addr falls within any of the configured trusted proxy prefixes.
func (rd *RedirDns) isTrustedProxy(addr netip.Addr) bool {
	for _, prefix := range rd.trustedNets {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// isRateLimitBypassed reports whether addr falls within any of the configured rate-limit bypass prefixes.
func (rd *RedirDns) isRateLimitBypassed(addr netip.Addr) bool {
	for _, prefix := range rd.bypassNets {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// parseTrustedProxyPrefixes converts a slice of CIDR strings or bare IP addresses into
// a slice of netip.Prefix values. Bare IP addresses are converted to host prefixes
// (/32 for IPv4, /128 for IPv6). CIDR prefixes are masked to their network address so
// that a host bit set in the input (e.g. "10.0.0.1/8") does not cause a mismatch.
// Returns nil for an empty input without error.
func parseTrustedProxyPrefixes(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return nil, fmt.Errorf("invalid trusted_proxies entry %q: %w", value, err)
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted_proxies entry %q: %w", value, err)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}

	return prefixes, nil
}

// parseRemoteAddr parses an IP address from a "host:port" string as set by
// Go's net/http in r.RemoteAddr. Unlike parseIPFromAddrPortOrLiteral it skips
// the bare-IP parse attempt since r.RemoteAddr is always in host:port form.
func parseRemoteAddr(value string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr, true
}

// parseIPFromAddrPortOrLiteral parses an IP address from either a bare IP
// string or a "host:port" string. Used for X-Forwarded-For and X-Real-IP
// header values which may appear in either form.
func parseIPFromAddrPortOrLiteral(value string) (netip.Addr, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, false
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr, true
	}
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}

	return addr, true
}
