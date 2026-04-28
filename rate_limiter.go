package redirdns

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	// Default per-client window for unique host tracking
	defaultHostLimitWindow = time.Minute

	// Default maximum unique hosts per client in a window
	defaultMaxHostsPerClient = 50

	// Default maximum number of tracked per-IP rate-limit entries
	defaultMaxTrackedClients = 100_000

	// Default IPv6 prefix length for rate-limit grouping (one slot per /64 — typical per-host allocation)
	defaultIPv6PrefixLength = 64
)

// hostTracker records the set of distinct hostnames a single client has triggered DNS
// lookups for within the current host-limit window. The map is keyed by hostname;
// the value is an empty struct since timestamps are not needed — the entire trackers
// map is reset at the end of each window by the background cleanup goroutine.
type hostTracker struct {
	hosts map[string]struct{}
}

// startHostLimitCleanup starts a background goroutine that resets all host-limit
// state once per window. Resetting the entire map is O(1) under the lock and avoids
// per-entry timestamp comparisons. The tradeoff is that the window is hard-aligned
// to the ticker start time rather than sliding per client: a client can observe up
// to 2× maxHostsPerClient unique hosts across a window boundary.
// The goroutine shuts down when the provisioning context is cancelled (i.e. when
// Caddy replaces or stops this module instance).
func (rd *RedirDns) startHostLimitCleanup(ctx caddy.Context) {
	go func() {
		ticker := time.NewTicker(rd.hostLimitWindow)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rd.hostLimit.mu.Lock()
				rd.hostLimit.trackers = make(map[string]*hostTracker, len(rd.hostLimit.trackers))
				rd.hostLimit.mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// exceedsPerClientHostLimit reports whether the client that sent r has triggered DNS
// lookups for more distinct hostnames than maxHostsPerClient within hostLimitWindow.
// Returns true (limit exceeded) when:
//   - the client's IP address cannot be determined (fail-closed)
//   - the client has already triggered DNS lookups for maxHostsPerClient distinct
//     hostnames within the current window
//
// A hostname the client has looked up before is always allowed through — only
// first-time lookups within the window consume a slot.
// Returns false (no limit) when maxHostsPerClient or hostLimitWindow is not positive.
func (rd *RedirDns) exceedsPerClientHostLimit(r *http.Request, host string) bool {
	if rd.maxHostsPerClient <= 0 || rd.hostLimitWindow <= 0 {
		return false
	}
	clientID := clientIPFromRequest(r)
	if clientID == "" {
		return true // fail-closed: unparseable remote address
	}
	if addr, err := netip.ParseAddr(clientID); err == nil {
		if len(rd.bypassNets) > 0 && rd.isRateLimitBypassed(addr) {
			return false
		}
		// group IPv6 clients by prefix to prevent prefix-rotation attacks
		if addr.Is6() && !addr.Is4In6() && rd.ipv6PrefixLen < 128 {
			clientID = netip.PrefixFrom(addr, rd.ipv6PrefixLen).Masked().String()
		}
	}

	rd.hostLimit.mu.Lock()
	defer rd.hostLimit.mu.Unlock()

	tracker, ok := rd.hostLimit.trackers[clientID]
	if !ok {
		// evict one entry before inserting a new one to keep the map within maxTrackedClients
		if len(rd.hostLimit.trackers) >= rd.maxTrackedClients {
			rd.evictOneHostTracker()
		}
		tracker = &hostTracker{
			hosts: make(map[string]struct{}),
		}
		rd.hostLimit.trackers[clientID] = tracker
	}

	if _, exists := tracker.hosts[host]; exists {
		return false
	}
	if len(tracker.hosts) >= rd.maxHostsPerClient {
		return true
	}
	tracker.hosts[host] = struct{}{}

	return false
}

// evictOneHostTracker removes an arbitrary client to make room when the map is at
// capacity. Must be called with hostLimitMu held. The background goroutine already
// prunes idle trackers on every tick, so remaining entries at capacity are all
// recently active; any eviction strategy is equivalent in practice.
// A single map iteration is O(1) amortised and avoids an O(n) scan.
func (rd *RedirDns) evictOneHostTracker() {
	for id := range rd.hostLimit.trackers {
		delete(rd.hostLimit.trackers, id)
		return
	}
}

// clientIPFromRequest returns the resolved client IP for rate-limit tracking.
// It reads the value that Caddy's PrepareRequest stored in the request context
// after performing trusted-proxy unwrapping using the server-level trusted_proxies
// and client_ip_headers configuration (defaulting to X-Forwarded-For). Falls back
// to the host part of r.RemoteAddr when the context value is absent, which happens
// in unit tests that do not run through a full Caddy HTTP server.
// Returns an empty string when no IP can be determined; callers treat this as
// rate-limited (fail-closed).
func clientIPFromRequest(r *http.Request) string {
	if ip, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && ip != "" {
		return ip
	}
	// Fallback for test environments where PrepareRequest has not run.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
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

// parseNetPrefixes converts a slice of CIDR strings or bare IP addresses into
// a slice of netip.Prefix values. Bare IP addresses are converted to host prefixes
// (/32 for IPv4, /128 for IPv6). CIDR prefixes are masked to their network address so
// that a host bit set in the input (e.g. "10.0.0.1/8") does not cause a mismatch.
// Returns nil for an empty input without error.
func parseNetPrefixes(values []string) ([]netip.Prefix, error) {
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
				return nil, fmt.Errorf("invalid entry %q: %w", value, err)
			}
			prefixes = append(prefixes, prefix.Masked())
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("invalid entry %q: %w", value, err)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}

	return prefixes, nil
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
