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

type clientHostTracker struct {
	hosts    map[string]time.Time
	lastSeen time.Time
}

// startRateLimiterCleanup starts a background goroutine that periodically
// purges expired rate-limit state. It shuts down when the provisioning
// context is cancelled (i.e. when Caddy replaces or stops this module instance).
func (rd *RedirDns) startRateLimiterCleanup(ctx caddy.Context) {
	go func() {
		ticker := time.NewTicker(rd.rateWindow)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				rd.rlMu.Lock()
				rd.cleanupRateLimitState(now)
				rd.rlMu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (rd *RedirDns) isClientHostRateLimited(r *http.Request, host string, now time.Time) bool {
	if rd.maxHosts <= 0 || rd.rateWindow <= 0 {
		return false
	}
	clientID := rd.clientIDFromRequest(r)
	if clientID == "" {
		return true // fail-closed: unparseable remote address
	}

	rd.rlMu.Lock()
	defer rd.rlMu.Unlock()

	tracker, ok := rd.clients[clientID]
	if !ok {
		if len(rd.clients) >= rd.maxClients {
			rd.evictOneClient()
		}
		tracker = &clientHostTracker{
			hosts: make(map[string]time.Time),
		}
		rd.clients[clientID] = tracker
	}

	for h, seenAt := range tracker.hosts {
		if now.Sub(seenAt) > rd.rateWindow {
			delete(tracker.hosts, h)
		}
	}
	tracker.lastSeen = now

	if _, exists := tracker.hosts[host]; exists {
		tracker.hosts[host] = now
		return false
	}
	if len(tracker.hosts) >= rd.maxHosts {
		return true
	}
	tracker.hosts[host] = now

	return false
}

// evictOneClient removes an arbitrary client to make room when the map is at
// capacity. It must be called with rlMu held. The background goroutine already
// prunes genuinely idle clients on every tick, so remaining entries at capacity
// are all recently active; any eviction strategy is equivalent in practice.
// A single map iteration is O(1) amortised and avoids an O(n) scan.
func (rd *RedirDns) evictOneClient() {
	for id := range rd.clients {
		delete(rd.clients, id)
		return
	}
}

// cleanupRateLimitState purges expired host entries and idle client trackers.
// It must be called with rlMu held.
func (rd *RedirDns) cleanupRateLimitState(now time.Time) {
	for clientID, tracker := range rd.clients {
		for host, seenAt := range tracker.hosts {
			if now.Sub(seenAt) > rd.rateWindow {
				delete(tracker.hosts, host)
			}
		}
		if len(tracker.hosts) == 0 && now.Sub(tracker.lastSeen) > rd.rateWindow {
			delete(rd.clients, clientID)
		}
	}
}

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

func (rd *RedirDns) isTrustedProxy(addr netip.Addr) bool {
	for _, prefix := range rd.trustedNets {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}

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
