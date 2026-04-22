package redirdns

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestExceedsPerClientHostLimitRespectsMaxTrackedClients(t *testing.T) {
	t.Parallel()

	const maxClients = 2
	rd := newTestRedirDns(t)
	rd.maxTrackedClients = maxClients
	rd.maxHostsPerClient = 100
	rd.hostLimitWindow = time.Minute

	makeReq := func(ip string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = ip + ":1234"
		return req
	}

	now := time.Now()
	rd.exceedsPerClientHostLimit(makeReq("203.0.113.1"), "a.example.com", now)
	rd.exceedsPerClientHostLimit(makeReq("203.0.113.2"), "b.example.com", now)
	rd.exceedsPerClientHostLimit(makeReq("203.0.113.3"), "c.example.com", now)

	rd.hostLimit.mu.Lock()
	clientsLen := len(rd.hostLimit.trackers)
	rd.hostLimit.mu.Unlock()

	if clientsLen > maxClients {
		t.Fatalf("host trackers map size = %d, want <= %d", clientsLen, maxClients)
	}
}

func TestExceedsPerClientHostLimitFailsClosedForUnparseableRemoteAddr(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "not-an-address"
	if !rd.exceedsPerClientHostLimit(req, "example.com", time.Now()) {
		t.Fatal("expected exceedsPerClientHostLimit to return true for unparseable RemoteAddr")
	}
}

func TestClientIDFromRequestUsesXFFWhenRemoteIsTrustedProxy(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	nets, err := parseTrustedProxyPrefixes([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parseTrustedProxyPrefixes returned error: %v", err)
	}
	rd.trustedNets = nets

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:4321"
	req.Header.Set("X-Forwarded-For", "198.51.100.10, 10.20.30.40")

	clientID := rd.clientIDFromRequest(req)
	if clientID != "198.51.100.10" {
		t.Fatalf("clientID = %q, want %q", clientID, "198.51.100.10")
	}
}

func TestClientIDFromRequestIgnoresXFFWhenRemoteIsUntrusted(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	nets, err := parseTrustedProxyPrefixes([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parseTrustedProxyPrefixes returned error: %v", err)
	}
	rd.trustedNets = nets

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.7:44321"
	req.Header.Set("X-Forwarded-For", "198.51.100.10")

	clientID := rd.clientIDFromRequest(req)
	if clientID != "203.0.113.7" {
		t.Fatalf("clientID = %q, want %q", clientID, "203.0.113.7")
	}
}

func TestClientIDFromRequestReturnsEmptyForUnparseableRemoteAddr(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "not-an-address"

	clientID := rd.clientIDFromRequest(req)
	if clientID != "" {
		t.Fatalf("clientID = %q, want %q", clientID, "")
	}
}

func TestClientIDFromRequestAcceptsPrivateXFFForAllInternalDeployment(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	// Proxy is trusted; client is also on private space (all-internal deployment).
	nets, err := parseTrustedProxyPrefixes([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parseTrustedProxyPrefixes returned error: %v", err)
	}
	rd.trustedNets = nets

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:4321"
	req.Header.Set("X-Forwarded-For", "192.168.5.10")

	clientID := rd.clientIDFromRequest(req)
	if clientID != "192.168.5.10" {
		t.Fatalf("clientID = %q, want %q", clientID, "192.168.5.10")
	}
}

func TestClientIDFromRequestFallsBackToXRealIP(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	nets, err := parseTrustedProxyPrefixes([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parseTrustedProxyPrefixes returned error: %v", err)
	}
	rd.trustedNets = nets

	for _, ip := range []string{"203.0.113.99", "192.168.5.10"} {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = "10.1.2.3:4321"
		req.Header.Set("X-Real-IP", ip)

		clientID := rd.clientIDFromRequest(req)
		if clientID != ip {
			t.Fatalf("X-Real-IP=%q: clientID = %q, want %q", ip, clientID, ip)
		}
	}
}

func TestClientIDFromRequestXFFTakesPrecedenceOverXRealIP(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	nets, err := parseTrustedProxyPrefixes([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parseTrustedProxyPrefixes returned error: %v", err)
	}
	rd.trustedNets = nets

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("X-Real-IP", "203.0.113.99")

	clientID := rd.clientIDFromRequest(req)
	if clientID != "203.0.113.10" {
		t.Fatalf("clientID = %q, want %q", clientID, "203.0.113.10")
	}
}

func TestParseTrustedProxyPrefixesRejectsInvalidEntry(t *testing.T) {
	t.Parallel()

	_, err := parseTrustedProxyPrefixes([]string{"not-an-ip"})
	if err == nil {
		t.Fatalf("expected parseTrustedProxyPrefixes error for invalid entry")
	}
}

func TestIsRateLimitBypassed(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	nets, err := parseTrustedProxyPrefixes([]string{"10.0.0.0/8", "192.168.1.0/24"})
	if err != nil {
		t.Fatalf("parseTrustedProxyPrefixes returned error: %v", err)
	}
	rd.bypassNets = nets

	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"192.168.1.50", true},
		{"192.168.2.1", false},
		{"203.0.113.1", false},
	}
	for _, tt := range tests {
		addr, err := netip.ParseAddr(tt.ip)
		if err != nil {
			t.Fatalf("ParseAddr(%q): %v", tt.ip, err)
		}
		if got := rd.isRateLimitBypassed(addr); got != tt.want {
			t.Errorf("isRateLimitBypassed(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestIsRateLimitBypassedEmptyNets(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	// bypassNets is nil by default — nothing should be bypassed
	addr, _ := netip.ParseAddr("10.0.0.1")
	if rd.isRateLimitBypassed(addr) {
		t.Fatal("expected isRateLimitBypassed to return false with no bypass nets configured")
	}
}

func TestExceedsPerClientHostLimitBypassesConfiguredCIDR(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	nets, err := parseTrustedProxyPrefixes([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parseTrustedProxyPrefixes returned error: %v", err)
	}
	rd.bypassNets = nets
	rd.maxHostsPerClient = 1 // would normally block after 1 unique host
	rd.hostLimitWindow = time.Minute

	makeReq := func(ip string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = ip + ":1234"
		return req
	}

	now := time.Now()
	// Bypass IP: should not be rate-limited even after exceeding maxHostsPerClient
	rd.exceedsPerClientHostLimit(makeReq("10.1.2.3"), "a.example.com", now)
	if rd.exceedsPerClientHostLimit(makeReq("10.1.2.3"), "b.example.com", now) {
		t.Fatal("expected bypass IP to not be rate-limited")
	}

	// Non-bypass IP: should be rate-limited
	rd.exceedsPerClientHostLimit(makeReq("203.0.113.1"), "a.example.com", now)
	if !rd.exceedsPerClientHostLimit(makeReq("203.0.113.1"), "b.example.com", now) {
		t.Fatal("expected non-bypass IP to be rate-limited after exceeding maxHostsPerClient")
	}
}

func TestCleanupHostLimitStateRemovesExpiredEntries(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	rd.hostLimitWindow = time.Minute

	past := time.Now().Add(-2 * time.Minute)
	recent := time.Now()

	rd.hostLimit.mu.Lock()
	rd.hostLimit.trackers["old-client"] = &hostTracker{
		hosts:    map[string]time.Time{"a.example.com": past},
		lastSeen: past,
	}
	rd.hostLimit.trackers["active-client"] = &hostTracker{
		hosts:    map[string]time.Time{"b.example.com": recent},
		lastSeen: recent,
	}
	rd.cleanupHostLimitState(time.Now())
	rd.hostLimit.mu.Unlock()

	rd.hostLimit.mu.Lock()
	_, oldExists := rd.hostLimit.trackers["old-client"]
	_, activeExists := rd.hostLimit.trackers["active-client"]
	rd.hostLimit.mu.Unlock()

	if oldExists {
		t.Fatal("expected expired tracker to be removed")
	}
	if !activeExists {
		t.Fatal("expected active tracker to be retained")
	}
}

func TestCleanupHostLimitStateRemovesExpiredHostsButKeepsTracker(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	rd.hostLimitWindow = time.Minute

	past := time.Now().Add(-2 * time.Minute)
	recent := time.Now()

	rd.hostLimit.mu.Lock()
	// Client is still active (lastSeen recent) but has one expired host entry
	rd.hostLimit.trackers["mixed-client"] = &hostTracker{
		hosts: map[string]time.Time{
			"old.example.com":    past,
			"recent.example.com": recent,
		},
		lastSeen: recent,
	}
	rd.cleanupHostLimitState(time.Now())
	rd.hostLimit.mu.Unlock()

	rd.hostLimit.mu.Lock()
	tracker, exists := rd.hostLimit.trackers["mixed-client"]
	rd.hostLimit.mu.Unlock()

	if !exists {
		t.Fatal("expected active tracker to be retained")
	}
	if _, ok := tracker.hosts["old.example.com"]; ok {
		t.Fatal("expected expired host entry to be removed")
	}
	if _, ok := tracker.hosts["recent.example.com"]; !ok {
		t.Fatal("expected recent host entry to be retained")
	}
}

func TestExceedsPerClientHostLimitIPv6PrefixGrouping(t *testing.T) {
	t.Parallel()

	// Two addresses within the same /48 should share a tracker slot.
	rd := newTestRedirDns(t)
	rd.maxHostsPerClient = 1
	rd.hostLimitWindow = time.Minute
	rd.ipv6PrefixLen = 48

	now := time.Now()
	makeReq := func(addr string) *http.Request {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = "[" + addr + "]:12345"
		return req
	}

	// First address in 2001:db8:1::/48 — consumes the one allowed slot.
	rd.exceedsPerClientHostLimit(makeReq("2001:db8:1::1"), "a.example.com", now)

	// Second address in the same /48 — should be rate-limited (shared slot).
	if !rd.exceedsPerClientHostLimit(makeReq("2001:db8:1::2"), "b.example.com", now) {
		t.Fatal("expected second address in same /48 to be rate-limited")
	}

	// Address in a different /48 — should get its own slot and be allowed.
	if rd.exceedsPerClientHostLimit(makeReq("2001:db8:2::1"), "c.example.com", now) {
		t.Fatal("expected address in different /48 to be allowed")
	}
}

func TestExceedsPerClientHostLimitIPv4UnaffectedByIPv6Prefix(t *testing.T) {
	t.Parallel()

	// IPv4 addresses must not be grouped by ipv6_prefix_length.
	rd := newTestRedirDns(t)
	rd.maxHostsPerClient = 1
	rd.hostLimitWindow = time.Minute
	rd.ipv6PrefixLen = 48

	now := time.Now()
	makeReq := func(addr string) *http.Request {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = addr + ":12345"
		return req
	}

	rd.exceedsPerClientHostLimit(makeReq("203.0.113.1"), "a.example.com", now)

	// Different IPv4 address — must get its own independent tracker slot.
	if rd.exceedsPerClientHostLimit(makeReq("203.0.113.2"), "b.example.com", now) {
		t.Fatal("IPv4 addresses must not share a tracker slot due to ipv6_prefix_length")
	}
}
