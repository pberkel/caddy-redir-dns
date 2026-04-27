package redirdns

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
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

	rd.exceedsPerClientHostLimit(makeReq("203.0.113.1"), "a.example.com")
	rd.exceedsPerClientHostLimit(makeReq("203.0.113.2"), "b.example.com")
	rd.exceedsPerClientHostLimit(makeReq("203.0.113.3"), "c.example.com")

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
	if !rd.exceedsPerClientHostLimit(req, "example.com") {
		t.Fatal("expected exceedsPerClientHostLimit to return true for unparseable RemoteAddr")
	}
}

func TestClientIPFromRequestUsesCaddyContextWhenPresent(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "10.1.2.3:4321"
	// Simulate what Caddy's PrepareRequest stores after trusted-proxy unwrapping.
	ctx := context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{
		caddyhttp.ClientIPVarKey: "198.51.100.10",
	})
	req = req.WithContext(ctx)

	if got := clientIPFromRequest(req); got != "198.51.100.10" {
		t.Fatalf("clientIPFromRequest = %q, want %q", got, "198.51.100.10")
	}
}

func TestClientIPFromRequestFallsBackToRemoteAddr(t *testing.T) {
	t.Parallel()

	// No Caddy context — should fall back to r.RemoteAddr host.
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "203.0.113.7:44321"

	if got := clientIPFromRequest(req); got != "203.0.113.7" {
		t.Fatalf("clientIPFromRequest = %q, want %q", got, "203.0.113.7")
	}
}

func TestClientIPFromRequestReturnsEmptyForUnparseableRemoteAddr(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "not-an-address"

	if got := clientIPFromRequest(req); got != "" {
		t.Fatalf("clientIPFromRequest = %q, want %q", got, "")
	}
}

func TestParseNetPrefixesRejectsInvalidEntry(t *testing.T) {
	t.Parallel()

	_, err := parseNetPrefixes([]string{"not-an-ip"})
	if err == nil {
		t.Fatalf("expected parseNetPrefixes error for invalid entry")
	}
}

func TestIsRateLimitBypassed(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	nets, err := parseNetPrefixes([]string{"10.0.0.0/8", "192.168.1.0/24"})
	if err != nil {
		t.Fatalf("parseNetPrefixes returned error: %v", err)
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
	nets, err := parseNetPrefixes([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("parseNetPrefixes returned error: %v", err)
	}
	rd.bypassNets = nets
	rd.maxHostsPerClient = 1 // would normally block after 1 unique host
	rd.hostLimitWindow = time.Minute

	makeReq := func(ip string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.RemoteAddr = ip + ":1234"
		return req
	}

	// Bypass IP: should not be rate-limited even after exceeding maxHostsPerClient
	rd.exceedsPerClientHostLimit(makeReq("10.1.2.3"), "a.example.com")
	if rd.exceedsPerClientHostLimit(makeReq("10.1.2.3"), "b.example.com") {
		t.Fatal("expected bypass IP to not be rate-limited")
	}

	// Non-bypass IP: should be rate-limited
	rd.exceedsPerClientHostLimit(makeReq("203.0.113.1"), "a.example.com")
	if !rd.exceedsPerClientHostLimit(makeReq("203.0.113.1"), "b.example.com") {
		t.Fatal("expected non-bypass IP to be rate-limited after exceeding maxHostsPerClient")
	}
}

func TestExceedsPerClientHostLimitIPv6PrefixGrouping(t *testing.T) {
	t.Parallel()

	// Two addresses within the same /48 should share a tracker slot.
	rd := newTestRedirDns(t)
	rd.maxHostsPerClient = 1
	rd.hostLimitWindow = time.Minute
	rd.ipv6PrefixLen = 48

	makeReq := func(addr string) *http.Request {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = "[" + addr + "]:12345"
		return req
	}

	// First address in 2001:db8:1::/48 — consumes the one allowed slot.
	rd.exceedsPerClientHostLimit(makeReq("2001:db8:1::1"), "a.example.com")

	// Second address in the same /48 — should be rate-limited (shared slot).
	if !rd.exceedsPerClientHostLimit(makeReq("2001:db8:1::2"), "b.example.com") {
		t.Fatal("expected second address in same /48 to be rate-limited")
	}

	// Address in a different /48 — should get its own slot and be allowed.
	if rd.exceedsPerClientHostLimit(makeReq("2001:db8:2::1"), "c.example.com") {
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

	makeReq := func(addr string) *http.Request {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		req.RemoteAddr = addr + ":12345"
		return req
	}

	rd.exceedsPerClientHostLimit(makeReq("203.0.113.1"), "a.example.com")

	// Different IPv4 address — must get its own independent tracker slot.
	if rd.exceedsPerClientHostLimit(makeReq("203.0.113.2"), "b.example.com") {
		t.Fatal("IPv4 addresses must not share a tracker slot due to ipv6_prefix_length")
	}
}
