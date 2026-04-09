package redirdns

import (
	"net/http"
	"net/http/httptest"
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

	rd.hostLimitMu.Lock()
	clientsLen := len(rd.hostTrackers)
	rd.hostLimitMu.Unlock()

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
