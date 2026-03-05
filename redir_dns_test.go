package redirdns

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func TestNormalizeRequestHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "valid host with port", input: "WWW.Example.COM:443", want: "www.example.com"},
		{name: "valid host trailing dot", input: "example.com.", want: "example.com"},
		{name: "empty host", input: "", wantErr: true},
		{name: "ip host", input: "127.0.0.1", wantErr: true},
		{name: "invalid character", input: "exa_mple.com", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeRequestHost(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got none", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalizeRequestHost(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLookupTXTCachesSuccessAndError(t *testing.T) {
	t.Parallel()

	rd := New()
	rd.lookupTTL = time.Minute
	var calls atomic.Int64
	rd.lookupFunc = func(ctx context.Context, query string) ([]string, error) {
		_ = ctx
		_ = query
		n := calls.Add(1)
		if n == 1 {
			return []string{"https://example.com"}, nil
		}
		return nil, errors.New("unexpected second call for cached success")
	}

	txt, err := rd.lookupTXT(context.Background(), "_redirdns.example.com")
	if err != nil {
		t.Fatalf("unexpected error on first lookup: %v", err)
	}
	if len(txt) != 1 || txt[0] != "https://example.com" {
		t.Fatalf("unexpected TXT result: %#v", txt)
	}
	txt, err = rd.lookupTXT(context.Background(), "_redirdns.example.com")
	if err != nil {
		t.Fatalf("unexpected error on cached lookup: %v", err)
	}
	if len(txt) != 1 || txt[0] != "https://example.com" {
		t.Fatalf("unexpected cached TXT result: %#v", txt)
	}
	if calls.Load() != 1 {
		t.Fatalf("lookup function called %d times, want 1", calls.Load())
	}

	rdErr := New()
	rdErr.lookupTTL = time.Minute
	var errCalls atomic.Int64
	rdErr.lookupFunc = func(ctx context.Context, query string) ([]string, error) {
		_ = ctx
		_ = query
		errCalls.Add(1)
		return nil, errNoTXTRecord
	}

	_, err = rdErr.lookupTXT(context.Background(), "_redirdns.missing.example.com")
	if !errors.Is(err, errNoTXTRecord) {
		t.Fatalf("expected errNoTXTRecord, got %v", err)
	}
	_, err = rdErr.lookupTXT(context.Background(), "_redirdns.missing.example.com")
	if !errors.Is(err, errNoTXTRecord) {
		t.Fatalf("expected cached errNoTXTRecord, got %v", err)
	}
	if errCalls.Load() != 1 {
		t.Fatalf("error lookup function called %d times, want 1", errCalls.Load())
	}
}

func TestLookupTXTSingleflightDedupesConcurrentCalls(t *testing.T) {
	t.Parallel()

	rd := New()
	rd.lookupTTL = time.Minute
	rd.lookupMax = time.Second

	var calls atomic.Int64
	rd.lookupFunc = func(ctx context.Context, query string) ([]string, error) {
		_ = query
		calls.Add(1)
		select {
		case <-time.After(50 * time.Millisecond):
			return []string{"https://example.org"}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	const workers = 20
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			txt, err := rd.lookupTXT(context.Background(), "_redirdns.concurrent.example.com")
			if err != nil {
				results <- err
				return
			}
			if len(txt) != 1 || txt[0] != "https://example.org" {
				results <- errors.New("unexpected TXT response")
				return
			}
			results <- nil
		}()
	}
	wg.Wait()
	close(results)

	for err := range results {
		if err != nil {
			t.Fatalf("concurrent lookup failed: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("lookup function called %d times, want 1", calls.Load())
	}
}

func TestParseTxtRecordWithoutReplacerContextDoesNotPanic(t *testing.T) {
	t.Parallel()

	rd := New()
	rd.logger = zap.NewNop()
	rd.replacer = strings.NewReplacer(
		"{scheme}", "{http.request.scheme}",
		"{host}", "{http.request.host}",
		"{hostport}", "{http.request.hostport}",
		"{port}", "{http.request.port}",
		"{uri}", "{http.request.uri}",
		"{%uri}", "{http.request.uri_escaped}",
		"{path}", "{http.request.uri.path}",
		"{%path}", "{http.request.uri.path_escaped}",
		"{dir}", "{http.request.uri.path.dir}",
		"{file}", "{http.request.uri.path.file}",
		"{query}", "{http.request.uri.query}",
		"{%query}", "{http.request.uri.query_escaped}",
		"{?query}", "{http.request.uri.prefixed_query}",
	)

	req, err := http.NewRequest(http.MethodGet, "https://example.com/path?id=1", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}

	assertNoPanic(t, func() {
		target, code := rd.parseTxtRecord("example.com", "https://target.example/ 301", req)
		if target != "https://target.example/" {
			t.Fatalf("unexpected target %q", target)
		}
		if code != 301 {
			t.Fatalf("unexpected status %d", code)
		}
	})
}

func TestParseTxtRecordWithInvalidReplacerContextTypeDoesNotPanic(t *testing.T) {
	t.Parallel()

	rd := New()
	rd.logger = zap.NewNop()
	rd.replacer = strings.NewReplacer(
		"{scheme}", "{http.request.scheme}",
		"{host}", "{http.request.host}",
		"{hostport}", "{http.request.hostport}",
		"{port}", "{http.request.port}",
		"{uri}", "{http.request.uri}",
		"{%uri}", "{http.request.uri_escaped}",
		"{path}", "{http.request.uri.path}",
		"{%path}", "{http.request.uri.path_escaped}",
		"{dir}", "{http.request.uri.path.dir}",
		"{file}", "{http.request.uri.path.file}",
		"{query}", "{http.request.uri.query}",
		"{%query}", "{http.request.uri.query_escaped}",
		"{?query}", "{http.request.uri.prefixed_query}",
	)

	req, err := http.NewRequest(http.MethodGet, "https://example.com/path?id=1", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}
	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, "not-a-replacer")
	req = req.WithContext(ctx)

	assertNoPanic(t, func() {
		target, code := rd.parseTxtRecord("example.com", "https://target.example/ permanent", req)
		if target != "https://target.example/" {
			t.Fatalf("unexpected target %q", target)
		}
		if code != 301 {
			t.Fatalf("unexpected status %d", code)
		}
	})
}

func assertNoPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	fn()
}

func TestServeHTTPInvalidHostWithDefaultTargetRedirects(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	rd.DefaultTarget = "https://default.example/"
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Host = "127.0.0.1"
	rr := httptest.NewRecorder()

	err := rd.ServeHTTP(rr, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if rr.Code != rd.StatusCode {
		t.Fatalf("status code = %d, want %d", rr.Code, rd.StatusCode)
	}
	if got := rr.Header().Get("Location"); got != rd.DefaultTarget {
		t.Fatalf("Location = %q, want %q", got, rd.DefaultTarget)
	}
}

func TestServeHTTPLookupTimeoutFallsBackToDefaultTarget(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	rd.DefaultTarget = "https://default.example/"
	rd.lookupMax = 20 * time.Millisecond
	rd.lookupFunc = func(ctx context.Context, query string) ([]string, error) {
		_ = query
		<-ctx.Done()
		return nil, ctx.Err()
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	req.Host = "www.example.com"
	rr := httptest.NewRecorder()
	err := rd.ServeHTTP(rr, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if rr.Code != rd.StatusCode {
		t.Fatalf("status code = %d, want %d", rr.Code, rd.StatusCode)
	}
	if got := rr.Header().Get("Location"); got != rd.DefaultTarget {
		t.Fatalf("Location = %q, want %q", got, rd.DefaultTarget)
	}
}

func TestServeHTTPMissingTXTWithoutDefaultReturnsNotFound(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	rd.lookupFunc = func(ctx context.Context, query string) ([]string, error) {
		_ = ctx
		_ = query
		return nil, errNoTXTRecord
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	req.Host = "www.example.com"
	rr := httptest.NewRecorder()
	err := rd.ServeHTTP(rr, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusNotFound)
	}
	if got := rr.Header().Get("Location"); got != "" {
		t.Fatalf("Location = %q, want empty", got)
	}
}

func TestServeHTTPValidTXTRedirects(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	rd.lookupFunc = func(ctx context.Context, query string) ([]string, error) {
		_ = ctx
		_ = query
		return []string{"https://redirect.example/new-path 308"}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/old-path", nil)
	req.Host = "www.example.com"
	rr := httptest.NewRecorder()
	err := rd.ServeHTTP(rr, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if rr.Code != http.StatusPermanentRedirect {
		t.Fatalf("status code = %d, want %d", rr.Code, http.StatusPermanentRedirect)
	}
	if got := rr.Header().Get("Location"); got != "https://redirect.example/new-path" {
		t.Fatalf("Location = %q, want %q", got, "https://redirect.example/new-path")
	}
}

func TestServeHTTPHostCardinalityRateLimitSkipsDNSLookup(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	rd.DefaultTarget = "https://default.example/"
	rd.maxHosts = 2
	rd.rateWindow = time.Minute

	var calls atomic.Int64
	rd.lookupFunc = func(ctx context.Context, query string) ([]string, error) {
		_ = ctx
		_ = query
		calls.Add(1)
		return nil, errNoTXTRecord
	}

	makeReq := func(host string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Host = host
		req.RemoteAddr = "203.0.113.10:12345"
		return req
	}

	rr1 := httptest.NewRecorder()
	if err := rd.ServeHTTP(rr1, makeReq("one.example.com"), nil); err != nil {
		t.Fatalf("ServeHTTP #1 returned error: %v", err)
	}
	rr2 := httptest.NewRecorder()
	if err := rd.ServeHTTP(rr2, makeReq("two.example.com"), nil); err != nil {
		t.Fatalf("ServeHTTP #2 returned error: %v", err)
	}
	rr3 := httptest.NewRecorder()
	if err := rd.ServeHTTP(rr3, makeReq("three.example.com"), nil); err != nil {
		t.Fatalf("ServeHTTP #3 returned error: %v", err)
	}

	if calls.Load() != 2 {
		t.Fatalf("lookup function called %d times, want 2 (third should be rate-limited)", calls.Load())
	}
	if rr3.Code != rd.StatusCode {
		t.Fatalf("third response status = %d, want %d", rr3.Code, rd.StatusCode)
	}
	if got := rr3.Header().Get("Location"); got != rd.DefaultTarget {
		t.Fatalf("third response Location = %q, want %q", got, rd.DefaultTarget)
	}
}

func TestServeHTTPHostCardinalityRateLimitResetsAfterWindow(t *testing.T) {
	t.Parallel()

	rd := newTestRedirDns(t)
	rd.maxHosts = 1
	rd.rateWindow = 30 * time.Millisecond

	var calls atomic.Int64
	rd.lookupFunc = func(ctx context.Context, query string) ([]string, error) {
		_ = ctx
		_ = query
		calls.Add(1)
		return nil, errNoTXTRecord
	}

	makeReq := func(host string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Host = host
		req.RemoteAddr = "203.0.113.11:54321"
		return req
	}

	rr1 := httptest.NewRecorder()
	if err := rd.ServeHTTP(rr1, makeReq("one.example.com"), nil); err != nil {
		t.Fatalf("ServeHTTP #1 returned error: %v", err)
	}
	rr2 := httptest.NewRecorder()
	if err := rd.ServeHTTP(rr2, makeReq("two.example.com"), nil); err != nil {
		t.Fatalf("ServeHTTP #2 returned error: %v", err)
	}
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second response status = %d, want %d", rr2.Code, http.StatusTooManyRequests)
	}
	if calls.Load() != 1 {
		t.Fatalf("lookup function called %d times after limit hit, want 1", calls.Load())
	}

	time.Sleep(40 * time.Millisecond)
	rr3 := httptest.NewRecorder()
	if err := rd.ServeHTTP(rr3, makeReq("three.example.com"), nil); err != nil {
		t.Fatalf("ServeHTTP #3 returned error: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("lookup function called %d times after window reset, want 2", calls.Load())
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

func TestParseTrustedProxyPrefixesRejectsInvalidEntry(t *testing.T) {
	t.Parallel()

	_, err := parseTrustedProxyPrefixes([]string{"not-an-ip"})
	if err == nil {
		t.Fatalf("expected parseTrustedProxyPrefixes error for invalid entry")
	}
}

func TestUnmarshalCaddyfileParsesLookupTimeoutAndCacheTTL(t *testing.T) {
	t.Parallel()

	rd := New()
	d := caddyfile.NewTestDispenser(`
redir_dns {
	lookup_timeout 750ms
	cache_ttl 45s
	rate_window 90s
	max_unique_hosts_per_client 77
	trusted_proxies 10.0.0.0/8 192.168.0.0/16
}
`)

	if err := rd.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if time.Duration(rd.LookupTimeout) != 750*time.Millisecond {
		t.Fatalf("lookup timeout = %v, want %v", time.Duration(rd.LookupTimeout), 750*time.Millisecond)
	}
	if time.Duration(rd.CacheTTL) != 45*time.Second {
		t.Fatalf("cache ttl = %v, want %v", time.Duration(rd.CacheTTL), 45*time.Second)
	}
	if time.Duration(rd.RateWindow) != 90*time.Second {
		t.Fatalf("rate window = %v, want %v", time.Duration(rd.RateWindow), 90*time.Second)
	}
	if rd.MaxUniqueHostsPerClient != 77 {
		t.Fatalf("max unique hosts per client = %d, want %d", rd.MaxUniqueHostsPerClient, 77)
	}
	if len(rd.TrustedProxies) != 2 {
		t.Fatalf("trusted proxies length = %d, want %d", len(rd.TrustedProxies), 2)
	}
	if rd.TrustedProxies[0] != "10.0.0.0/8" || rd.TrustedProxies[1] != "192.168.0.0/16" {
		t.Fatalf("unexpected trusted proxies: %#v", rd.TrustedProxies)
	}
}

func TestValidateRejectsNonPositiveLookupTimeoutOrCacheTTL(t *testing.T) {
	t.Parallel()

	rd := New()
	rd.logger = zap.NewNop()
	rd.LookupTimeout = 0
	if err := rd.Validate(); err == nil {
		t.Fatalf("expected validate error for zero lookup timeout")
	}

	rd = New()
	rd.logger = zap.NewNop()
	rd.CacheTTL = -1
	if err := rd.Validate(); err == nil {
		t.Fatalf("expected validate error for negative cache ttl")
	}

	rd = New()
	rd.logger = zap.NewNop()
	rd.RateWindow = 0
	if err := rd.Validate(); err == nil {
		t.Fatalf("expected validate error for zero rate window")
	}

	rd = New()
	rd.logger = zap.NewNop()
	rd.MaxUniqueHostsPerClient = 0
	if err := rd.Validate(); err == nil {
		t.Fatalf("expected validate error for non-positive max_unique_hosts_per_client")
	}

	rd = New()
	rd.logger = zap.NewNop()
	rd.TrustedProxies = []string{"bad-entry"}
	if err := rd.Validate(); err == nil {
		t.Fatalf("expected validate error for invalid trusted_proxies entry")
	}
}

func newTestRedirDns(t *testing.T) *RedirDns {
	t.Helper()
	rd := New()
	rd.logger = zap.NewNop()
	rd.replacer = strings.NewReplacer(
		"{scheme}", "{http.request.scheme}",
		"{host}", "{http.request.host}",
		"{hostport}", "{http.request.hostport}",
		"{port}", "{http.request.port}",
		"{uri}", "{http.request.uri}",
		"{%uri}", "{http.request.uri_escaped}",
		"{path}", "{http.request.uri.path}",
		"{%path}", "{http.request.uri.path_escaped}",
		"{dir}", "{http.request.uri.path.dir}",
		"{file}", "{http.request.uri.path.file}",
		"{query}", "{http.request.uri.query}",
		"{%query}", "{http.request.uri.query_escaped}",
		"{?query}", "{http.request.uri.prefixed_query}",
	)
	tpl, err := template.New("default").Parse(defaultResponseTemplate)
	if err != nil {
		t.Fatalf("failed to parse response template: %v", err)
	}
	rd.responseTpl = tpl
	rd.cache = make(map[string]dnsCacheEntry)
	return rd
}
