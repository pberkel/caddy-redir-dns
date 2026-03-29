package redirdns

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func TestContainsControlChars(t *testing.T) {
	t.Parallel()

	allowed := []string{
		"https://example.com/path?q=1",
		"https://example.com/%0d%0a", // percent-encoded CRLF — plain printable ASCII, safe
		"https://xn--mnchen-3ya.de/", // IDN in punycode — ASCII only
	}
	for _, s := range allowed {
		if containsNonPrintableASCII(s) {
			t.Errorf("containsNonPrintableASCII(%q) = true, want false", s)
		}
	}

	rejected := []string{
		"https://example.com/\r\nX-Injected: evil", // C0: CR + LF (header injection)
		"https://example.com/\x00",                 // C0: NUL
		"https://example.com/\x1f",                 // C0: last C0 control
		"https://example.com/\x7f",                 // DEL
		"https://münchen.de/",                      // raw non-ASCII — must be punycode/percent-encoded
		"https://example.com/caf\u00e9",            // raw non-ASCII in path — must be percent-encoded
	}
	for _, s := range rejected {
		if !containsNonPrintableASCII(s) {
			t.Errorf("containsNonPrintableASCII(%q) = false, want true", s)
		}
	}
}

func TestIsSupportedStatusCode(t *testing.T) {
	t.Parallel()

	valid := []int{301, 302, 303, 307, 308}
	for _, code := range valid {
		if !isSupportedStatusCode(code) {
			t.Errorf("isSupportedStatusCode(%d) = false, want true", code)
		}
	}

	invalid := []int{200, 204, 300, 304, 305, 306, 399, 401, 403, 404, 500}
	for _, code := range invalid {
		if isSupportedStatusCode(code) {
			t.Errorf("isSupportedStatusCode(%d) = true, want false", code)
		}
	}
}

func TestIsValidAbsoluteURLRejectsCredentials(t *testing.T) {
	t.Parallel()

	valid := []string{
		"https://example.com",
		"https://example.com/path?q=1",
		"http://example.com",
	}
	for _, u := range valid {
		if !isValidAbsoluteURL(u) {
			t.Errorf("isValidAbsoluteURL(%q) = false, want true", u)
		}
	}

	invalid := []string{
		"https://user:pass@example.com", // username + password
		"https://user@example.com",      // username only
		"https://:pass@example.com",     // password without username
	}
	for _, u := range invalid {
		if isValidAbsoluteURL(u) {
			t.Errorf("isValidAbsoluteURL(%q) = true, want false", u)
		}
	}
}

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
	if rr.Code != rd.statusCode {
		t.Fatalf("status code = %d, want %d", rr.Code, rd.statusCode)
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
	if rr.Code != rd.statusCode {
		t.Fatalf("status code = %d, want %d", rr.Code, rd.statusCode)
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
	if got := rr.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want %q", got, "nosniff")
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
	if rr3.Code != http.StatusTooManyRequests {
		t.Fatalf("third response status = %d, want %d", rr3.Code, http.StatusTooManyRequests)
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
	if got := rr2.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want %q", got, "nosniff")
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

func TestValidateRejectsNonPositiveLookupTimeoutOrCacheTTL(t *testing.T) {
	t.Parallel()

	rd := New()
	rd.logger = zap.NewNop()
	rd.LookupTimeout = "0"
	if err := rd.Validate(); err == nil {
		t.Fatalf("expected validate error for zero lookup timeout")
	}

	rd = New()
	rd.logger = zap.NewNop()
	rd.LookupTimeout = "31s"
	if err := rd.Validate(); err == nil {
		t.Fatalf("expected validate error for lookup_timeout exceeding maximum")
	}

	rd = New()
	rd.logger = zap.NewNop()
	rd.CacheTTL = "-1ns"
	if err := rd.Validate(); err == nil {
		t.Fatalf("expected validate error for negative cache ttl")
	}

	rd = New()
	rd.logger = zap.NewNop()
	rd.RateWindow = "0"
	if err := rd.Validate(); err == nil {
		t.Fatalf("expected validate error for zero rate window")
	}

	rd = New()
	rd.logger = zap.NewNop()
	rd.MaxUniqueHostsPerClient = "0"
	if err := rd.Validate(); err == nil {
		t.Fatalf("expected validate error for non-positive max_unique_hosts_per_client")
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
