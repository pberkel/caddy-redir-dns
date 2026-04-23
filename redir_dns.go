package redirdns

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/sync/singleflight"
)

const (
	// Default DNS TXT record prefix
	defaultDnsPrefix = "_redirdns"

	// Sentinel returned by resolveStatusCode when HTML redirect mode is active.
	// Not a valid HTTP status code; used only as an internal routing signal.
	htmlRedirectCode = -1

	// HTML redirect template (minified). Sends a 200 OK with a meta-refresh and
	// JavaScript redirect so that browsers follow the redirect while API clients
	// that check the HTTP status code or Content-Type receive a 200 with an HTML
	// body rather than a 3xx redirect. The template is compiled once at package
	// init time into htmlRedirectTpl.
	htmlRedirectTemplate = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta http-equiv="refresh" content="0; url={{.URL}}"><title>Redirecting&#x2026;</title><script>window.location.replace({{.URLJSON}});</script></head><body><p>Redirecting to <a href="{{.URL}}">{{.URL}}</a>&#x2026;</p></body></html>`

	// Default HTTP response template (minified; canonical source: examples/error_template.html)
	defaultResponseTemplate = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>{{.Title}}</title><meta name="viewport" content="width=device-width,initial-scale=1.0"><style>*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}:root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#4f8ef7;--warn:#f5c842}body{font-family:system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh;display:flex;flex-direction:column}header{background:var(--surface);border-bottom:1px solid var(--border);padding:0 2rem;height:56px;display:flex;align-items:center;gap:2rem}.logo{font-size:1.1rem;font-weight:700;color:var(--accent);letter-spacing:-0.01em}nav{display:flex;gap:1.5rem;margin-left:auto}nav a{color:var(--muted);text-decoration:none;font-size:0.875rem;transition:color 0.15s}nav a:hover{color:var(--text)}main{flex:1;display:flex;align-items:flex-start;justify-content:center;padding:6rem 1.5rem 4rem}.card{width:100%;max-width:640px}.badge{display:inline-block;font-size:0.7rem;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;color:var(--warn);border:1px solid var(--warn);border-radius:4px;padding:0.2rem 0.55rem;margin-bottom:1rem}h1{font-size:1.6rem;font-weight:600;margin-bottom:2rem;line-height:1.3}section{margin-bottom:1.5rem}h2{font-size:0.7rem;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted);margin-bottom:0.5rem}.detail{font-family:ui-monospace,"Cascadia Code",monospace;font-size:0.875rem;background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--warn);border-radius:0 6px 6px 0;padding:0.75rem 1rem;color:var(--text);word-break:break-word}.resolution{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:0 6px 6px 0;padding:0.75rem 1rem;font-size:0.9rem;line-height:1.65;color:var(--muted)}footer{background:var(--surface);border-top:1px solid var(--border);padding:0 2rem;height:48px;display:flex;align-items:center;justify-content:center;font-size:0.8rem;color:var(--muted)}footer a{color:var(--muted);text-decoration:none;transition:color 0.15s}footer a:hover{color:var(--text)}</style></head><body><header><span class="logo">caddy-redir-dns</span><nav><a href="https://github.com/pberkel/caddy-redir-dns#configuration">Documentation</a><a href="https://github.com/pberkel/caddy-redir-dns">GitHub</a></nav></header><main><div class="card"><div class="badge">Error</div><h1>{{.Title}}</h1><section><h2>What happened</h2><div class="detail">{{.Detail}}</div></section><section><h2>How to resolve</h2><div class="resolution">{{.Resolution}}</div></section></div></main><footer><span>Powered by <a href="https://caddyserver.com">Caddy</a> and <a href="https://github.com/pberkel/caddy-redir-dns">caddy-redir-dns</a></span></footer></body></html>`
)

// htmlRedirectTpl is compiled once at package init from htmlRedirectTemplate.
var htmlRedirectTpl = template.Must(template.New("html-redirect").Parse(htmlRedirectTemplate))

// htmlRedirectPageData holds the fields passed to htmlRedirectTpl.
type htmlRedirectPageData struct {
	URL     template.URL // auto-escaped in HTML attribute and URL contexts
	URLJSON template.JS  // JSON-encoded URL, safe for embedding in a JS string literal
}

// RedirDns is a Caddy module implementing HTTP redirects stored in DNS TXT records
type RedirDns struct {
	// --- Redirect ---

	// The target URL to redirect when an error occurs. Default: none
	DefaultTarget string `json:"default_target,omitempty"`
	// The HTTP redirect status to use. Accepts a numeric code (301, 302, 303, 307, 308)
	// or one of three keywords:
	//   "temporary"  — 302 for GET/HEAD, 307 for all other methods (method-preserving).
	//   "permanent"  — 301 for GET/HEAD, 308 for all other methods (method-preserving).
	//   "html"       — 200 OK with an HTML body containing a meta-refresh and JavaScript
	//                  redirect. Browsers follow the redirect; API clients that check the
	//                  HTTP status code or Content-Type receive a 200 with an HTML document.
	// Numeric codes always emit that exact code regardless of request method.
	// Accepts a bare integer or a quoted string (e.g. "{env.STATUS_CODE}"). Default: "temporary".
	StatusCode StringOrInt `json:"status_code,omitempty"`
	// DNS TXT record prefix where the redirect information is stored. Default: "_redirdns"
	DnsPrefix string `json:"dns_prefix,omitempty"`

	// --- DNS lookup ---

	// Custom DNS resolvers (hostnames or IPs, optional port) used for TXT lookups.
	// When empty the system resolver is used. Multiple entries are tried in order
	// until one succeeds.
	Resolvers []string `json:"resolvers,omitempty"`
	// Maximum time to wait for DNS TXT lookups before falling back. Default: 2s
	// Accepts a Go duration string or a Caddy placeholder (e.g. "{env.LOOKUP_TIMEOUT}").
	LookupTimeout string `json:"lookup_timeout,omitempty"`
	// TTL for in-memory DNS TXT lookup cache entries. When no custom resolvers are
	// configured, the system resolver is used and does not expose DNS record TTLs —
	// this value is used directly as the cache TTL. When custom resolvers are
	// configured and the DNS record returns a TTL, the larger of the two is used,
	// up to max_cache_ttl. Default: 30s
	// Accepts a Go duration string or a Caddy placeholder (e.g. "{env.MIN_CACHE_TTL}").
	MinCacheTTL string `json:"min_cache_ttl,omitempty"`
	// Maximum TTL for in-memory DNS TXT lookup cache entries. Caps the TTL honoured
	// from the DNS record so that a long-lived record does not prevent the cache from
	// reflecting updates within a reasonable time. Must be >= min_cache_ttl. Default: 1h
	// Accepts a Go duration string or a Caddy placeholder (e.g. "{env.MAX_CACHE_TTL}").
	MaxCacheTTL string `json:"max_cache_ttl,omitempty"`
	// TTL applied to failed lookups (NXDOMAIN, no record, timeout). Kept shorter than
	// min_cache_ttl so that newly-added TXT records are discovered quickly. Default: 5s
	// Accepts a Go duration string or a Caddy placeholder (e.g. "{env.NEGATIVE_CACHE_TTL}").
	NegativeCacheTTL string `json:"negative_cache_ttl,omitempty"`
	// How long after a cache entry expires it may still be served while a background
	// refresh is in flight (stale-while-revalidate). When set, an expired entry is
	// returned immediately and a single upstream lookup is triggered in the background
	// rather than blocking the request. Requests arriving after the entry is fully
	// refreshed receive the fresh value. Default: "" (disabled — expired entries block
	// until a fresh result is available).
	// Accepts a Go duration string or a Caddy placeholder (e.g. "{env.STALE_CACHE_TTL}").
	StaleCacheTTL string `json:"stale_cache_ttl,omitempty"`
	// Maximum number of DNS TXT records held in the in-memory cache. Default: 10000
	// Accepts a bare integer or a quoted string (e.g. "{env.MAX_CACHE_SIZE}").
	MaxCacheSize StringOrInt `json:"max_cache_size,omitempty"`
	// Whether to cache DNS TXT lookup results in memory. When false every request
	// triggers a fresh DNS lookup; when true results are cached according to the
	// min_cache_ttl / max_cache_ttl / negative_cache_ttl / stale_cache_ttl
	// parameters. Default: false.
	Cache bool `json:"cache,omitempty"`

	// --- DNS lookup guard ---

	// Whether to enforce the per-client DNS lookup rate limit. When false (the default)
	// all requests are allowed through regardless of how many distinct hostnames they
	// trigger. Set to true to enable the per-IP rate limit. Default: false.
	RateLimit bool `json:"rate_limit,omitempty"`
	// Per-client rate limit: maximum distinct hostnames a single IP may trigger
	// first-time DNS lookups for within the sliding window. Takes two positional
	// arguments: <limit> <duration> (e.g. "50 30s"). Repeat lookups for a hostname
	// already seen within the window are always free. Exceeding the limit returns
	// HTTP 429. Default: 100 1m.
	// Both values accept Caddy global placeholders (e.g. "{env.PER_IP_LIMIT}").
	PerClientRateLimit *PerClientRateLimit `json:"per_client_rate_limit,omitempty"`
	// Maximum number of per-IP trackers held in memory. An arbitrary entry is evicted
	// when the cap is reached, preventing unbounded growth under rotating-IP traffic.
	// Default: 100000. Accepts a bare integer or a quoted string (e.g. "{env.MAX_TRACKED_IPS}").
	MaxTrackedClients StringOrInt `json:"max_tracked_clients,omitempty"`
	// IPv6 prefix length used to group client addresses for rate limiting. IPv6 clients
	// within the same prefix are counted as a single entity, preventing prefix-rotation
	// attacks where an attacker cycles through a large address block to evade per-IP limits.
	// Has no effect on IPv4 addresses. Default: 64 (typical per-host allocation boundary).
	// Accepts a bare integer or a quoted string (e.g. "{env.IPV6_PREFIX_LENGTH}").
	IPv6PrefixLength StringOrInt `json:"ipv6_prefix_length,omitempty"`
	// CIDRs or IPs that are exempt from the per-client DNS lookup rate limit.
	// Accepts bare IPs or CIDR notation (e.g. "10.0.0.0/8").
	// Useful for internal health checks, load tests, or known trusted clients.
	RateLimitBypass []string `json:"rate_limit_bypass,omitempty"`

	// --- Response ---

	// Custom error response template: either a file path or an inline Go html/template
	// string. At provision time the value is first attempted as a file read; if the file
	// does not exist the value is used as a literal template string. Any other file error
	// (e.g. permission denied) is treated as a hard failure. The template has access to
	// .Title, .Detail, and .Resolution fields. When empty the built-in default is used.
	// Accepts a Caddy global placeholder (e.g. "{env.TEMPLATE_PATH}").
	// Security note: the template is loaded under the Caddy process's file permissions;
	// ensure the value is operator-controlled and not derived from untrusted input.
	ResponseTemplate string `json:"response_template,omitempty"`
	// When true, Prometheus metrics are collected for every request: redirects_total (by
	// status code), errors_total (by reason), cache_lookups_total (by status), and
	// request_duration_seconds. Requires Caddy to be built with metrics support (default).
	// Default: false.
	Metrics bool `json:"metrics,omitempty"`
	// When true, Cache-Control: max-age=N and Age: N headers are added to successful
	// redirect responses. max-age is the full TTL of the DNS cache entry; Age is the
	// number of seconds elapsed since the entry was cached. Default: false.
	HTTPCacheControl bool `json:"http_cache_control,omitempty"`
	// Opt-in debug key: when non-empty, requests carrying an X-Debug-Key request header
	// whose value matches this string receive diagnostic response headers describing the
	// DNS lookup outcome. The key is compared using a constant-time comparison to avoid
	// timing-based key enumeration. Accepts a Caddy global placeholder (e.g. "{env.DEBUG_KEY}").
	DebugHeaders string `json:"debug_headers,omitempty"`

	// response rendering
	responseTpl *template.Template
	logger      *zap.Logger
	debugKey    []byte     // compiled from DebugHeaders at provision time; nil when disabled
	metrics     *rdMetrics // nil when Metrics is false

	// redirect
	statusCode          int               // explicit numeric code; only used when !statusCodeAuto && !statusCodeHTML
	statusCodeAuto      bool              // true: pick 302/307 or 301/308 based on request method
	statusCodePermanent bool              // when auto: true → 301/308 pair, false → 302/307 pair
	statusCodeHTML      bool              // true: 200 OK with HTML meta-refresh/JS redirect body
	replacer            *strings.Replacer // shorthand → expanded placeholder pre-processor

	// DNS lookup
	resolver          *net.Resolver
	lookupTTL         time.Duration
	maxLookupTTL      time.Duration
	negativeLookupTTL time.Duration
	staleLookupTTL    time.Duration
	lookupMax         time.Duration
	lookupFunc        func(context.Context, string) ([]string, time.Duration, error) // overridden in tests
	dnsCache          *dnsCache
	maxCacheSize      int
	cacheEnabled      bool // runtime copy of Cache; true in New() so tests work without Provision

	// DNS lookup guard
	hostLimit         *hostLimitState
	maxTrackedClients int
	hostLimitWindow   time.Duration
	maxHostsPerClient int
	ipv6PrefixLen     int  // runtime copy of IPv6PrefixLength; default 64 in New()
	rateLimitEnabled  bool // runtime copy of RateLimit; true in New() so tests work without Provision
	bypassNets        []netip.Prefix
}

// dnsCache holds the in-memory DNS TXT result cache and its associated
// concurrency primitives. Allocated as a pointer in Provision so that
// RedirDns itself contains no mutex fields and can be registered as a
// value type via caddy.RegisterModule(RedirDns{}).
type dnsCache struct {
	mu      sync.RWMutex
	entries map[string]dnsCacheEntry
	group   singleflight.Group
}

// PerClientRateLimit defines the per-client distinct-hostname DNS lookup rate limit.
// It mirrors the RateLimit type in caddy-tls-issuer-rate-limit: two fields, same
// positional Caddyfile syntax (<limit> <duration>).
type PerClientRateLimit struct {
	// Maximum distinct hostnames per client within Duration. Default: 50
	Limit StringOrInt `json:"limit,omitempty"`
	// Sliding window duration. Default: 1m
	Duration string `json:"duration,omitempty"`
}

// hostLimitState holds the per-client hostname tracker map and its mutex.
// Allocated as a pointer in Provision for the same reason as dnsCache.
type hostLimitState struct {
	mu       sync.Mutex
	trackers map[string]*hostTracker
}

// ServeHTTP implements caddyhttp.MiddlewareHandler. The next handler is never
// called because this module always terminates the request with either a
// redirect response or an error page — it is designed as a terminal handler,
// not a pass-through middleware.
func (rd *RedirDns) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	debug := rd.newRequestDebug(r)

	if rd.metrics != nil {
		defer rd.metrics.startTimer().ObserveDuration()
	}

	// extract the host name from the request
	reqHost, err := normalizeRequestHost(r.Host)
	if err != nil {
		if c := rd.logger.Check(zapcore.DebugLevel, "Request cannot be processed because the Host header is invalid"); c != nil {
			c.Write(zap.String("host", r.Host), zap.Error(err))
		}
		debug.reason = "invalid_host"
		if handled, herr := rd.redirectToDefault(w, r, r.Host, &debug); handled {
			if rd.metrics != nil {
				rd.metrics.recordRedirect(effectiveStatusCode(rd.resolveStatusCode(r.Method)))
			}
			return herr
		}
		if rd.metrics != nil {
			rd.metrics.recordError("invalid_host")
		}
		debug.writeHeaders(w)
		return rd.writeHtmlResponse(w, http.StatusNotFound,
			"Redirect Failure",
			err.Error(),
			"DNS-based redirects require a valid hostname. IP addresses do not have TXT records "+
				"and cannot be used as redirect targets. Ensure the request Host header contains a "+
				"properly formed domain name (e.g. www.example.com).")
	}

	debug.host = reqHost

	// check if client has exceeded the per-client distinct-hostname DNS lookup limit
	if rd.rateLimitEnabled && rd.exceedsPerClientHostLimit(r, reqHost, time.Now()) {
		if c := rd.logger.Check(zapcore.DebugLevel, "DNS lookup skipped: client exceeded per-client host limit"); c != nil {
			c.Write(
				zap.String("host", reqHost),
				zap.Duration("window", rd.hostLimitWindow),
				zap.Int("max_hosts_per_client", rd.maxHostsPerClient),
			)
		}
		debug.reason = "rate_limited"
		debug.writeHeaders(w)
		if rd.metrics != nil {
			rd.metrics.recordError("rate_limited")
		}
		return rd.writeHtmlResponse(w, http.StatusTooManyRequests,
			"Too Many Requests",
			fmt.Sprintf("This client has triggered DNS lookups for more than %d distinct hostnames within a %s window.", rd.maxHostsPerClient, rd.hostLimitWindow),
			"The per-client DNS lookup guard limits how many distinct hostnames a single client can trigger "+
				"DNS lookups for within a window, to prevent DNS amplification. Repeat requests to the same "+
				"hostname within the window are not counted against the limit.")
	}

	// create DNS TXT query and perform lookup
	txtQuery := rd.DnsPrefix + "." + reqHost
	debug.query = txtQuery
	txtRecord, err, cacheResult := rd.lookupTXT(txtQuery)
	debug.hasCached = true
	debug.cached = cacheResult != cacheMiss
	debug.records = append([]string(nil), txtRecord...)
	if ttl, ok := rd.remainingCacheTTL(txtQuery); ok {
		debug.hasCacheTTL = true
		debug.cacheTTL = ttl
	}
	if rd.metrics != nil {
		rd.metrics.recordCacheLookup(cacheResult)
	}

	// check if the DNS lookup returned a response
	if err != nil || len(txtRecord) == 0 {
		if c := rd.logger.Check(zapcore.DebugLevel, "DNS TXT lookup did not return redirect data; applying fallback behavior"); c != nil {
			c.Write(
				zap.String("host", reqHost),
				zap.String("query", txtQuery),
				zap.String("reason", classifyLookupError(err)),
			)
		}
		// DNS lookup returned no / invalid response
		debug.reason = "dns_lookup_failed"
		if handled, herr := rd.redirectToDefault(w, r, reqHost, &debug); handled {
			if rd.metrics != nil {
				rd.metrics.recordRedirect(effectiveStatusCode(rd.resolveStatusCode(r.Method)))
			}
			return herr
		}
		var dnsDetail string
		if err != nil {
			dnsDetail = fmt.Sprintf("Lookup failed for TXT record %s (%s).", txtQuery, classifyLookupError(err))
		} else {
			dnsDetail = fmt.Sprintf("No TXT records found at %s.", txtQuery)
		}
		if rd.metrics != nil {
			rd.metrics.recordError("dns_lookup_failed")
		}
		debug.writeHeaders(w)
		return rd.writeHtmlResponse(w, http.StatusNotFound,
			"Redirect Failure",
			dnsDetail,
			fmt.Sprintf("Create a TXT record at %s containing a valid absolute HTTP or HTTPS redirect URL. "+
				"If the record already exists, verify that the configured resolver is reachable and that "+
				"the lookup_timeout setting is sufficient.", txtQuery))
	}

	// iterate over each TXT record in the response
	for i, txt := range txtRecord {
		// parse the TXT record to extract redirect location
		targetUrl, statusCode := rd.parseTxtRecord(reqHost, txt, r)
		if c := rd.logger.Check(zapcore.DebugLevel, "Evaluated DNS TXT redirect candidate"); c != nil {
			c.Write(
				zap.String("host", reqHost),
				zap.Int("txt_index", i),
				zap.Bool("accepted", targetUrl != ""),
				zap.Int("status_code", statusCode),
			)
		}
		if targetUrl != "" {
			if rd.HTTPCacheControl {
				if maxAge, age, ok := rd.cacheTiming(txtQuery); ok {
					w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", int(maxAge.Seconds())))
					w.Header().Set("Age", fmt.Sprintf("%d", int(age.Seconds())))
				}
			}
			debug.reason = "redirect"
			debug.writeHeaders(w)
			if rd.metrics != nil {
				rd.metrics.recordRedirect(effectiveStatusCode(statusCode))
			}
			if statusCode == htmlRedirectCode {
				return writeHtmlRedirectResponse(w, targetUrl)
			}
			return writeRedirectResponse(w, statusCode, targetUrl)
		}
	}

	// none of the TXT records contained a valid redirect
	debug.reason = "no_valid_txt_record"
	if handled, herr := rd.redirectToDefault(w, r, reqHost, &debug); handled {
		if rd.metrics != nil {
			rd.metrics.recordRedirect(effectiveStatusCode(rd.resolveStatusCode(r.Method)))
		}
		return herr
	}

	if rd.metrics != nil {
		rd.metrics.recordError("no_valid_txt_record")
	}
	debug.writeHeaders(w)
	return rd.writeHtmlResponse(w, http.StatusNotFound,
		"Redirect Failure",
		fmt.Sprintf("TXT records were found at %s but none contained a valid redirect target URL.", txtQuery),
		"Each TXT record value must be a valid absolute HTTP or HTTPS URL containing only printable ASCII "+
			"characters. An optional status token may follow the URL separated by a space: use the keywords "+
			"\"temporary\" or \"permanent\" (method-preserving) or a numeric code (301, 302, 303, 307, 308). "+
			"URLs must not include credentials (user:pass@host).")
}

// redirectToDefault redirects to DefaultTarget when configured. Reports whether
// the redirect was written so the caller can return immediately.
func (rd *RedirDns) redirectToDefault(w http.ResponseWriter, r *http.Request, host string, debug *requestDebug) (bool, error) {
	if rd.DefaultTarget == "" {
		return false, nil
	}
	code := rd.resolveStatusCode(r.Method)
	debug.writeHeaders(w)
	if code == htmlRedirectCode {
		return true, writeHtmlRedirectResponse(w, rd.DefaultTarget)
	}
	return true, writeRedirectResponse(w, code, rd.DefaultTarget)
}

// writeRedirectResponse writes a redirect response with the given status code and Location header.
func writeRedirectResponse(w http.ResponseWriter, statusCode int, location string) error {
	w.Header().Set("Location", location)
	w.WriteHeader(statusCode)

	return nil
}

// writeHtmlRedirectResponse sends a 200 OK with an HTML body that redirects the browser
// via a meta-refresh tag and a JavaScript window.location.replace() call. API clients
// that check the HTTP status code or Content-Type receive a 200 with an HTML document
// rather than a 3xx redirect, which can be used to redirect browsers without triggering
// automatic redirect-following in programmatic HTTP clients.
func writeHtmlRedirectResponse(w http.ResponseWriter, targetURL string) error {
	urlJSON, err := json.Marshal(targetURL)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	return htmlRedirectTpl.Execute(w, htmlRedirectPageData{
		URL:     template.URL(targetURL),
		URLJSON: template.JS(urlJSON),
	})
}

// htmlResponseData holds the fields passed to the error response template.
type htmlResponseData struct {
	Title      string
	Detail     string
	Resolution string
}

// writeHtmlResponse renders the HTML error page template with the given status code, title,
// detail (what went wrong), and resolution (how the operator or user can fix it).
func (rd *RedirDns) writeHtmlResponse(w http.ResponseWriter, statusCode int, title, detail, resolution string) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)

	return rd.responseTpl.Execute(w, htmlResponseData{
		Title:      title,
		Detail:     detail,
		Resolution: resolution,
	})
}

// resolveStatusCode returns the redirect code to use for a request with the given method.
// Returns htmlRedirectCode (-1) when HTML redirect mode is active; otherwise returns the
// method-appropriate 3xx code (auto mode) or the fixed numeric code (explicit mode).
func (rd *RedirDns) resolveStatusCode(method string) int {
	if rd.statusCodeHTML {
		return htmlRedirectCode
	}
	if rd.statusCodeAuto {
		return autoStatusCode(rd.statusCodePermanent, method)
	}
	return rd.statusCode
}

// autoStatusCode selects the method-appropriate redirect status from the 302/307
// (temporary) or 301/308 (permanent) pair. GET and HEAD use the non-method-preserving
// codes (301/302) because the method does not change in practice; all other methods use
// the method-preserving codes (307/308) to prevent the request body from being silently
// discarded by the client.
func autoStatusCode(permanent bool, method string) int {
	if method != http.MethodGet && method != http.MethodHead {
		if permanent {
			return 308
		}
		return 307
	}
	if permanent {
		return 301
	}
	return 302
}

// parseTxtRecord parses a single DNS TXT record value into a redirect target URL and
// HTTP status code. Placeholder expansion is performed in two passes:
//
//  1. rd.replacer rewrites shorthand tokens (e.g. "{host}") to their expanded Caddy
//     equivalents (e.g. "{http.request.host}") so that either form works in TXT records.
//  2. The per-request Caddy replacer substitutes the expanded tokens with live request
//     values. Only an explicit allowlist of request-derived placeholders is accepted;
//     all others are replaced with an empty string to prevent accidental data leakage.
//
// Returns an empty target string if the TXT record does not contain a valid redirect.
func (rd *RedirDns) parseTxtRecord(reqHost string, record string, r *http.Request) (string, int) {
	// first pass: rewrite shorthand tokens to full Caddy placeholder names
	replaced := rd.replacer.Replace(record)

	// second pass: substitute live request values via the per-request Caddy replacer
	replVal := r.Context().Value(caddy.ReplacerCtxKey)
	repl, ok := replVal.(*caddy.Replacer)
	if !ok || repl == nil {
		if c := rd.logger.Check(zapcore.DebugLevel, "Dynamic placeholder expansion skipped because request replacer context is unavailable"); c != nil {
			c.Write()
		}
	} else {
		replaced, _ = repl.ReplaceFunc(replaced, func(key string, val any) (any, error) {
			// {labels.N} and {http.request.host.labels.N} index hostname labels right-to-left:
			// index 0 is the TLD, 1 is the second-level domain, etc.
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
				// reverse the index so that 0 = rightmost label (TLD)
				return strings.ToLower(components[len(components)-idx-1]), nil
			}
			// for security reasons, only substitute the following request-derived placeholders;
			// any other key is blanked out rather than passed through to prevent leaking
			// internal Caddy state (e.g. vars, env, auth) into redirect Location headers
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

	targetUrl := ""
	// start from the module-level default, applying method-based selection when configured
	statusCode := rd.resolveStatusCode(r.Method)

	// split the expanded record on whitespace; format is: "<url> [<status>]"
	parts := strings.Fields(replaced)

	// first token (mandatory): the redirect target URL
	if len(parts) > 0 {
		if isValidAbsoluteURL(parts[0]) && !containsNonPrintableASCII(parts[0]) {
			targetUrl = parts[0]
		} else {
			if c := rd.logger.Check(zapcore.DebugLevel, "Rejected DNS TXT redirect candidate because target is not a valid absolute HTTP/HTTPS URL"); c != nil {
				c.Write()
			}
		}
	}

	// second token (optional): numeric status code or the keywords "permanent" / "temporary" / "html"
	if len(parts) > 1 {
		switch parts[1] {
		case "permanent":
			// select 301 for GET/HEAD, 308 for all other methods
			statusCode = autoStatusCode(true, r.Method)
		case "temporary":
			// select 302 for GET/HEAD, 307 for all other methods
			statusCode = autoStatusCode(false, r.Method)
		case "html":
			statusCode = htmlRedirectCode
		default:
			code, err := strconv.Atoi(parts[1])
			if err == nil && isSupportedStatusCode(code) {
				statusCode = code
			} else {
				if c := rd.logger.Check(zapcore.DebugLevel, "Ignored TXT status token because it is not a supported redirect status"); c != nil {
					c.Write(zap.String("status_token", parts[1]))
				}
			}
		}
	}

	return targetUrl, statusCode
}

// normalizeRequestHost extracts and validates the hostname from an HTTP Host header value.
// It strips an optional port, IPv6 brackets, surrounding whitespace, and a trailing dot
// (absolute-form FQDN), then rejects empty values, IP addresses (which have no DNS TXT
// record to look up), and hostnames that do not conform to DNS label syntax.
// Returns the hostname lowercased and without a trailing dot.
func normalizeRequestHost(host string) (string, error) {
	reqHost, _, err := net.SplitHostPort(host)
	if err != nil {
		reqHost = host
	}
	reqHost = strings.TrimSpace(reqHost)
	reqHost = strings.TrimSuffix(reqHost, ".")
	if reqHost == "" {
		return "", fmt.Errorf("empty host header")
	}
	if _, err := netip.ParseAddr(reqHost); err == nil {
		return "", fmt.Errorf("host is an IP address")
	}
	if !isValidDNSHost(reqHost) {
		return "", fmt.Errorf("invalid hostname %q", reqHost)
	}

	return strings.ToLower(reqHost), nil
}

// isValidDNSHost reports whether host is a syntactically valid DNS hostname per
// RFC 1123: total length ≤ 253 characters, each dot-separated label 1–63 characters,
// composed only of ASCII letters, digits, and hyphens, and not starting or ending
// with a hyphen.
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

// isValidAbsoluteURL reports whether location is a valid absolute HTTP or HTTPS URL
// suitable for use as a redirect target. It rejects non-HTTP(S) schemes, URLs that
// contain a userinfo (credentials) component, and URLs without a host.
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

// effectiveStatusCode converts the internal htmlRedirectCode sentinel (-1) to the
// actual HTTP status it produces (200 OK), leaving all other codes unchanged.
// Used to normalise the code value before recording it as a metric label.
func effectiveStatusCode(code int) int {
	if code == htmlRedirectCode {
		return http.StatusOK
	}
	return code
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

// requestDebug accumulates per-request DNS diagnostic data and writes it as response
// headers when the request carries an X-Debug-Key header matching the configured key.
// The zero value is safe to use (active=false means no headers are emitted).
type requestDebug struct {
	active      bool
	written     bool          // guards against writing headers more than once per response
	host        string        // normalised request hostname
	query       string        // DNS TXT query name (e.g. "_redirdns.www.example.com")
	records     []string      // raw TXT record values returned by the lookup
	cached      bool          // true when the lookup was served from the outer cache
	hasCached   bool          // true once cached has been set
	cacheTTL    time.Duration // remaining time until the cache entry expires
	hasCacheTTL bool          // true once cacheTTL has been set
	reason      string        // outcome: "redirect", "invalid_host", "rate_limited", etc.
}

// newRequestDebug returns an active requestDebug when debug_headers is configured and
// the request's X-Debug-Key header matches the configured key (constant-time comparison).
// It returns an inactive (zero-value) requestDebug when debug_headers is not configured
// or the key does not match, so callers never need a nil check.
func (rd *RedirDns) newRequestDebug(r *http.Request) requestDebug {
	if len(rd.debugKey) == 0 {
		return requestDebug{}
	}
	key := []byte(r.Header.Get("X-Debug-Key"))
	if len(key) == 0 || subtle.ConstantTimeCompare(key, rd.debugKey) != 1 {
		return requestDebug{}
	}
	return requestDebug{active: true}
}

// writeHeaders sets the diagnostic response headers on w. It is a no-op when the
// requestDebug is inactive (debug_headers not configured or key mismatch) or after
// the first call (headers must be set before WriteHeader is called by the response
// writer, and the written flag prevents duplicates when multiple code paths converge).
func (d *requestDebug) writeHeaders(w http.ResponseWriter) {
	if !d.active || d.written {
		return
	}
	d.written = true
	h := w.Header()
	if d.host != "" {
		h.Set("X-Redir-Dns-Host", d.host)
	}
	if d.query != "" {
		h.Set("X-Redir-Dns-Query", d.query)
	}
	for _, rec := range d.records {
		h.Add("X-Redir-Dns-Record", rec)
	}
	if d.hasCached {
		if d.cached {
			h.Set("X-Redir-Dns-Cache", "HIT")
		} else {
			h.Set("X-Redir-Dns-Cache", "MISS")
		}
	}
	if d.hasCacheTTL {
		h.Set("X-Redir-Dns-Cache-Ttl", d.cacheTTL.Round(time.Millisecond).String())
	}
	if d.reason != "" {
		h.Set("X-Redir-Dns-Reason", d.reason)
	}
}

// Interface guard
var _ caddyhttp.MiddlewareHandler = (*RedirDns)(nil)
