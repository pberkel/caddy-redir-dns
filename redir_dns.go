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

var txtPrefixRegex = regexp.MustCompile(`^[_a-zA-Z0-9]([_a-zA-Z0-9-]{0,61}[_a-zA-Z0-9])?$`)

// StringOrInt is a config field type that accepts both a bare JSON number (e.g. 302)
// and a quoted string (e.g. "302" or "{env.STATUS_CODE}"). Values are stored as a
// string so that Caddy environment-variable placeholders can be expanded in Provision
// before the integer is parsed. JSON serialisation round-trips numeric strings back
// to bare numbers for backward compatibility.
type StringOrInt string

// UnmarshalJSON accepts either a bare JSON number or a quoted string.
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

// MarshalJSON emits a bare JSON number when the stored value is purely numeric,
// and a quoted string otherwise, preserving backward-compatible JSON round-trips.
func (s StringOrInt) MarshalJSON() ([]byte, error) {
	if _, err := strconv.Atoi(string(s)); err == nil {
		return []byte(string(s)), nil
	}
	return json.Marshal(string(s))
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
	// Custom DNS nameservers (hostnames or IPs, optional port) used for TXT lookups.
	// When empty the system resolver is used. Multiple entries are tried in order
	// until one succeeds.
	Nameservers []string `json:"nameservers,omitempty"`

	// response rendering
	responseTpl *template.Template
	logger      *zap.Logger

	// redirect
	statusCode int
	replacer   *strings.Replacer // shorthand → expanded placeholder pre-processor

	// DNS lookup
	resolver     *net.Resolver
	lookupTTL    time.Duration
	lookupMax    time.Duration
	lookupFunc   func(context.Context, string) ([]string, time.Duration, error) // overridden in tests
	cacheMu      sync.RWMutex
	cache        map[string]dnsCacheEntry
	maxCacheSize int
	lookupGroup  singleflight.Group

	// rate limiting
	rlMu        sync.Mutex
	clients     map[string]*clientHostTracker
	maxClients  int
	rateWindow  time.Duration
	maxHosts    int
	trustedNets []netip.Prefix
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

// writeRedirectResponse writes a redirect response with the given status code and Location header.
func writeRedirectResponse(w http.ResponseWriter, statusCode int, location string) error {
	w.Header().Set("Location", location)
	w.WriteHeader(statusCode)

	return nil
}

// writeHtmlResponse renders the HTML error page template with the given status code, title, and message.
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
		rd.logger.Debug("Dynamic placeholder expansion skipped because request replacer context is unavailable")
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
	statusCode := rd.statusCode

	// split the expanded record on whitespace; format is: "<url> [<status>]"
	parts := strings.Fields(replaced)

	// first token (mandatory): the redirect target URL
	if len(parts) > 0 {
		if isValidAbsoluteURL(parts[0]) && !containsNonPrintableASCII(parts[0]) {
			targetUrl = parts[0]
		} else {
			rd.logger.Debug("Rejected DNS TXT redirect candidate because target is not a valid absolute HTTP/HTTPS URL")
		}
	}

	// second token (optional): numeric status code or the keywords "permanent" / "temporary"
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

// classifyLookupError returns a short, log-safe string describing the category of a
// DNS lookup error. Used to populate the "reason" field in debug log messages without
// including raw error text that could contain resolver-supplied data.
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
