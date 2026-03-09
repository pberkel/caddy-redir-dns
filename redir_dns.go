package redirdns

import (
	"context"
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
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

const (
	// Default DNS TXT record prefix
	defaultDnsPrefix = "_redirdns"

	// Default HTTP response status code
	defaultStatusCode = 302

	// Default DNS lookup timeout per request
	defaultDnsLookupTimeout = 500 * time.Millisecond

	// Default DNS TXT cache TTL
	defaultDnsCacheTTL = 30 * time.Second

	// Default per-client window for unique host tracking
	defaultRateLimitWindow = time.Minute

	// Default maximum unique hosts per client in a window
	defaultMaxUniqueHostsPerClient = 50

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

var errNoTXTRecord = errors.New("no TXT DNS record found")

func init() {
	caddy.RegisterModule(&RedirDns{})
	httpcaddyfile.RegisterHandlerDirective("redir_dns", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("redir_dns", httpcaddyfile.After, "redir")
}

type dnsCacheEntry struct {
	txt       []string
	err       error
	expiresAt time.Time
}

type clientHostTracker struct {
	hosts    map[string]time.Time
	lastSeen time.Time
}

// RedirDns is a Caddy module implementing HTTP redirects stored in DNS TXT records
type RedirDns struct {
	// The target URL to redirect when an error occurs. Default: none
	DefaultTarget string `json:"default_target,omitempty"`
	// DNS TXT record prefix where the redirect information is stored. Default: "_redirdns"
	DnsPrefix string `json:"dns_prefix,omitempty"`
	// The HTTP status code returned by the redirect response. Default: 302
	StatusCode int `json:"status_code,omitempty"`
	// Maximum time to wait for DNS TXT lookups before falling back. Default: 500ms
	LookupTimeout caddy.Duration `json:"lookup_timeout,omitempty"`
	// TTL for in-memory DNS TXT lookup cache entries. Default: 30s
	CacheTTL caddy.Duration `json:"cache_ttl,omitempty"`
	// Sliding window used to track per-client unique hosts. Default: 1m
	RateWindow caddy.Duration `json:"rate_window,omitempty"`
	// Maximum unique hosts allowed per client within rate_window. Default: 50
	MaxUniqueHostsPerClient int `json:"max_unique_hosts_per_client,omitempty"`
	// Trusted proxy CIDRs or IPs allowed to supply client IP via X-Forwarded-For
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	// The HTML response document served when the redirect cannot be completed
	responseTpl *template.Template
	logger      *zap.Logger
	replacer    *strings.Replacer
	resolver    *net.Resolver
	lookupTTL   time.Duration
	lookupMax   time.Duration
	lookupFunc  func(context.Context, string) ([]string, error)
	cacheMu     sync.RWMutex
	cache       map[string]dnsCacheEntry
	lookupGroup singleflight.Group
	rlMu        sync.Mutex
	clients     map[string]*clientHostTracker
	rateWindow  time.Duration
	maxHosts    int
	trustedNets []netip.Prefix
	lastCleanup time.Time
}

func New() *RedirDns {
	// create and return new RedirDns struct with default values
	rd := RedirDns{
		DefaultTarget:           "",
		DnsPrefix:               defaultDnsPrefix,
		StatusCode:              defaultStatusCode,
		LookupTimeout:           caddy.Duration(defaultDnsLookupTimeout),
		CacheTTL:                caddy.Duration(defaultDnsCacheTTL),
		RateWindow:              caddy.Duration(defaultRateLimitWindow),
		MaxUniqueHostsPerClient: defaultMaxUniqueHostsPerClient,
		resolver:                net.DefaultResolver,
		lookupTTL:               defaultDnsCacheTTL,
		lookupMax:               defaultDnsLookupTimeout,
		cache:                   make(map[string]dnsCacheEntry),
		clients:                 make(map[string]*clientHostTracker),
		rateWindow:              defaultRateLimitWindow,
		maxHosts:                defaultMaxUniqueHostsPerClient,
	}
	return &rd
}

// CaddyModule returns the Caddy module information
func (*RedirDns) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "http.handlers.redir_dns",
		New: func() caddy.Module {
			return New()
		},
	}
}

// Provision implements caddy.Provisioner
func (rd *RedirDns) Provision(ctx caddy.Context) error {
	var err error = nil
	// store reference to the global log
	rd.logger = ctx.Logger()
	// create replacer to expand short placeholders
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
	rd.lookupMax = time.Duration(rd.LookupTimeout)
	rd.lookupTTL = time.Duration(rd.CacheTTL)
	rd.rateWindow = time.Duration(rd.RateWindow)
	rd.maxHosts = rd.MaxUniqueHostsPerClient
	rd.trustedNets, err = parseTrustedProxyPrefixes(rd.TrustedProxies)
	if err != nil {
		return err
	}
	// compile error response template
	rd.responseTpl, err = template.New("default").Parse(defaultResponseTemplate)

	return err
}

// Validate implements caddy.Validator
func (rd *RedirDns) Validate() error {
	// Check if default target is supplied and is a valid absolute URL
	if rd.DefaultTarget != "" && !isValidAbsoluteURL(rd.DefaultTarget) {
		return fmt.Errorf("invalid absolute URL default_target '%s'", rd.DefaultTarget)
	}
	// Check if supplied DNS TXT record prefix is valid
	var txtprefixRegex = regexp.MustCompile(`^[_a-zA-Z0-9]([_a-zA-Z0-9-]{0,61}[_a-zA-Z0-9])?$`)
	if !txtprefixRegex.MatchString(rd.DnsPrefix) {
		return fmt.Errorf("invalid dns_prefix '%s'", rd.DnsPrefix)
	}
	// Check if supplied response status code is supported
	if !isSupportedStatusCode(rd.StatusCode) {
		return fmt.Errorf("unsupported status_code %d", rd.StatusCode)
	}
	if rd.LookupTimeout <= 0 {
		return fmt.Errorf("lookup_timeout must be greater than 0")
	}
	if rd.CacheTTL <= 0 {
		return fmt.Errorf("cache_ttl must be greater than 0")
	}
	if rd.RateWindow <= 0 {
		return fmt.Errorf("rate_window must be greater than 0")
	}
	if rd.MaxUniqueHostsPerClient <= 0 {
		return fmt.Errorf("max_unique_hosts_per_client must be greater than 0")
	}
	if _, err := parseTrustedProxyPrefixes(rd.TrustedProxies); err != nil {
		return err
	}
	rd.logger.Info("provisioned module with default values",
		zap.String("default_target", rd.DefaultTarget),
		zap.String("dns_prefix", rd.DnsPrefix),
		zap.Int("status_code", rd.StatusCode),
		zap.Duration("lookup_timeout", time.Duration(rd.LookupTimeout)),
		zap.Duration("cache_ttl", time.Duration(rd.CacheTTL)),
		zap.Duration("rate_window", time.Duration(rd.RateWindow)),
		zap.Int("max_unique_hosts_per_client", rd.MaxUniqueHostsPerClient),
		zap.Int("trusted_proxy_entries", len(rd.TrustedProxies)),
	)

	return nil
}

func (rd *RedirDns) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {

	// extract the host name from the request
	reqHost, err := normalizeRequestHost(r.Host)
	if err != nil {
		rd.logger.Debug("Request cannot be processed for DNS redirect because the Host header is invalid",
			zap.String("host", r.Host), zap.Error(err))
		if rd.DefaultTarget != "" {
			// redirect to default target if supplied
			return writeRedirectResponse(w, rd.StatusCode, rd.DefaultTarget)
		}
		return rd.writeHtmlResponse(w, http.StatusNotFound,
			"Redirect Failed", "Unable to process request hostname")
	}

	// create DNS TXT query and perform lookup
	txtQuery := rd.DnsPrefix + "." + reqHost
	clientID := rd.clientIDFromRequest(r)
	if rd.isClientHostRateLimited(clientID, reqHost, time.Now()) {
		rd.logger.Debug("DNS lookup skipped because client exceeded unique host rate limit in active window",
			zap.String("client_id", clientID),
			zap.String("host", reqHost),
			zap.Duration("window", rd.rateWindow),
			zap.Int("max_unique_hosts", rd.maxHosts))
		if rd.DefaultTarget != "" {
			return writeRedirectResponse(w, rd.StatusCode, rd.DefaultTarget)
		}
		return rd.writeHtmlResponse(w, http.StatusTooManyRequests,
			"Too Many Requests", "Too many unique hostnames requested in a short period")
	}
	txtRecord, err := rd.lookupTXT(r.Context(), txtQuery)

	// check if the DNS lookup returned a response
	if err != nil || len(txtRecord) == 0 {
		rd.logger.Debug("DNS TXT lookup did not return redirect data; applying fallback behavior",
			zap.String("host", reqHost),
			zap.String("query", txtQuery),
			zap.String("reason", classifyLookupError(err)))
		// DNS lookup returned no / invalid response
		if rd.DefaultTarget != "" {
			// redirect to default target if supplied
			return writeRedirectResponse(w, rd.StatusCode, rd.DefaultTarget)
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
		return writeRedirectResponse(w, rd.StatusCode, rd.DefaultTarget)
	}

	return rd.writeHtmlResponse(w, http.StatusNotFound,
		"Redirect Failed", "Unable to determine redirect target")
}

func writeRedirectResponse(w http.ResponseWriter, statusCode int, location string) error {
	w.Header().Set("Location", location)
	w.WriteHeader(statusCode)

	return nil
}

func (rd *RedirDns) writeHtmlResponse(w http.ResponseWriter, statusCode int, title, msg string) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	data := map[string]string{
		"Title": title,
		"Msg":   msg,
	}

	return rd.responseTpl.Execute(w, data)
}

func (rd *RedirDns) parseTxtRecord(reqHost string, record string, r *http.Request) (string, int) {
	// expand and replace shortcode placeholder values
	replaced := rd.replacer.Replace(record)
	replVal := r.Context().Value(caddy.ReplacerCtxKey)
	repl, ok := replVal.(*caddy.Replacer)
	if !ok || repl == nil {
		rd.logger.Debug("Dynamic placeholder expansion skipped because request replacer context is unavailable")
	} else {
		replaced, _ = repl.ReplaceFunc(replaced, func(key string, val any) (any, error) {
			// hostname component labels (seperated by dots)
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
				return strings.ToLower(components[len(components)-idx-1]), nil
			}
			// for security reasons, only replace the following placeholders
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
	// set default return values
	targetUrl := ""
	statusCode := rd.StatusCode
	// split the expanded record on whitespace
	parts := strings.Fields(replaced)
	// First part (manditory) should be the target URL
	if len(parts) > 0 {
		if isValidAbsoluteURL(parts[0]) {
			targetUrl = parts[0]
		} else {
			rd.logger.Debug("Rejected DNS TXT redirect candidate because target is not a valid absolute HTTP/HTTPS URL")
		}
	}
	// Second part (optional) could be the status code
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

func (rd *RedirDns) lookupTXT(ctx context.Context, query string) ([]string, error) {
	now := time.Now()
	if txt, err, found := rd.cachedLookup(query, now); found {
		return txt, err
	}

	value, _, _ := rd.lookupGroup.Do(query, func() (any, error) {
		checkNow := time.Now()
		if txt, err, found := rd.cachedLookup(query, checkNow); found {
			return dnsCacheEntry{txt: txt, err: err}, nil
		}

		lookupCtx, cancel := context.WithTimeout(ctx, rd.lookupMax)
		defer cancel()
		var (
			txt []string
			err error
		)
		if rd.lookupFunc != nil {
			txt, err = rd.lookupFunc(lookupCtx, query)
		} else {
			txt, err = rd.resolver.LookupTXT(lookupCtx, query)
		}
		if err == nil && len(txt) == 0 {
			err = errNoTXTRecord
		}

		entry := dnsCacheEntry{
			txt:       append([]string(nil), txt...),
			err:       err,
			expiresAt: checkNow.Add(rd.lookupTTL),
		}
		rd.storeLookup(query, entry)

		return entry, nil
	})

	entry := value.(dnsCacheEntry)
	return append([]string(nil), entry.txt...), entry.err
}

func (rd *RedirDns) cachedLookup(query string, now time.Time) ([]string, error, bool) {
	rd.cacheMu.RLock()
	entry, ok := rd.cache[query]
	rd.cacheMu.RUnlock()
	if !ok {
		return nil, nil, false
	}
	if now.After(entry.expiresAt) {
		rd.cacheMu.Lock()
		if current, exists := rd.cache[query]; exists && now.After(current.expiresAt) {
			delete(rd.cache, query)
		}
		rd.cacheMu.Unlock()
		return nil, nil, false
	}

	return append([]string(nil), entry.txt...), entry.err, true
}

func (rd *RedirDns) storeLookup(query string, entry dnsCacheEntry) {
	rd.cacheMu.Lock()
	rd.cache[query] = entry
	rd.cacheMu.Unlock()
}

func (rd *RedirDns) clientIDFromRequest(r *http.Request) string {
	remoteIP, ok := parseIPFromAddrPortOrLiteral(r.RemoteAddr)
	if !ok {
		return "unknown"
	}
	if !rd.isTrustedProxy(remoteIP) {
		return remoteIP.String()
	}

	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff == "" {
		return remoteIP.String()
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		candidateIP, valid := parseIPFromAddrPortOrLiteral(strings.TrimSpace(parts[i]))
		if !valid {
			continue
		}
		if rd.isTrustedProxy(candidateIP) {
			continue
		}
		return candidateIP.String()
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

func (rd *RedirDns) isClientHostRateLimited(clientID, host string, now time.Time) bool {
	if rd.maxHosts <= 0 || rd.rateWindow <= 0 {
		return false
	}

	rd.rlMu.Lock()
	defer rd.rlMu.Unlock()

	rd.cleanupRateLimitState(now)

	tracker, ok := rd.clients[clientID]
	if !ok {
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

func (rd *RedirDns) cleanupRateLimitState(now time.Time) {
	if rd.lastCleanup.IsZero() {
		rd.lastCleanup = now
		return
	}
	if now.Sub(rd.lastCleanup) < rd.rateWindow {
		return
	}
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
	rd.lastCleanup = now
}

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

func isValidDNSHost(host string) bool {
	if len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
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

func isValidAbsoluteURL(location string) bool {
	parsedUrl, err := url.Parse(location)
	if err != nil {
		return false
	}
	// restrict to HTTP/HTTPS only
	if parsedUrl.Scheme != "http" && parsedUrl.Scheme != "https" {
		return false
	}
	// must have a non-empty host
	return parsedUrl.Host != ""
}

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
	// HTTP response code can be any number in the 3xx range or 401
	if (code >= 300 && code < 400) || code == 401 {
		return true
	}

	return false
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (rd *RedirDns) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "default_target":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.DefaultTarget = d.Val()
			case "dns_prefix":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.DnsPrefix = d.Val()
			case "status_code":
				if !d.NextArg() {
					return d.ArgErr()
				}
				statusCode, err := strconv.Atoi(d.Val())
				if err != nil {
					return fmt.Errorf("invalid status code %q: %v", d.Val(), err)
				}
				rd.StatusCode = statusCode
			case "lookup_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				timeout, err := time.ParseDuration(d.Val())
				if err != nil {
					return fmt.Errorf("invalid lookup_timeout %q: %v", d.Val(), err)
				}
				rd.LookupTimeout = caddy.Duration(timeout)
			case "cache_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				ttl, err := time.ParseDuration(d.Val())
				if err != nil {
					return fmt.Errorf("invalid cache_ttl %q: %v", d.Val(), err)
				}
				rd.CacheTTL = caddy.Duration(ttl)
			case "rate_window":
				if !d.NextArg() {
					return d.ArgErr()
				}
				window, err := time.ParseDuration(d.Val())
				if err != nil {
					return fmt.Errorf("invalid rate_window %q: %v", d.Val(), err)
				}
				rd.RateWindow = caddy.Duration(window)
			case "max_unique_hosts_per_client":
				if !d.NextArg() {
					return d.ArgErr()
				}
				maxHosts, err := strconv.Atoi(d.Val())
				if err != nil {
					return fmt.Errorf("invalid max_unique_hosts_per_client %q: %v", d.Val(), err)
				}
				rd.MaxUniqueHostsPerClient = maxHosts
			case "trusted_proxies":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.TrustedProxies = append(rd.TrustedProxies, d.Val())
				for d.NextArg() {
					rd.TrustedProxies = append(rd.TrustedProxies, d.Val())
				}
			default:
				return d.Errf("unrecognized configuration option %q", d.Val())
			}
		}
	}

	return nil
}

// parseCaddyfile unmarshals tokens into a new RedirDns struct.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var rd = New()
	err := rd.UnmarshalCaddyfile(h.Dispenser)
	return rd, err
}

// Interface guard
var (
	_ caddy.Provisioner           = (*RedirDns)(nil)
	_ caddy.Validator             = (*RedirDns)(nil)
	_ caddyhttp.MiddlewareHandler = (*RedirDns)(nil)
	_ caddyfile.Unmarshaler       = (*RedirDns)(nil)
)
