package redirdns

import (
	"fmt"
	"html/template"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func init() {
	caddy.RegisterModule(&RedirDns{})
	httpcaddyfile.RegisterHandlerDirective("redir_dns", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("redir_dns", httpcaddyfile.After, "redir")
}

// New returns a RedirDns instance pre-populated with all default values.
// Both the public config fields and the corresponding unexported runtime fields
// are initialised so that the struct is usable without calling Provision first
// (e.g. in tests).
func New() *RedirDns {
	rd := RedirDns{
		DnsPrefix:               defaultDnsPrefix,
		StatusCode:              StringOrInt(strconv.Itoa(defaultStatusCode)),
		LookupTimeout:           defaultDnsLookupTimeout.String(),
		CacheTTL:                defaultDnsCacheTTL.String(),
		RateWindow:              defaultRateLimitWindow.String(),
		MaxUniqueHostsPerClient: StringOrInt(strconv.Itoa(defaultMaxUniqueHostsPerClient)),
		MaxCacheSize:            StringOrInt(strconv.Itoa(defaultMaxCacheSize)),
		MaxClients:              StringOrInt(strconv.Itoa(defaultMaxClients)),
		resolver:                net.DefaultResolver,
		statusCode:              defaultStatusCode,
		lookupTTL:               defaultDnsCacheTTL,
		lookupMax:               defaultDnsLookupTimeout,
		cache:                   make(map[string]dnsCacheEntry),
		maxCacheSize:            defaultMaxCacheSize,
		clients:                 make(map[string]*clientHostTracker),
		maxClients:              defaultMaxClients,
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
	var err error
	// store reference to the global log
	rd.logger = ctx.Logger()
	// create replacer to expand short placeholders in TXT record values at request time
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

	// expand Caddy global placeholders (e.g. {env.X}) in all config fields
	repl := caddy.NewReplacer()
	rd.DefaultTarget = repl.ReplaceAll(rd.DefaultTarget, "")
	rd.DnsPrefix = repl.ReplaceAll(rd.DnsPrefix, "")
	rd.LookupTimeout = repl.ReplaceAll(rd.LookupTimeout, "")
	rd.CacheTTL = repl.ReplaceAll(rd.CacheTTL, "")
	rd.RateWindow = repl.ReplaceAll(rd.RateWindow, "")
	rd.StatusCode = StringOrInt(repl.ReplaceAll(string(rd.StatusCode), ""))
	rd.MaxUniqueHostsPerClient = StringOrInt(repl.ReplaceAll(string(rd.MaxUniqueHostsPerClient), ""))
	rd.MaxCacheSize = StringOrInt(repl.ReplaceAll(string(rd.MaxCacheSize), ""))
	rd.MaxClients = StringOrInt(repl.ReplaceAll(string(rd.MaxClients), ""))
	for i, p := range rd.TrustedProxies {
		rd.TrustedProxies[i] = repl.ReplaceAll(p, "")
	}
	for i, ns := range rd.Nameservers {
		ns = repl.ReplaceAll(ns, "")
		if _, _, err := net.SplitHostPort(ns); err != nil {
			ns = net.JoinHostPort(ns, "53")
		}
		rd.Nameservers[i] = ns
	}

	// parse duration fields
	if rd.lookupMax, err = time.ParseDuration(rd.LookupTimeout); err != nil {
		return fmt.Errorf("invalid lookup_timeout %q: %v", rd.LookupTimeout, err)
	}
	if rd.lookupTTL, err = time.ParseDuration(rd.CacheTTL); err != nil {
		return fmt.Errorf("invalid cache_ttl %q: %v", rd.CacheTTL, err)
	}
	if rd.rateWindow, err = time.ParseDuration(rd.RateWindow); err != nil {
		return fmt.Errorf("invalid rate_window %q: %v", rd.RateWindow, err)
	}

	// parse int fields
	if rd.statusCode, err = strconv.Atoi(string(rd.StatusCode)); err != nil {
		return fmt.Errorf("invalid status_code %q: %v", rd.StatusCode, err)
	}
	if rd.maxHosts, err = strconv.Atoi(string(rd.MaxUniqueHostsPerClient)); err != nil {
		return fmt.Errorf("invalid max_unique_hosts_per_client %q: %v", rd.MaxUniqueHostsPerClient, err)
	}
	if rd.maxCacheSize, err = strconv.Atoi(string(rd.MaxCacheSize)); err != nil {
		return fmt.Errorf("invalid max_cache_size %q: %v", rd.MaxCacheSize, err)
	}
	if rd.maxClients, err = strconv.Atoi(string(rd.MaxClients)); err != nil {
		return fmt.Errorf("invalid max_clients %q: %v", rd.MaxClients, err)
	}

	if len(rd.Nameservers) > 0 {
		rd.lookupFunc = newMiekgLookupFunc(rd.Nameservers)
	}

	rd.trustedNets, err = parseTrustedProxyPrefixes(rd.TrustedProxies)
	if err != nil {
		return err
	}
	// compile error response template
	rd.responseTpl, err = template.New("default").Parse(defaultResponseTemplate)
	if err != nil {
		return err
	}
	if c := rd.logger.Check(zapcore.InfoLevel, "provisioned module"); c != nil {
		c.Write(
			zap.String("default_target", rd.DefaultTarget),
			zap.String("dns_prefix", rd.DnsPrefix),
			zap.Int("status_code", rd.statusCode),
			zap.Duration("lookup_timeout", rd.lookupMax),
			zap.Duration("cache_ttl", rd.lookupTTL),
			zap.Int("max_cache_size", rd.maxCacheSize),
			zap.Int("max_clients", rd.maxClients),
			zap.Duration("rate_window", rd.rateWindow),
			zap.Int("max_unique_hosts_per_client", rd.maxHosts),
			zap.Int("trusted_proxy_entries", len(rd.TrustedProxies)),
			zap.Int("nameserver_entries", len(rd.Nameservers)),
		)
	}

	rd.startRateLimiterCleanup(ctx)

	return nil
}

// Validate implements caddy.Validator
func (rd *RedirDns) Validate() error {
	// Check if default target is supplied and is a valid absolute URL
	if rd.DefaultTarget != "" && (!isValidAbsoluteURL(rd.DefaultTarget) || containsNonPrintableASCII(rd.DefaultTarget)) {
		return fmt.Errorf("invalid absolute URL default_target '%s'", rd.DefaultTarget)
	}
	// Check if supplied DNS TXT record prefix is valid
	if !txtPrefixRegex.MatchString(rd.DnsPrefix) {
		return fmt.Errorf("invalid dns_prefix '%s'", rd.DnsPrefix)
	}
	// Check if supplied response status code is supported
	statusCode, err := strconv.Atoi(string(rd.StatusCode))
	if err != nil {
		return fmt.Errorf("invalid status_code %q: %v", rd.StatusCode, err)
	}
	if !isSupportedStatusCode(statusCode) {
		return fmt.Errorf("unsupported status_code %d", statusCode)
	}
	lookupTimeout, err := time.ParseDuration(rd.LookupTimeout)
	if err != nil {
		return fmt.Errorf("invalid lookup_timeout %q: %v", rd.LookupTimeout, err)
	}
	if lookupTimeout <= 0 {
		return fmt.Errorf("lookup_timeout must be greater than 0")
	}
	if lookupTimeout > maxLookupTimeout {
		return fmt.Errorf("lookup_timeout must not exceed %s", maxLookupTimeout)
	}
	cacheTTL, err := time.ParseDuration(rd.CacheTTL)
	if err != nil {
		return fmt.Errorf("invalid cache_ttl %q: %v", rd.CacheTTL, err)
	}
	if cacheTTL <= 0 {
		return fmt.Errorf("cache_ttl must be greater than 0")
	}
	rateWindow, err := time.ParseDuration(rd.RateWindow)
	if err != nil {
		return fmt.Errorf("invalid rate_window %q: %v", rd.RateWindow, err)
	}
	if rateWindow <= 0 {
		return fmt.Errorf("rate_window must be greater than 0")
	}
	maxHosts, err := strconv.Atoi(string(rd.MaxUniqueHostsPerClient))
	if err != nil || maxHosts <= 0 {
		return fmt.Errorf("max_unique_hosts_per_client must be greater than 0")
	}
	maxCacheSize, err := strconv.Atoi(string(rd.MaxCacheSize))
	if err != nil || maxCacheSize <= 0 {
		return fmt.Errorf("max_cache_size must be greater than 0")
	}
	maxClients, err := strconv.Atoi(string(rd.MaxClients))
	if err != nil || maxClients <= 0 {
		return fmt.Errorf("max_clients must be greater than 0")
	}
	for _, ns := range rd.Nameservers {
		host, port, splitErr := net.SplitHostPort(ns)
		if splitErr != nil {
			// no port — entire value is the host; port validation below is skipped.
			// In the normal Caddy lifecycle Provision runs first and normalises all
			// bare addresses to host:port form, so this branch is only reachable when
			// Validate is called directly (e.g. in tests) without a prior Provision.
			host = ns
			port = ""
		}
		if net.ParseIP(host) == nil && !isValidDNSHost(host) {
			return fmt.Errorf("invalid nameserver address %q", ns)
		}
		if port != "" {
			p, err := strconv.Atoi(port)
			if err != nil || p < 1 || p > 65535 {
				return fmt.Errorf("invalid port in nameserver address %q", ns)
			}
		}
	}
	return nil
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
				rd.StatusCode = StringOrInt(d.Val())
			case "lookup_timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.LookupTimeout = d.Val()
			case "cache_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.CacheTTL = d.Val()
			case "rate_window":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.RateWindow = d.Val()
			case "max_unique_hosts_per_client":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.MaxUniqueHostsPerClient = StringOrInt(d.Val())
			case "max_cache_size":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.MaxCacheSize = StringOrInt(d.Val())
			case "max_clients":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.MaxClients = StringOrInt(d.Val())
			case "trusted_proxies":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.TrustedProxies = append(rd.TrustedProxies, d.Val())
				for d.NextArg() {
					rd.TrustedProxies = append(rd.TrustedProxies, d.Val())
				}
			case "nameserver":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.Nameservers = append(rd.Nameservers, d.Val())
				for d.NextArg() {
					rd.Nameservers = append(rd.Nameservers, d.Val())
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

// Interface guards
var (
	_ caddy.Provisioner     = (*RedirDns)(nil)
	_ caddy.Validator       = (*RedirDns)(nil)
	_ caddyfile.Unmarshaler = (*RedirDns)(nil)
)
