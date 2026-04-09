package redirdns

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"os"
	"regexp"
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
		StatusCode:              "temporary",
		LookupTimeout:           defaultDnsLookupTimeout.String(),
		CacheTTL:                defaultDnsCacheTTL.String(),
		HostLimitWindow:   defaultHostLimitWindow.String(),
		MaxHostsPerClient: StringOrInt(strconv.Itoa(defaultMaxHostsPerClient)),
		MaxCacheSize:      StringOrInt(strconv.Itoa(defaultMaxCacheSize)),
		MaxTrackedClients: StringOrInt(strconv.Itoa(defaultMaxTrackedClients)),
		resolver:            net.DefaultResolver,
		statusCodeAuto:      true,
		statusCodePermanent: false,
		lookupTTL:         defaultDnsCacheTTL,
		lookupMax:         defaultDnsLookupTimeout,
		cache:             make(map[string]dnsCacheEntry),
		maxCacheSize:      defaultMaxCacheSize,
		hostTrackers:      make(map[string]*hostTracker),
		maxTrackedClients: defaultMaxTrackedClients,
		hostLimitWindow:   defaultHostLimitWindow,
		maxHostsPerClient: defaultMaxHostsPerClient,
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
	rd.HostLimitWindow = repl.ReplaceAll(rd.HostLimitWindow, "")
	rd.StatusCode = StringOrInt(repl.ReplaceAll(string(rd.StatusCode), ""))
	rd.MaxHostsPerClient = StringOrInt(repl.ReplaceAll(string(rd.MaxHostsPerClient), ""))
	rd.MaxCacheSize = StringOrInt(repl.ReplaceAll(string(rd.MaxCacheSize), ""))
	rd.MaxTrackedClients = StringOrInt(repl.ReplaceAll(string(rd.MaxTrackedClients), ""))
	for i, p := range rd.TrustedProxies {
		rd.TrustedProxies[i] = repl.ReplaceAll(p, "")
	}
	for i, ns := range rd.Resolvers {
		ns = repl.ReplaceAll(ns, "")
		host, port, splitErr := net.SplitHostPort(ns)
		if splitErr != nil {
			// No port — treat entire value as host, default to port 53.
			host = ns
			port = "53"
			ns = net.JoinHostPort(host, port)
		}
		if net.ParseIP(host) == nil && !isValidDNSHost(host) {
			return fmt.Errorf("invalid resolver address %q", ns)
		}
		p, parseErr := strconv.Atoi(port)
		if parseErr != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port in resolver address %q", ns)
		}
		rd.Resolvers[i] = ns
	}
	rd.ResponseTemplate = repl.ReplaceAll(rd.ResponseTemplate, "")
	rd.DebugHeaders = repl.ReplaceAll(rd.DebugHeaders, "")
	if rd.DebugHeaders != "" {
		rd.debugKey = []byte(rd.DebugHeaders)
	}

	// validate fields whose constraints cannot be expressed as parse errors
	if rd.DefaultTarget != "" && (!isValidAbsoluteURL(rd.DefaultTarget) || containsNonPrintableASCII(rd.DefaultTarget)) {
		return fmt.Errorf("invalid absolute URL default_target '%s'", rd.DefaultTarget)
	}
	if !txtPrefixRegex.MatchString(rd.DnsPrefix) {
		return fmt.Errorf("invalid dns_prefix '%s'", rd.DnsPrefix)
	}

	// parse and validate duration fields
	if rd.lookupMax, err = time.ParseDuration(rd.LookupTimeout); err != nil {
		return fmt.Errorf("invalid lookup_timeout %q: %v", rd.LookupTimeout, err)
	}
	if rd.lookupMax <= 0 {
		return fmt.Errorf("lookup_timeout must be greater than 0")
	}
	if rd.lookupMax > maxLookupTimeout {
		return fmt.Errorf("lookup_timeout must not exceed %s", maxLookupTimeout)
	}
	if rd.lookupTTL, err = time.ParseDuration(rd.CacheTTL); err != nil {
		return fmt.Errorf("invalid cache_ttl %q: %v", rd.CacheTTL, err)
	}
	if rd.lookupTTL <= 0 {
		return fmt.Errorf("cache_ttl must be greater than 0")
	}
	if rd.hostLimitWindow, err = time.ParseDuration(rd.HostLimitWindow); err != nil {
		return fmt.Errorf("invalid host_limit_window %q: %v", rd.HostLimitWindow, err)
	}
	if rd.hostLimitWindow <= 0 {
		return fmt.Errorf("host_limit_window must be greater than 0")
	}

	// parse and validate int fields
	switch string(rd.StatusCode) {
	case "temporary":
		rd.statusCodeAuto, rd.statusCodePermanent = true, false
	case "permanent":
		rd.statusCodeAuto, rd.statusCodePermanent = true, true
	case "html":
		rd.statusCodeHTML = true
	default:
		if rd.statusCode, err = strconv.Atoi(string(rd.StatusCode)); err != nil {
			return fmt.Errorf("invalid status_code %q: must be a numeric code (301/302/303/307/308) or \"temporary\"/\"permanent\"/\"html\"", rd.StatusCode)
		}
		if !isSupportedStatusCode(rd.statusCode) {
			return fmt.Errorf("unsupported status_code %d", rd.statusCode)
		}
		rd.statusCodeAuto = false
	}
	if rd.maxHostsPerClient, err = strconv.Atoi(string(rd.MaxHostsPerClient)); err != nil {
		return fmt.Errorf("invalid max_hosts_per_client %q: %v", rd.MaxHostsPerClient, err)
	}
	if rd.maxHostsPerClient <= 0 {
		return fmt.Errorf("max_hosts_per_client must be greater than 0")
	}
	if rd.maxCacheSize, err = strconv.Atoi(string(rd.MaxCacheSize)); err != nil {
		return fmt.Errorf("invalid max_cache_size %q: %v", rd.MaxCacheSize, err)
	}
	if rd.maxCacheSize <= 0 {
		return fmt.Errorf("max_cache_size must be greater than 0")
	}
	if rd.maxTrackedClients, err = strconv.Atoi(string(rd.MaxTrackedClients)); err != nil {
		return fmt.Errorf("invalid max_tracked_clients %q: %v", rd.MaxTrackedClients, err)
	}
	if rd.maxTrackedClients <= 0 {
		return fmt.Errorf("max_tracked_clients must be greater than 0")
	}

	if len(rd.Resolvers) > 0 {
		rd.lookupFunc = newMiekgLookupFunc(rd.Resolvers)
	}

	rd.trustedNets, err = parseTrustedProxyPrefixes(rd.TrustedProxies)
	if err != nil {
		return err
	}
	// compile error response template — from file, literal string, or built-in default
	if rd.ResponseTemplate != "" {
		src, readErr := os.ReadFile(rd.ResponseTemplate)
		switch {
		case readErr == nil:
			// value resolved to a readable file — use its contents
			rd.responseTpl, err = template.New("custom").Parse(string(src))
			if err != nil {
				return fmt.Errorf("response_template: cannot parse file %q: %w", rd.ResponseTemplate, err)
			}
		case errors.Is(readErr, os.ErrNotExist):
			// no file at that path — treat the value itself as an inline template string
			rd.responseTpl, err = template.New("custom").Parse(rd.ResponseTemplate)
			if err != nil {
				return fmt.Errorf("response_template: cannot parse inline template: %w", err)
			}
		default:
			// file exists but could not be read (e.g. permission denied) — hard failure so
			// that a misconfigured path does not silently fall back to the inline literal
			return fmt.Errorf("response_template: cannot read file %q: %w", rd.ResponseTemplate, readErr)
		}
	} else {
		rd.responseTpl, err = template.New("default").Parse(defaultResponseTemplate)
		if err != nil {
			return err
		}
	}
	if c := rd.logger.Check(zapcore.InfoLevel, "provisioned module"); c != nil {
		c.Write(
			zap.String("default_target", rd.DefaultTarget),
			zap.String("dns_prefix", rd.DnsPrefix),
			zap.String("status_code", string(rd.StatusCode)),
			zap.Duration("lookup_timeout", rd.lookupMax),
			zap.Duration("cache_ttl", rd.lookupTTL),
			zap.Int("max_cache_size", rd.maxCacheSize),
			zap.Int("max_tracked_clients", rd.maxTrackedClients),
			zap.Duration("host_limit_window", rd.hostLimitWindow),
			zap.Int("max_hosts_per_client", rd.maxHostsPerClient),
			zap.Int("trusted_proxy_entries", len(rd.TrustedProxies)),
			zap.Int("resolvers_count", len(rd.Resolvers)),
			zap.String("response_template", rd.ResponseTemplate),
			zap.Bool("debug_headers", len(rd.debugKey) > 0),
		)
	}

	rd.startHostLimitCleanup(ctx)

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
			case "host_limit_window":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.HostLimitWindow = d.Val()
			case "max_hosts_per_client":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.MaxHostsPerClient = StringOrInt(d.Val())
			case "max_cache_size":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.MaxCacheSize = StringOrInt(d.Val())
			case "max_tracked_clients":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.MaxTrackedClients = StringOrInt(d.Val())
			case "trusted_proxies":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.TrustedProxies = append(rd.TrustedProxies, d.Val())
				for d.NextArg() {
					rd.TrustedProxies = append(rd.TrustedProxies, d.Val())
				}
			case "resolvers":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.Resolvers = append(rd.Resolvers, d.Val())
				for d.NextArg() {
					rd.Resolvers = append(rd.Resolvers, d.Val())
				}
			case "response_template":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.ResponseTemplate = d.Val()
			case "log_redirects":
				rd.LogRedirects = true
			case "debug_headers":
				if !d.NextArg() {
					return d.ArgErr()
				}
				rd.DebugHeaders = d.Val()
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
	_ caddyfile.Unmarshaler = (*RedirDns)(nil)
)
