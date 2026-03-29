package redirdns

import (
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(&RedirDns{})
	httpcaddyfile.RegisterHandlerDirective("redir_dns", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("redir_dns", httpcaddyfile.After, "redir")
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
	rd.maxCacheSize = rd.MaxCacheSize
	rd.maxClients = rd.MaxClients
	rd.trustedNets, err = parseTrustedProxyPrefixes(rd.TrustedProxies)
	if err != nil {
		return err
	}
	// compile error response template
	rd.responseTpl, err = template.New("default").Parse(defaultResponseTemplate)
	if err != nil {
		return err
	}
	rd.logger.Info("provisioned module",
		zap.String("default_target", rd.DefaultTarget),
		zap.String("dns_prefix", rd.DnsPrefix),
		zap.Int("status_code", rd.StatusCode),
		zap.Duration("lookup_timeout", time.Duration(rd.LookupTimeout)),
		zap.Duration("cache_ttl", time.Duration(rd.CacheTTL)),
		zap.Int("max_cache_size", rd.MaxCacheSize),
		zap.Int("max_clients", rd.MaxClients),
		zap.Duration("rate_window", time.Duration(rd.RateWindow)),
		zap.Int("max_unique_hosts_per_client", rd.MaxUniqueHostsPerClient),
		zap.Int("trusted_proxy_entries", len(rd.TrustedProxies)),
	)

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
	if !isSupportedStatusCode(rd.StatusCode) {
		return fmt.Errorf("unsupported status_code %d", rd.StatusCode)
	}
	if rd.LookupTimeout <= 0 {
		return fmt.Errorf("lookup_timeout must be greater than 0")
	}
	if time.Duration(rd.LookupTimeout) > maxLookupTimeout {
		return fmt.Errorf("lookup_timeout must not exceed %s", maxLookupTimeout)
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
	if rd.MaxCacheSize <= 0 {
		return fmt.Errorf("max_cache_size must be greater than 0")
	}
	if rd.MaxClients <= 0 {
		return fmt.Errorf("max_clients must be greater than 0")
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
			case "max_cache_size":
				if !d.NextArg() {
					return d.ArgErr()
				}
				maxCacheSize, err := strconv.Atoi(d.Val())
				if err != nil {
					return fmt.Errorf("invalid max_cache_size %q: %v", d.Val(), err)
				}
				rd.MaxCacheSize = maxCacheSize
			case "max_clients":
				if !d.NextArg() {
					return d.ArgErr()
				}
				maxClients, err := strconv.Atoi(d.Val())
				if err != nil {
					return fmt.Errorf("invalid max_clients %q: %v", d.Val(), err)
				}
				rd.MaxClients = maxClients
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

// Interface guards
var (
	_ caddy.Provisioner     = (*RedirDns)(nil)
	_ caddy.Validator       = (*RedirDns)(nil)
	_ caddyfile.Unmarshaler = (*RedirDns)(nil)
)
