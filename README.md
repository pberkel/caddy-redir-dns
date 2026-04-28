# HTTP redirect module for Caddy Server 2

A [Caddy](https://caddyserver.com) HTTP handler module that serves redirects configured entirely through DNS TXT records. Domain owners can manage host-level redirects without any changes to the Caddy configuration — adding, updating, or removing a redirect is a DNS change only.

### Installation

This module requires Caddy Server 2.11.1 or later.  The simplest way to build the module is using xcaddy:

```bash
$ xcaddy build --with github.com/pberkel/caddy-redir-dns
```

### Configuration

This module implements the Caddy HTTP handler interface so can be configured very easily in a Caddyfile:

```caddyfile
:80 {
  redir_dns
}
```

Several optional parameters are also supported:

```caddyfile
:80 {
	redir_dns {
		# Redirect parameters
		default_target          https://www.example.com
		status_code             temporary
		dns_prefix              _redirdns
		# DNS parameters
		resolvers               1.1.1.1 8.8.8.8
		lookup_timeout          2s
		# Cache parameters
		cache                   true
		min_cache_ttl           30s
		max_cache_ttl           1h
		negative_cache_ttl      5s
		stale_cache_ttl         30s
		max_cache_size          10_000
		# Rate limit parameters
		rate_limit              true
		per_client_rate_limit   50 1m
		max_tracked_clients     100_000
		ipv6_prefix_length      64
		rate_limit_bypass       192.168.0.0/16 192.168.2.1/32
		# Response parameters
		response_template       /etc/caddy/error.html
		http_cache_control
		metrics
		debug_headers           my-secret-key
	}
}
```

All parameters accept [Caddy global placeholders](https://caddyserver.com/docs/caddyfile/concepts#placeholders) (expanded at startup, not per-request). The most common use is injecting values from environment variables:

```caddyfile
:80 {
	redir_dns {
		default_target  "{env.FALLBACK_URL}"
		status_code     "{env.REDIRECT_STATUS}"
		lookup_timeout  "{env.LOOKUP_TIMEOUT}"
	}
}
```

**Redirect**

| Parameter | Default | Description |
|---|---|---|
| `default_target` | — | Redirect URL used as a fallback when an error occurs (invalid host, missing or invalid TXT record). When unset a `404` is returned instead. |
| `status_code` | `temporary` | HTTP redirect status. Keywords: `temporary` (`302`/`307`), `permanent` (`301`/`308`), `html` (`200 OK` with meta-refresh + JS redirect for browser-only redirects). Numeric codes `301`, `302`, `303`, `307`, `308` are also accepted and always emit that exact code regardless of method. Keywords are preferred — `temporary` and `permanent` automatically select the method-preserving code (`307`/`308`) for non-`GET` requests. |
| `dns_prefix` | `_redirdns` | Prefix used to form the TXT record query name: `<dns_prefix>.<host>`. |

**DNS lookup**

| Parameter | Default | Description |
|---|---|---|
| `resolvers` | system | One or more DNS resolver addresses (`host` or `host:port`, e.g. `1.1.1.1`, `8.8.8.8:53`, `dns.example.com:5353`). Tried in order; port `53` assumed when omitted. When absent the system resolver is used. |
| `lookup_timeout` | `2s` | Maximum time to wait for a DNS TXT lookup before applying fallback behaviour. Go duration string; maximum `30s`. |

**DNS cache**

| Parameter | Default | Description |
|---|---|---|
| `cache` | `false` | Enable in-memory caching of DNS TXT lookup results. When `false` (default) every request triggers a fresh DNS lookup. Set to `true` on high-traffic deployments where DNS lookup latency would otherwise be a bottleneck. The remaining cache parameters (`min_cache_ttl`, `max_cache_ttl`, etc.) only take effect when `cache true` is set. |
| `min_cache_ttl` | `30s` | Time to cache successful DNS TXT results in memory. When custom `resolvers` are not configured the system resolver is used, which does not expose DNS record TTLs — this value is used directly as the cache TTL. When custom resolvers are configured and the DNS record returns a TTL, the larger of the two is used, up to `max_cache_ttl`. Must be ≤ `max_cache_ttl`. Go duration string. |
| `max_cache_ttl` | `1h` | Maximum time to cache successful DNS TXT results in memory. Caps the TTL honoured from the DNS record so that long-lived records are still refreshed within a predictable bound. Must be ≥ `min_cache_ttl`. Go duration string. |
| `negative_cache_ttl` | `5s` | Time to cache failed lookups (NXDOMAIN, no record found, timeout). Kept shorter than `min_cache_ttl` so that newly-added TXT records are discovered quickly. Go duration string. |
| `stale_cache_ttl` | — | How long after a cache entry expires it may still be served while a single background refresh is in flight (stale-while-revalidate). Eliminates cache-stampede bursts when many entries expire simultaneously — requests during the stale window return immediately with the old value; only one upstream lookup per key is triggered. Once `min_cache_ttl + stale_cache_ttl` is exceeded the next caller blocks on a fresh lookup as normal. Disabled when absent. Go duration string. |
| `max_cache_size` | `10_000` | Maximum number of DNS TXT results held in the in-memory cache. The entry with the soonest expiry is evicted when full. |

**DNS lookup guard / Request rate limit**

| Parameter | Default | Description |
|---|---|---|
| `rate_limit` | `false` | Enable per-client DNS lookup rate limiting. When `false` (default) all requests pass through regardless of how many distinct hostnames they trigger. Set to `true` on public deployments to guard against DNS amplification from a single client. The remaining rate-limit parameters only take effect when `rate_limit true` is set. |
| `per_client_rate_limit` | `50 1m` | Per-client rate limit: `<limit> <duration>`. Maximum distinct hostnames a single IP may trigger first-time DNS lookups for within a fixed window. Repeat lookups for a hostname already seen in the window are always free. All per-client state is reset atomically at each window boundary. Exceeding the limit returns `429`. Both values accept Caddy global placeholders. |
| `max_tracked_clients` | `100_000` | Maximum number of per-IP tracking entries held in memory. An arbitrary entry is evicted when full, preventing unbounded memory growth under rotating-IP traffic. |
| `ipv6_prefix_length` | `64` | IPv6 prefix length used to group client addresses for rate limiting. Clients within the same prefix are counted as a single entity, preventing prefix-rotation attacks where an attacker cycles through a large IPv6 block to evade per-IP limits. Has no effect on IPv4 addresses. Accepts values between `1` and `128`; use `128` to track each IPv6 address individually. |
| `rate_limit_bypass` | — | CIDRs or IPs exempt from the per-client DNS lookup rate limit. Each value may be a bare IP address or a CIDR prefix (e.g. `10.0.0.0/8`). The resolved client IP is matched against this list. Useful for load testing, internal health checks, or other known trusted clients. |

> **Client IP resolution and trusted proxies:** `caddy-redir-dns` reads the client IP resolved by Caddy's own trusted-proxy pipeline rather than implementing its own `X-Forwarded-For` parsing. Configure trusted proxies once at the Caddy server level using the global `servers` block:
>
> ```caddyfile
> {
>     servers {
>         trusted_proxies static 10.0.0.0/8 192.168.0.0/16
>     }
> }
> ```
>
> When a request arrives from a trusted peer, Caddy walks `X-Forwarded-For` left-to-right by default and stores the resolved client IP in the request context. `caddy-redir-dns` reads this value directly for rate-limit tracking — no additional configuration is required in the module itself.
>
> If your deployment uses `X-Forwarded-For` in the conventional format (rightmost entry is the closest proxy), add `trusted_proxies_strict` inside the `servers` block. This switches Caddy to a right-to-left walk, which finds the rightmost non-trusted entry and is more resistant to header spoofing:
>
> ```caddyfile
> {
>     servers {
>         trusted_proxies static 10.0.0.0/8
>         trusted_proxies_strict
>     }
> }
> ```
>
> See the [Caddy documentation](https://caddyserver.com/docs/caddyfile/options#servers) for the full list of server options.

**Response**

| Parameter | Default | Description |
|---|---|---|
| `response_template` | built-in | Custom error page: a file path or inline [Go html/template](https://pkg.go.dev/html/template) string. Resolved at provision time — file content is used when readable; the value is used as a literal template otherwise; any other file error is a hard failure. Template fields: `.Title`, `.Detail`, `.Resolution`. See `examples/error_template.html`. |
| `metrics` | `false` | Expose Prometheus metrics. When enabled, the following metrics are emitted under the `caddy_redir_dns_` namespace: `redirects_total{code}` (redirect responses by HTTP status code), `errors_total{reason}` (error responses by reason: `invalid_host`, `rate_limited`, `dns_lookup_failed`, `no_valid_txt_record`), `cache_lookups_total{status}` (cache outcomes: `hit`, `miss`, `stale`), `request_duration_seconds` (handler latency histogram). Requires Caddy to be built with metrics support (enabled by default). Metrics are scraped from the standard Caddy `/metrics` endpoint. |
| `http_cache_control` | `false` | Add `Cache-Control: max-age=N` and `Age: N` headers to successful redirect responses. `max-age` is the full TTL of the DNS cache entry; `Age` is the number of seconds elapsed since the entry was cached. Not added to error responses (404, 429). |
| `debug_headers` | — | Secret key for opt-in diagnostic response headers. Requests carrying `X-Debug-Key: <key>` with a matching value receive the headers below. Key is constant-time compared. |

When `debug_headers` is active the following response headers are added:

| Response Header | Present when | Value |
|---|---|---|
| `X-Redir-Dns-Host` | valid hostname found | normalised request hostname |
| `X-Redir-Dns-Query` | lookup attempted | TXT query name (e.g. `_redirdns.www.example.com`) |
| `X-Redir-Dns-Record` | records returned | raw TXT record value; one header per record |
| `X-Redir-Dns-Cache` | lookup attempted | `HIT` or `MISS` |
| `X-Redir-Dns-Cache-Ttl` | cache entry exists | remaining TTL (e.g. `28.5s`) |
| `X-Redir-Dns-Reason` | always | `redirect`, `invalid_host`, `rate_limited`, `dns_lookup_failed`, or `no_valid_txt_record` |

### Usage

#### Basic Features

To implement a HTTP redirect for host `www.example.com` first create an A or CNAME DNS record pointing to your Caddy Server:

```
www.example.com. IN CNAME my-caddy-server.com.
```

Then create a corresponding TXT DNS record name with the appropriate `dns_prefix` prepended to the hostname and the value containing the redirect target URL (which must be valid, fully qualified, and contain only printable ASCII characters).

> **URL encoding requirement:** HTTP `Location` headers are ASCII-only (RFC 7230). Any non-ASCII characters in the target URL must be encoded before being placed in the TXT record: use [Punycode](https://en.wikipedia.org/wiki/Punycode) for internationalised domain names (e.g. `xn--mnchen-3ya.de` instead of `münchen.de`) and [percent-encoding](https://en.wikipedia.org/wiki/Percent-encoding) for non-ASCII path or query characters (e.g. `caf%C3%A9` instead of `café`). URLs containing raw non-ASCII or control characters will be rejected at redirect time.

```
_redirdns.www.example.com. IN TXT "https://www.redirect-target.com"
```

To specify a specific response status code for the redirect, simply append the numeric code after the target URL separated by a space character:

```
_redirdns.mail.example.com. IN TXT "https://www.redirect-target.com/mail/ 301"
_redirdns.blog.example.com. IN TXT "https://www.redirect-target.com/blog/ 308"
```

It is also possible to use the keywords `permanent`, `temporary`, or `html` instead of a numeric code.  Unlike numeric codes, `temporary` and `permanent` select the method-appropriate code at request time: `temporary` emits `302` for `GET`/`HEAD` and `307` for all other methods; `permanent` emits `301` for `GET`/`HEAD` and `308` for all other methods.  Using these keywords is preferred over numeric `301`/`302` codes because they preserve the request method and body for `POST`, `PUT`, and `DELETE` redirects without any extra configuration.  The `html` keyword sends a `200 OK` with an HTML meta-refresh and JavaScript redirect — browsers follow it silently while API clients that check the HTTP status code or `Content-Type` receive a plain `200` with an HTML document.

```
_redirdns.one.example.com. IN TXT "https://www.redirect-target.com permanent"
_redirdns.two.example.com. IN TXT "https://www.redirect-target.com temporary"
```

#### Advanced Features

This module supports a subset of Caddy HTTP [placeholders](https://caddyserver.com/docs/caddyfile/concepts#placeholders) to provide dynamic redirect capabilities.  The following supported shorthand or expanded placeholders may be included in TXT records and will be substituted with values from the initial request before the redirect is served:

| __Shorthand__ | __Expanded Placeholder__ |
|---|---|
| {scheme} | {http.request.scheme} |
| {host} | {http.request.host} |
| {labels.*} | {http.request.host.labels.*} |
| {domain} | registrable domain (eTLD+1) of the request host, e.g. `example.com` from `www.example.com` |
| {subdomain} | everything to the left of `{domain}`, e.g. `www` from `www.example.com`; empty string for apex hosts |
| {subdomain.} | `{subdomain}` with a trailing dot appended, or empty string for apex hosts — useful for building host strings: `{subdomain.}{domain}` → `www.example.com` or `example.com` |
| {hostport} | {http.request.hostport} |
| {port} | {http.request.port} |
| {uri} | {http.request.uri} |
| {%uri} | {http.request.uri_escaped} |
| {path} | {http.request.uri.path} |
| {%path} | {http.request.uri.path_escaped} |
| {dir} | {http.request.uri.path.dir} |
| {file} | {http.request.uri.path.file} |
| {query} | {http.request.uri.query} |
| {%query} | {http.request.uri.query_escaped} |
| {?query} | {http.request.uri.prefixed_query} |

**NOTE:** `{%uri}`, `{%path}`, and `{%query}` require Caddy Server 2.11 or later.

**NOTE:** The URL encoding requirement above applies to the fully expanded redirect target. If a placeholder such as `{path}` may expand to non-ASCII characters, use the percent-encoded variant `{%path}` instead to ensure the result is valid ASCII.

Several examples demonstrate how placeholder values will be substituted:

| __Incoming Request__ | __TXT Record__ | __Redirect Response__ |
|---|---|---|
| http://www.old-domain.com/blog/?id=100 | https://www.new-domain.com{path}{?query} | https://www.new-domain.com/blog/?id=100 |
| http://web.old-domain.com/blog/?id=100 | {scheme}://{labels.2}.new-domain.com{uri} | http://web.new-domain.com/blog/?id=100 |
| https://web.old-domain.com/blog/?id=100 | https://www.new-domain.com?host={host}&uri={%uri}| https://www.new-domain.com?host=web.old-domain.com&uri=%2Fblog%2F%3Fid%3D100 |
| http://www.old-domain.com/page | https://{subdomain.}new-domain.com{path} | https://www.new-domain.com/page |
| http://old-domain.com/page | https://{subdomain.}new-domain.com{path} | https://new-domain.com/page |

### Acknowledgements

This module was inspired by [argami/redir-dns](https://github.com/argami/redir-dns), an earlier Caddy module with the same core idea of storing redirects in DNS TXT records.
