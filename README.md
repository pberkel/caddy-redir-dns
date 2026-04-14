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
		default_target       https://www.example.com
		status_code          temporary
		dns_prefix           _redirdns

		resolvers            1.1.1.1 8.8.8.8
		lookup_timeout       2s
		cache_ttl            30s
		negative_cache_ttl   5s
		max_cache_size       10_000

		trusted_proxies      10.0.0.0/8 192.168.0.0/16
		host_limit_window    1m
		max_hosts_per_client 50
		max_tracked_clients  100_000

		response_template    /etc/caddy/error.html
		http_cache_control
		log_redirects
		debug_headers        my-secret-key
	}
}
```

All parameters accept [Caddy global placeholders](https://caddyserver.com/docs/caddyfile/concepts#placeholders) (expanded at startup, not per-request). The most common use is injecting values from environment variables:

```caddyfile
:80 {
	redir_dns {
		default_target "{env.FALLBACK_URL}"
		status_code    "{env.REDIRECT_STATUS}"
		lookup_timeout "{env.LOOKUP_TIMEOUT}"
		trusted_proxies "{env.PROXY_CIDR}"
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
| `cache_ttl` | `30s` | Minimum time to cache successful DNS TXT results in memory. When the record's own DNS TTL is larger it is used instead, so entries are never served from cache longer than the upstream resolver intended. Go duration string. |
| `negative_cache_ttl` | `5s` | Time to cache failed lookups (NXDOMAIN, no record found, timeout). Kept shorter than `cache_ttl` so that newly-added TXT records are discovered quickly. Go duration string. |
| `max_cache_size` | `10000` | Maximum number of DNS TXT results held in the in-memory cache. The entry with the soonest expiry is evicted when full. |

**DNS lookup guard**

| Parameter | Default | Description |
|---|---|---|
| `trusted_proxies` | — | CIDRs or IPs allowed to supply the client address via `X-Forwarded-For` or `X-Real-IP`. `X-Forwarded-For` is walked right-to-left to find the rightmost non-trusted entry; `X-Real-IP` is used as a fallback. Both headers are ignored when the direct peer is not trusted. |
| `host_limit_window` | `1m` | Sliding window over which per-client distinct-hostname DNS lookups are counted. Go duration string. |
| `max_hosts_per_client` | `50` | Maximum distinct hostnames a single client may trigger first-time DNS lookups for within `host_limit_window`. Repeat lookups for a hostname already seen in the window are always free. Exceeding the limit falls back to `default_target` or returns `429`. |
| `max_tracked_clients` | `100000` | Maximum number of per-client tracking entries held in memory. An existing entry is evicted when full, preventing unbounded memory growth under rotating-IP traffic. |

**Response**

| Parameter | Default | Description |
|---|---|---|
| `response_template` | built-in | Custom error page: a file path or inline [Go html/template](https://pkg.go.dev/html/template) string. Resolved at provision time — file content is used when readable; the value is used as a literal template otherwise; any other file error is a hard failure. Template fields: `.Title`, `.Detail`, `.Resolution`. See `examples/error_template.html`. |
| `log_redirects` | `false` | Emit a structured info-level log entry for every request. Successful redirects log as `redirect`; errors as `redirect error` with fields `client`, `method`, `host`, `uri`, `status`, `target` (redirects only), `reason` (errors only). |
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

### Acknowledgements

This module was inspired by [argami/redir-dns](https://github.com/argami/redir-dns), an earlier Caddy module with the same core idea of storing redirects in DNS TXT records.
