# HTTP redirect module for Caddy Server 2

This is a comprehensive rewrite of the [argami/redir-dns](https://github.com/argami/redir-dns) module providing HTTP redirect functionality configured with TXT DNS records.  This allows domain owners manage host-level redirects entirely within DNS without requiring any changes to the Caddy Server configuration.  This module fixes a number of bugs in present in [argami/redir-dns](https://github.com/argami/redir-dns) and implements additional dynamic placeholder substitution functionality.

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
		default_target              https://www.example.com
		status_code                 temporary
		dns_prefix                  _redirdns

		resolvers                   1.1.1.1 8.8.8.8
		lookup_timeout              2s
		cache_ttl                   30s
		max_cache_size              10000

		trusted_proxies    10.0.0.0/8 192.168.0.0/16
		host_limit_window  1m
		max_hosts_per_client 50
		max_tracked_clients  100000

		response_template           /etc/caddy/error.html
		log_redirects
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

* __default_target__ specifies a redirect URL that will be used if the module is unable to determine an appropriate redirect location (i.e. the hostname is an IP address, the TXT record doesn't exist or is invalid).  If this parameter is not set and an error occurs during redirect processing, a simple 404 response will be returned.
* __status_code__ specifies the HTTP redirect status to use. Accepts a numeric code (`301`, `302`, `303`, `307`, `308`) or one of three keywords:
  * `temporary` — `302` for `GET`/`HEAD`, `307` for all other methods (default).
  * `permanent` — `301` for `GET`/`HEAD`, `308` for all other methods.
  * `html` — `200 OK` with an HTML body containing a `<meta http-equiv="refresh">` and a JavaScript `window.location.replace()` redirect. Browsers follow the redirect transparently; API clients that inspect the HTTP status code or `Content-Type` receive a `200` with an HTML document rather than a `3xx` redirect.

  Keywords are preferred over numeric codes because `temporary` and `permanent` automatically select the method-preserving code (`307`/`308`) for non-`GET` requests, preserving the request body without any additional configuration. Numeric codes always emit that exact code regardless of request method.
* __dns_prefix__ specifies the prefix used to construct the TXT DNS record name where redirect information for a given host is stored in the format `<dns_prefix>.<host>`.  Default value: `"_redirdns"`.

**DNS lookup**

* __resolvers__ specifies one or more custom DNS resolvers to use for TXT record lookups. Each value is a hostname or IP address with an optional port (e.g. `1.1.1.1`, `8.8.8.8:53`, `dns.example.com:5353`). Multiple addresses may be given space-separated on a single line or across multiple `resolvers` lines; they are tried in order and port `53` is assumed when no port is specified. When this parameter is absent the system resolver is used.
* __lookup_timeout__ specifies the maximum time to wait for each DNS TXT lookup before applying fallback behavior.  Duration format must be valid for Go's `time.ParseDuration` (for example `500ms`, `2s`).  Default value: `2s`.
* __cache_ttl__ specifies the minimum time that successful or failed DNS TXT lookup results are cached in memory. When the TXT record's own DNS TTL exceeds this value the record TTL is used instead, so entries are never served from cache longer than the upstream resolver intended.  Duration format must be valid for Go's `time.ParseDuration` (for example `30s`, `2m`).  Default value: `30s`.
* __max_cache_size__ specifies the maximum number of DNS TXT lookup results held in the in-memory cache. When the limit is reached, the entry with the soonest expiry is evicted before inserting a new one.  Default value: `10000`.

**DNS lookup guard**

* __trusted_proxies__ specifies CIDRs or IP addresses that are allowed to provide the client IP via the `X-Forwarded-For` or `X-Real-IP` request headers.  `X-Forwarded-For` is checked first (walking right-to-left to find the rightmost non-trusted entry); `X-Real-IP` is used as a fallback (set by nginx and some other proxies).  If the direct peer is not trusted, both headers are ignored and the remote peer address is used instead.
* __host_limit_window__ specifies the per-client sliding window used to track how many distinct hostnames a client has triggered first-time DNS lookups for.  Duration format must be valid for Go's `time.ParseDuration` (for example `1m`, `30s`).  Default value: `1m`.
* __max_hosts_per_client__ specifies how many distinct hostnames a single client may trigger first-time DNS lookups for within `host_limit_window`.  Repeat lookups for a hostname already seen within the window are always allowed and do not consume an additional slot.  When the limit is exceeded, requests fall back to `default_target` if configured; otherwise a `429 Too Many Requests` response is returned.  Default value: `50`.
* __max_tracked_clients__ specifies the maximum number of per-client host-tracking entries held in memory. When the limit is reached, an existing entry is evicted to make room, preventing unbounded memory growth under rotating-IP traffic.  Default value: `100000`.

**Response**

* __response_template__ overrides the built-in HTML error page with a custom [Go html/template](https://pkg.go.dev/html/template). The value is resolved at provision time as follows: if the value refers to a readable file that path, the file content is used as the template; if no file exists at that path, the value itself is used as an inline template string; any other file error (e.g. permission denied) is treated as a hard failure. The template has access to three fields: `.Title` (short error label), `.Detail` (what went wrong), and `.Resolution` (how to fix it). Accepts a Caddy global placeholder (e.g. `{env.TEMPLATE_PATH}`). See `examples/error_template.html` for a reference implementation.
* __log_redirects__ enables structured info-level logging of every request handled by the module. When enabled, successful redirects are logged with message `redirect` and error responses with message `redirect error`. Each entry includes the fields `client` (IP address), `method`, `host`, `uri`, `status`, `target` (redirects only), and `reason` (errors only). Logging is disabled by default.

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
