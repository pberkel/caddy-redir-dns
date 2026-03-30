# Changelog

## Unreleased

### Added
- `nameserver` configuration parameter accepts one or more custom DNS nameserver addresses (hostname or IP, with optional port). When configured, a `miekg/dns` client is used and the supplied servers are queried in order; the first successful response is returned. NXDOMAIN is treated as terminal and short-circuits any remaining servers. Multiple addresses may be given space-separated on a single line or across multiple `nameserver` lines. Addresses without an explicit port default to `:53`. When `nameserver` is absent the system resolver is used, as before.
- DNS TXT record TTL is now honoured: when the TTL returned by the upstream resolver exceeds the configured `cache_ttl`, the larger value is used as the cache expiry. This prevents entries from being served from cache after the record's natural DNS TTL has elapsed while still respecting `cache_ttl` as a minimum.
- `response_template` configuration parameter allows the built-in HTML error template to be replaced with a custom one. The value may be a file path (read at provision time if the file exists) or an inline Go `html/template` string (used directly when no file is found at the given path). Any file error other than not-found is treated as a hard failure to prevent a misconfigured path from silently falling back to literal interpretation. The template receives `.Title`, `.Detail`, and `.Resolution` fields. Accepts a Caddy global placeholder (e.g. `{env.TEMPLATE_PATH}`).
- `log_redirects` configuration flag enables structured info-level access logging. When set, every request emits a log entry: successful redirects as `redirect` (fields: `client`, `method`, `host`, `uri`, `target`, `status`), error responses as `redirect error` (same fields plus `reason`: `invalid_host`, `rate_limited`, `dns_lookup_failed`, or `no_valid_txt_record`). Disabled by default; no per-request logging occurs unless explicitly enabled.
- `examples/error_template.html` — a dark-themed reference template matching the module's default error page style, suitable for use with `response_template`.

### Changed
- Default `lookup_timeout` increased from `500ms` to `2s` to reduce spurious fallback behaviour on moderately slow resolvers.
- Added doc comments and inline comments throughout `redir_dns.go` and `rate_limiter.go`, covering all previously undocumented functions and types.
- `X-Forwarded-For` header processing now caps input to 1024 bytes (retaining the rightmost portion) to bound per-request CPU cost under adversarial header values.
- `evictOneCacheEntry` merged from two sequential map iterations into one, halving the work when no expired entry is present.
- Cache miss path in `lookupTXT` reduced from two defensive slice copies to one; the stored cache entry now holds the slice returned directly by the lookup function, and callers receive a copy only at read time.
- All debug log calls converted to the zap checked-entry pattern (`logger.Check`) so field allocations are skipped entirely when debug logging is disabled.
- Error responses now include a structured "What happened" detail and "How to resolve" guidance section. Each failure case (invalid host, rate-limited, DNS lookup failure, no valid redirect target) carries a specific explanation and actionable resolution message tailored to that error. The HTML template has been restyled accordingly.

## v1.1.3 — 2026-03-30

### Added
- All configuration parameters now accept Caddy global placeholders (e.g. `{env.VAR_NAME}`) in addition to their literal values. Placeholders are expanded at provision time using `caddy.NewReplacer()`, so environment variables and other Caddy-provided global values can be used to configure any parameter without rebuilding the binary or changing the Caddyfile.

### Changed
- JSON schema for `status_code`, `max_unique_hosts_per_client`, `max_cache_size`, and `max_clients` now accepts both a bare integer (`302`) and a quoted string (`"302"` or `"{env.STATUS_CODE}"`). Bare integers continue to round-trip correctly; no changes to existing JSON configs are required.
- JSON schema for `lookup_timeout`, `cache_ttl`, and `rate_window` is unchanged (these were already quoted duration strings in JSON via `caddy.Duration`). The underlying field type has changed from `caddy.Duration` to `string`; the serialised form is identical.
- Caddyfile parsing of typed fields (durations and integers) is now deferred from `UnmarshalCaddyfile` to `Provision`. Parse errors for these fields are therefore reported at provision time rather than at Caddyfile parse time. The observable behaviour is the same — both prevent Caddy from starting — but the error message may differ slightly in format.

## v1.1.2 — 2026-03-29

### Added
- `X-Real-IP` header is now accepted as a fallback client identifier when the direct peer is a trusted proxy and no usable `X-Forwarded-For` entry is present. This supports nginx and other proxies that set `X-Real-IP` instead of `X-Forwarded-For`.

### Changed
- HTTP redirect status codes are now restricted to an explicit allowlist: `301`, `302`, `303`, `307`, and `308`. Previously all `3xx` codes were accepted, including `300` (Multiple Choices), `304` (Not Modified), `305` (Use Proxy, deprecated), and `306` (Switch Proxy, obsolete).
- `X-Forwarded-For` is now walked right-to-left without allocating a string slice, reducing per-request allocations on trusted-proxy deployments.
- Client identification now fails closed: requests with an unparseable `RemoteAddr` are treated as rate-limited rather than being assigned to a shared `"unknown"` bucket.
- `clientIDFromRequest` is now called inside `isClientHostRateLimited`, ensuring client IP extraction is skipped entirely when rate-limiting is disabled.
- Per-client rate-limit state cleanup (expired host entries and idle client trackers) has been moved from the request path to a background goroutine that runs every `rate_window`. This eliminates an O(clients × hosts) sweep under the rate-limit mutex that previously caused latency spikes at the cleanup boundary.
- Client eviction when the `max_clients` cap is reached is now O(1) (single map iteration) rather than O(n) (full scan for oldest `lastSeen`).
- `isValidDNSHost` now uses `strings.SplitSeq` to avoid a slice allocation per hostname validation.
- `lookupTXT` no longer accepts a `context.Context` parameter. DNS lookups always run on an internal timeout context derived from `context.Background()`, decoupled from any caller context. The function signature now makes this explicit.
- The `singleflight` result type assertion is now non-panicking: a failed assertion returns an empty result, which is treated as a cache miss rather than crashing the server.

### Security
- Private, loopback, and link-local addresses appearing in `X-Forwarded-For` or `X-Real-IP` are now accepted as client identifiers when the direct peer is trusted. Previously they were rejected, causing all clients behind an all-private-network proxy to share the proxy's IP as their rate-limit bucket.

## v1.1.1 — 2026-03-27

### Added
- `max_cache_size` configuration option (default: `10000`) caps the number of in-memory DNS TXT cache entries. When the limit is reached, the entry with the soonest expiry is evicted before inserting the new one, preventing unbounded memory growth under sustained unique-hostname traffic.
- `max_clients` configuration option (default: `100000`) caps the number of per-client rate-limit entries tracked in memory. When the limit is reached, the least-recently-seen client is evicted, preventing unbounded memory growth under rotating-IP attacks.
- `X-Content-Type-Options: nosniff` header is now included on all HTML error responses (404, 429) to prevent MIME-type sniffing by older browsers.

### Changed
- DNS TXT lookups inside `singleflight` now use `context.Background()` with the configured `lookup_timeout` rather than inheriting the first caller's request context. Previously, if the request that won the singleflight race was cancelled mid-flight, all other goroutines waiting on the same query received the cancellation error even if their own contexts were still valid.
- Startup log message moved from `Validate()` to `Provision()`, where the logger is guaranteed to be initialised. Previously, calling `Validate()` independently of `Provision()` would cause a nil pointer dereference on the logger.
- `parseTrustedProxyPrefixes` is no longer called redundantly inside `Validate()`; trusted proxy validation is fully covered by `Provision()`.
- `txtPrefixRegex` promoted to a package-level variable so the regular expression is compiled once at startup rather than on every `Validate()` call.
- HTTP status code `401` is no longer accepted as a valid redirect code. RFC 9110 does not define 401 as a redirect and client behaviour when a `Location` header accompanies a 401 is inconsistent. Allowed values are now strictly `300–399`.
- `lookup_timeout` now has a maximum allowed value of `30s`. Since DNS lookups run on `context.Background()` (decoupled from the request context), an unbounded timeout could cause goroutine accumulation under slow or unresponsive DNS servers.

### Security
- Redirect target URLs are now rejected if they contain any byte outside the printable ASCII range (0x20–0x7E). This covers ASCII C0 control characters (including raw `\r\n` header-injection sequences), DEL (0x7F), and all non-ASCII bytes. Non-ASCII characters in redirect URLs must be properly encoded: Punycode for internationalised hostnames, percent-encoding for path and query components. Previously the module relied implicitly on Go's `net/http` sanitising control characters from header values at write time.
- Redirect target URLs containing credentials (userinfo component) are now rejected by `isValidAbsoluteURL`. This covers username-only (`user@host`), username and password (`user:pass@host`), and password-without-username (`:pass@host`) forms. Redirecting to a credential-bearing URL leaks secrets in browser history and `Referer` headers.

## v1.1.0

### Added
- DNS hardening controls:
  - `lookup_timeout`
  - `cache_ttl`
  - `rate_window`
  - `max_unique_hosts_per_client`
  - `trusted_proxies`
- In-memory DNS TXT cache with TTL and singleflight deduplication.
- Per-client unique-host cardinality limiter.
- Trusted-proxy-aware client identification using `X-Forwarded-For` when the direct peer matches `trusted_proxies`.
- Integration and regression tests for `ServeHTTP`, panic safety, rate limiting, and configuration parsing/validation.
- CI workflow that runs `go test ./...` and `go vet ./...` on pushes and pull requests.

### Changed
- Safer debug logging (removed sensitive request/TXT payload logging and added structured reason codes).
- `CaddyModule()` updated to pointer receiver to avoid lock-copy issues detected by `go vet`.

### Security
- Ran `govulncheck` on March 5, 2026.
- Initial scan reported vulnerabilities in transitive dependencies.
- Dependency upgrade pass completed, including:
  - `github.com/caddyserver/caddy/v2` to `v2.11.1`
  - `github.com/cloudflare/circl` to `v1.6.3`
  - `golang.org/x/crypto` to `v0.48.0`
  - `github.com/slackhq/nebula` to `v1.10.3`
  - `github.com/quic-go/quic-go` to `v0.59.0`
  - `golang.org/x/net` to `v0.51.0`
- Final result: `govulncheck` reports no known vulnerabilities.

## v1.0.0

- Initial release.
