# Changelog

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
