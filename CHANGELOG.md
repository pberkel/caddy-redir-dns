# Changelog

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
