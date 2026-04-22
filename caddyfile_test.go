package redirdns

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfileParsesLookupTimeoutAndMinCacheTTL(t *testing.T) {
	t.Parallel()

	rd := New()
	d := caddyfile.NewTestDispenser(`
redir_dns {
	lookup_timeout 750ms
	min_cache_ttl 45s
	per_client_rate_limit 77 90s
	trusted_proxies 10.0.0.0/8 192.168.0.0/16
}
`)

	if err := rd.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if rd.LookupTimeout != "750ms" {
		t.Fatalf("lookup timeout = %q, want %q", rd.LookupTimeout, "750ms")
	}
	if rd.MinCacheTTL != "45s" {
		t.Fatalf("min_cache_ttl = %q, want %q", rd.MinCacheTTL, "45s")
	}
	if rd.PerClientRateLimit == nil {
		t.Fatal("per_client_rate_limit should not be nil")
	}
	if rd.PerClientRateLimit.Duration != "90s" {
		t.Fatalf("per_client_rate_limit duration = %q, want %q", rd.PerClientRateLimit.Duration, "90s")
	}
	if rd.PerClientRateLimit.Limit != "77" {
		t.Fatalf("per_client_rate_limit limit = %q, want %q", rd.PerClientRateLimit.Limit, "77")
	}
	if len(rd.TrustedProxies) != 2 {
		t.Fatalf("trusted proxies length = %d, want %d", len(rd.TrustedProxies), 2)
	}
	if rd.TrustedProxies[0] != "10.0.0.0/8" || rd.TrustedProxies[1] != "192.168.0.0/16" {
		t.Fatalf("unexpected trusted proxies: %#v", rd.TrustedProxies)
	}
}

func TestUnmarshalCaddyfileMaxCacheTTL(t *testing.T) {
	t.Parallel()

	rd := New()
	d := caddyfile.NewTestDispenser(`
redir_dns {
	min_cache_ttl 30s
	max_cache_ttl 2h
}
`)
	if err := rd.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if rd.MinCacheTTL != "30s" {
		t.Fatalf("min_cache_ttl = %q, want %q", rd.MinCacheTTL, "30s")
	}
	if rd.MaxCacheTTL != "2h" {
		t.Fatalf("max_cache_ttl = %q, want %q", rd.MaxCacheTTL, "2h")
	}
}

func TestUnmarshalCaddyfileStaleCacheTTL(t *testing.T) {
	t.Parallel()

	rd := New()
	d := caddyfile.NewTestDispenser(`
redir_dns {
	stale_cache_ttl 60s
}
`)
	if err := rd.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if rd.StaleCacheTTL != "60s" {
		t.Fatalf("stale_cache_ttl = %q, want %q", rd.StaleCacheTTL, "60s")
	}
}

func TestUnmarshalCaddyfileCache(t *testing.T) {
	t.Parallel()

	rd := New()
	d := caddyfile.NewTestDispenser(`
redir_dns {
	cache true
}
`)
	if err := rd.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if !rd.Cache {
		t.Fatal("cache = false, want true")
	}
}

func TestUnmarshalCaddyfileRateLimit(t *testing.T) {
	t.Parallel()

	rd := New()
	d := caddyfile.NewTestDispenser(`
redir_dns {
	rate_limit true
	ipv6_prefix_length 48
}
`)
	if err := rd.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if !rd.RateLimit {
		t.Fatal("rate_limit = false, want true")
	}
	if rd.IPv6PrefixLength != "48" {
		t.Fatalf("ipv6_prefix_length = %q, want %q", rd.IPv6PrefixLength, "48")
	}
}

func TestUnmarshalCaddyfileRateLimitBypass(t *testing.T) {
	t.Parallel()

	rd := New()
	d := caddyfile.NewTestDispenser(`
redir_dns {
	rate_limit_bypass 10.0.0.0/8 172.16.0.0/12
}
`)
	if err := rd.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if len(rd.RateLimitBypass) != 2 {
		t.Fatalf("rate_limit_bypass length = %d, want 2", len(rd.RateLimitBypass))
	}
	if rd.RateLimitBypass[0] != "10.0.0.0/8" || rd.RateLimitBypass[1] != "172.16.0.0/12" {
		t.Fatalf("unexpected rate_limit_bypass: %#v", rd.RateLimitBypass)
	}
}
