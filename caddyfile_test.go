package redirdns

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfileParsesLookupTimeoutAndCacheTTL(t *testing.T) {
	t.Parallel()

	rd := New()
	d := caddyfile.NewTestDispenser(`
redir_dns {
	lookup_timeout 750ms
	cache_ttl 45s
	host_limit_window 90s
	max_hosts_per_client 77
	trusted_proxies 10.0.0.0/8 192.168.0.0/16
}
`)

	if err := rd.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if rd.LookupTimeout != "750ms" {
		t.Fatalf("lookup timeout = %q, want %q", rd.LookupTimeout, "750ms")
	}
	if rd.CacheTTL != "45s" {
		t.Fatalf("cache ttl = %q, want %q", rd.CacheTTL, "45s")
	}
	if rd.HostLimitWindow != "90s" {
		t.Fatalf("host limit window = %q, want %q", rd.HostLimitWindow, "90s")
	}
	if rd.MaxHostsPerClient != "77" {
		t.Fatalf("max hosts per client = %q, want %q", rd.MaxHostsPerClient, "77")
	}
	if len(rd.TrustedProxies) != 2 {
		t.Fatalf("trusted proxies length = %d, want %d", len(rd.TrustedProxies), 2)
	}
	if rd.TrustedProxies[0] != "10.0.0.0/8" || rd.TrustedProxies[1] != "192.168.0.0/16" {
		t.Fatalf("unexpected trusted proxies: %#v", rd.TrustedProxies)
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
