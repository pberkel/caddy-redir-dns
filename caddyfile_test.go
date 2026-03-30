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
	unique_host_window 90s
	max_unique_hosts_per_client 77
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
	if rd.UniqueHostWindow != "90s" {
		t.Fatalf("unique host window = %q, want %q", rd.UniqueHostWindow, "90s")
	}
	if rd.MaxUniqueHostsPerClient != "77" {
		t.Fatalf("max unique hosts per client = %q, want %q", rd.MaxUniqueHostsPerClient, "77")
	}
	if len(rd.TrustedProxies) != 2 {
		t.Fatalf("trusted proxies length = %d, want %d", len(rd.TrustedProxies), 2)
	}
	if rd.TrustedProxies[0] != "10.0.0.0/8" || rd.TrustedProxies[1] != "192.168.0.0/16" {
		t.Fatalf("unexpected trusted proxies: %#v", rd.TrustedProxies)
	}
}
