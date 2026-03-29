package redirdns

import (
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestUnmarshalCaddyfileParsesLookupTimeoutAndCacheTTL(t *testing.T) {
	t.Parallel()

	rd := New()
	d := caddyfile.NewTestDispenser(`
redir_dns {
	lookup_timeout 750ms
	cache_ttl 45s
	rate_window 90s
	max_unique_hosts_per_client 77
	trusted_proxies 10.0.0.0/8 192.168.0.0/16
}
`)

	if err := rd.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile returned error: %v", err)
	}
	if time.Duration(rd.LookupTimeout) != 750*time.Millisecond {
		t.Fatalf("lookup timeout = %v, want %v", time.Duration(rd.LookupTimeout), 750*time.Millisecond)
	}
	if time.Duration(rd.CacheTTL) != 45*time.Second {
		t.Fatalf("cache ttl = %v, want %v", time.Duration(rd.CacheTTL), 45*time.Second)
	}
	if time.Duration(rd.RateWindow) != 90*time.Second {
		t.Fatalf("rate window = %v, want %v", time.Duration(rd.RateWindow), 90*time.Second)
	}
	if rd.MaxUniqueHostsPerClient != 77 {
		t.Fatalf("max unique hosts per client = %d, want %d", rd.MaxUniqueHostsPerClient, 77)
	}
	if len(rd.TrustedProxies) != 2 {
		t.Fatalf("trusted proxies length = %d, want %d", len(rd.TrustedProxies), 2)
	}
	if rd.TrustedProxies[0] != "10.0.0.0/8" || rd.TrustedProxies[1] != "192.168.0.0/16" {
		t.Fatalf("unexpected trusted proxies: %#v", rd.TrustedProxies)
	}
}
