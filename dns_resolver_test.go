package redirdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.uber.org/zap"
)

func TestLookupTXTCachesSuccessAndError(t *testing.T) {
	t.Parallel()

	rd := New()
	rd.lookupTTL = time.Minute
	var calls atomic.Int64
	rd.lookupFunc = func(ctx context.Context, query string) ([]string, time.Duration, error) {
		_ = ctx
		_ = query
		n := calls.Add(1)
		if n == 1 {
			return []string{"https://example.com"}, 0, nil
		}
		return nil, 0, errors.New("unexpected second call for cached success")
	}

	txt, err, cached := rd.lookupTXT("_redirdns.example.com")
	if err != nil {
		t.Fatalf("unexpected error on first lookup: %v", err)
	}
	if len(txt) != 1 || txt[0] != "https://example.com" {
		t.Fatalf("unexpected TXT result: %#v", txt)
	}
	if cached {
		t.Fatal("first lookup should not be a cache hit")
	}
	txt, err, cached = rd.lookupTXT("_redirdns.example.com")
	if err != nil {
		t.Fatalf("unexpected error on cached lookup: %v", err)
	}
	if len(txt) != 1 || txt[0] != "https://example.com" {
		t.Fatalf("unexpected cached TXT result: %#v", txt)
	}
	if !cached {
		t.Fatal("second lookup should be a cache hit")
	}
	if calls.Load() != 1 {
		t.Fatalf("lookup function called %d times, want 1", calls.Load())
	}

	rdErr := New()
	rdErr.lookupTTL = time.Minute
	var errCalls atomic.Int64
	rdErr.lookupFunc = func(ctx context.Context, query string) ([]string, time.Duration, error) {
		_ = ctx
		_ = query
		errCalls.Add(1)
		return nil, 0, errNoTXTRecord
	}

	_, err, _ = rdErr.lookupTXT("_redirdns.missing.example.com")
	if !errors.Is(err, errNoTXTRecord) {
		t.Fatalf("expected errNoTXTRecord, got %v", err)
	}
	_, err, _ = rdErr.lookupTXT("_redirdns.missing.example.com")
	if !errors.Is(err, errNoTXTRecord) {
		t.Fatalf("expected cached errNoTXTRecord, got %v", err)
	}
	if errCalls.Load() != 1 {
		t.Fatalf("error lookup function called %d times, want 1", errCalls.Load())
	}
}

func TestLookupTXTSingleflightDedupesConcurrentCalls(t *testing.T) {
	t.Parallel()

	rd := New()
	rd.lookupTTL = time.Minute
	rd.lookupMax = time.Second

	var calls atomic.Int64
	rd.lookupFunc = func(ctx context.Context, query string) ([]string, time.Duration, error) {
		_ = query
		calls.Add(1)
		select {
		case <-time.After(50 * time.Millisecond):
			return []string{"https://example.org"}, 0, nil
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		}
	}

	const workers = 20
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			txt, err, _ := rd.lookupTXT("_redirdns.concurrent.example.com")
			if err != nil {
				results <- err
				return
			}
			if len(txt) != 1 || txt[0] != "https://example.org" {
				results <- errors.New("unexpected TXT response")
				return
			}
			results <- nil
		}()
	}
	wg.Wait()
	close(results)

	for err := range results {
		if err != nil {
			t.Fatalf("concurrent lookup failed: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("lookup function called %d times, want 1", calls.Load())
	}
}

// startTestDNSServer starts a local UDP DNS server using mux and returns its
// address. The server is shut down automatically when the test ends.
func startTestDNSServer(t *testing.T, mux *dns.ServeMux) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Net: "udp", Handler: mux}
	go srv.ActivateAndServe()            //nolint:errcheck
	t.Cleanup(func() { srv.Shutdown() }) //nolint:errcheck
	return pc.LocalAddr().String()
}

func TestMiekgLookupTXTDirect(t *testing.T) {
	t.Parallel()

	mux := dns.NewServeMux()
	mux.HandleFunc("_redirect.www.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{Name: "_redirect.www.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{"https://www.new-domain.com"},
			},
		}
		w.WriteMsg(m) //nolint:errcheck
	})
	addr := startTestDNSServer(t, mux)

	lookupFunc := newMiekgLookupFunc([]string{addr}, zap.NewNop())
	records, ttl, err := lookupFunc(context.Background(), "_redirect.www.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 || records[0] != "https://www.new-domain.com" {
		t.Fatalf("unexpected records: %v", records)
	}
	if ttl != 60*time.Second {
		t.Fatalf("unexpected TTL: %v, want 60s", ttl)
	}
}

func TestMiekgLookupTXTFollowsCNAME(t *testing.T) {
	t.Parallel()

	// Simulates a non-recursive resolver that returns only the CNAME record for
	// the queried name rather than resolving it to the final TXT answer. The
	// lookup function must follow the CNAME with an explicit second query.
	mux := dns.NewServeMux()
	mux.HandleFunc("_redirect.www.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "_redirect.www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30},
				Target: "redirector.example.net.",
			},
		}
		w.WriteMsg(m) //nolint:errcheck
	})
	mux.HandleFunc("redirector.example.net.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{Name: "redirector.example.net.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120},
				Txt: []string{"https://www.new-domain.com"},
			},
		}
		w.WriteMsg(m) //nolint:errcheck
	})
	addr := startTestDNSServer(t, mux)

	lookupFunc := newMiekgLookupFunc([]string{addr}, zap.NewNop())
	records, ttl, err := lookupFunc(context.Background(), "_redirect.www.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 || records[0] != "https://www.new-domain.com" {
		t.Fatalf("unexpected records: %v", records)
	}
	if ttl != 120*time.Second {
		t.Fatalf("unexpected TTL: %v, want 120s", ttl)
	}
}

func TestMiekgLookupTXTFollowsCNAMEChain(t *testing.T) {
	t.Parallel()

	// Two-hop CNAME chain: queried → intermediate → final TXT.
	mux := dns.NewServeMux()
	mux.HandleFunc("_redirect.www.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "_redirect.www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30},
				Target: "intermediate.example.net.",
			},
		}
		w.WriteMsg(m) //nolint:errcheck
	})
	mux.HandleFunc("intermediate.example.net.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "intermediate.example.net.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "redirector.example.net.",
			},
		}
		w.WriteMsg(m) //nolint:errcheck
	})
	mux.HandleFunc("redirector.example.net.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{Name: "redirector.example.net.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 90},
				Txt: []string{"https://www.new-domain.com"},
			},
		}
		w.WriteMsg(m) //nolint:errcheck
	})
	addr := startTestDNSServer(t, mux)

	lookupFunc := newMiekgLookupFunc([]string{addr}, zap.NewNop())
	records, _, err := lookupFunc(context.Background(), "_redirect.www.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 || records[0] != "https://www.new-domain.com" {
		t.Fatalf("unexpected records: %v", records)
	}
}

func TestMiekgLookupTXTCNAMEAndTXTInSingleResponse(t *testing.T) {
	t.Parallel()

	// Simulates a recursive resolver that returns both the CNAME and the final
	// TXT records in a single response. The lookup function should use the TXT
	// records from the answer directly without issuing a follow-up query.
	mux := dns.NewServeMux()
	mux.HandleFunc("_redirect.www.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "_redirect.www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30},
				Target: "redirector.example.net.",
			},
			&dns.TXT{
				Hdr: dns.RR_Header{Name: "redirector.example.net.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120},
				Txt: []string{"https://www.new-domain.com"},
			},
		}
		w.WriteMsg(m) //nolint:errcheck
	})
	addr := startTestDNSServer(t, mux)

	lookupFunc := newMiekgLookupFunc([]string{addr}, zap.NewNop())
	records, ttl, err := lookupFunc(context.Background(), "_redirect.www.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 || records[0] != "https://www.new-domain.com" {
		t.Fatalf("unexpected records: %v", records)
	}
	if ttl != 120*time.Second {
		t.Fatalf("unexpected TTL: %v, want 120s", ttl)
	}
}

func TestMiekgLookupTXTNXDOMAIN(t *testing.T) {
	t.Parallel()

	mux := dns.NewServeMux()
	mux.HandleFunc("_redirect.missing.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeNameError
		w.WriteMsg(m) //nolint:errcheck
	})
	addr := startTestDNSServer(t, mux)

	lookupFunc := newMiekgLookupFunc([]string{addr}, zap.NewNop())
	_, _, err := lookupFunc(context.Background(), "_redirect.missing.example.com")
	if !errors.Is(err, errNoTXTRecord) {
		t.Fatalf("expected errNoTXTRecord, got %v", err)
	}
}

func TestMiekgLookupTXTCNAMELoopExceedsMaxDepth(t *testing.T) {
	t.Parallel()

	// Every query returns a CNAME pointing back to itself, creating an infinite
	// loop. The lookup function must give up after maxCNAMEDepth hops.
	mux := dns.NewServeMux()
	mux.HandleFunc("loop.example.com.", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "loop.example.com.",
			},
		}
		w.WriteMsg(m) //nolint:errcheck
	})
	addr := startTestDNSServer(t, mux)

	lookupFunc := newMiekgLookupFunc([]string{addr}, zap.NewNop())
	_, _, err := lookupFunc(context.Background(), "loop.example.com")
	if err == nil {
		t.Fatal("expected error for CNAME loop, got nil")
	}
}

func TestLookupTXTRespectsMaxCacheSize(t *testing.T) {
	t.Parallel()

	const maxSize = 3
	rd := New()
	rd.lookupTTL = time.Hour
	rd.maxCacheSize = maxSize
	rd.lookupFunc = func(ctx context.Context, query string) ([]string, time.Duration, error) {
		return []string{"https://example.com"}, 0, nil
	}

	queries := []string{
		"_redirdns.one.example.com",
		"_redirdns.two.example.com",
		"_redirdns.three.example.com",
		"_redirdns.four.example.com",
		"_redirdns.five.example.com",
	}
	for _, q := range queries {
		if _, err, _ := rd.lookupTXT(q); err != nil {
			t.Fatalf("lookupTXT(%q) returned error: %v", q, err)
		}
	}

	rd.dnsCache.mu.RLock()
	cacheLen := len(rd.dnsCache.entries)
	rd.dnsCache.mu.RUnlock()

	if cacheLen > maxSize {
		t.Fatalf("cache size = %d, want <= %d", cacheLen, maxSize)
	}
}

func TestClassifyLookupError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		err  error
		want string
	}{
		{nil, "none"},
		{context.DeadlineExceeded, "timeout"},
		{errNoTXTRecord, "not_found"},
		{&net.DNSError{IsNotFound: true}, "nxdomain"},
		{&net.DNSError{IsTimeout: true}, "timeout"},
		{&net.DNSError{IsTemporary: true}, "temporary_dns_error"},
		{&net.DNSError{}, "dns_error"},
		{fmt.Errorf("some other error"), "lookup_error"},
	}
	for _, tt := range tests {
		got := classifyLookupError(tt.err)
		if got != tt.want {
			t.Errorf("classifyLookupError(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}

func TestParseIPFromAddrPortOrLiteral(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
		ok    bool
	}{
		{"203.0.113.1", "203.0.113.1", true},
		{"2001:db8::1", "2001:db8::1", true},
		{"203.0.113.1:8080", "203.0.113.1", true},
		{"[2001:db8::1]:443", "2001:db8::1", true},
		{"", "", false},
		{"not-an-ip", "", false},
		{"not-an-ip:port", "", false},
	}
	for _, tt := range tests {
		addr, ok := parseIPFromAddrPortOrLiteral(tt.input)
		if ok != tt.ok {
			t.Errorf("parseIPFromAddrPortOrLiteral(%q) ok = %v, want %v", tt.input, ok, tt.ok)
			continue
		}
		if ok && addr.String() != tt.want {
			t.Errorf("parseIPFromAddrPortOrLiteral(%q) = %q, want %q", tt.input, addr.String(), tt.want)
		}
	}
}
