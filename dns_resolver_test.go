package redirdns

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

	rd.cacheMu.RLock()
	cacheLen := len(rd.cache)
	rd.cacheMu.RUnlock()

	if cacheLen > maxSize {
		t.Fatalf("cache size = %d, want <= %d", cacheLen, maxSize)
	}
}
