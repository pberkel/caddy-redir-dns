package redirdns

import (
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// rdMetrics holds the Prometheus collectors registered for the redir_dns module.
// A single set of collectors is shared across all redir_dns instances (http and https)
// because Caddy provisions each block independently but both write to the same registry.
// Duplicate registration is resolved via the AlreadyRegisteredError pattern so that
// the second instance reuses the collectors registered by the first.
type rdMetrics struct {
	redirectsTotal    *prometheus.CounterVec
	errorsTotal       *prometheus.CounterVec
	cacheLookupsTotal *prometheus.CounterVec
	requestDuration   prometheus.Histogram
}

// initMetrics registers (or reuses) the redir_dns Prometheus collectors on registry.
// Called once per redir_dns instance during Provision; both instances share the same
// collectors because the AlreadyRegisteredError pattern returns the existing collector
// on duplicate registration.
func initMetrics(registry *prometheus.Registry) *rdMetrics {
	return &rdMetrics{
		redirectsTotal: registerOrReuse(registry, prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "caddy",
				Subsystem: "redir_dns",
				Name:      "redirects_total",
				Help:      "Total number of redirect responses issued, by HTTP status code.",
			},
			[]string{"code"},
		)),
		errorsTotal: registerOrReuse(registry, prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "caddy",
				Subsystem: "redir_dns",
				Name:      "errors_total",
				Help:      "Total number of error responses issued, by reason (invalid_host, rate_limited, dns_lookup_failed, no_valid_txt_record).",
			},
			[]string{"reason"},
		)),
		cacheLookupsTotal: registerOrReuse(registry, prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "caddy",
				Subsystem: "redir_dns",
				Name:      "cache_lookups_total",
				Help:      "Total number of DNS TXT cache lookup outcomes, by status (miss, hit, stale).",
			},
			[]string{"status"},
		)),
		requestDuration: registerOrReuse(registry, prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: "caddy",
				Subsystem: "redir_dns",
				Name:      "request_duration_seconds",
				Help:      "Duration of redir_dns handler processing in seconds.",
				Buckets:   prometheus.DefBuckets,
			},
		)),
	}
}

// recordRedirect increments redirects_total for the given HTTP status code.
func (m *rdMetrics) recordRedirect(code int) {
	m.redirectsTotal.With(prometheus.Labels{"code": strconv.Itoa(code)}).Inc()
}

// recordError increments errors_total for the given reason label.
func (m *rdMetrics) recordError(reason string) {
	m.errorsTotal.With(prometheus.Labels{"reason": reason}).Inc()
}

// recordCacheLookup increments cache_lookups_total for the given cache outcome.
func (m *rdMetrics) recordCacheLookup(status cacheStatus) {
	var s string
	switch status {
	case cacheHit:
		s = "hit"
	case cacheStale:
		s = "stale"
	default:
		s = "miss"
	}
	m.cacheLookupsTotal.With(prometheus.Labels{"status": s}).Inc()
}

// startTimer returns a Prometheus timer that observes into requestDuration on ObserveDuration.
func (m *rdMetrics) startTimer() *prometheus.Timer {
	return prometheus.NewTimer(m.requestDuration)
}

// registerOrReuse registers c on registry and returns c. If c is already registered
// (AlreadyRegisteredError), the existing collector is returned so both redir_dns
// instances share the same counters. Any other registration error causes a panic.
func registerOrReuse[C prometheus.Collector](registry *prometheus.Registry, c C) C {
	if err := registry.Register(c); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			existing, ok := are.ExistingCollector.(C)
			if !ok {
				panic(fmt.Sprintf("caddy-redir-dns: existing collector has unexpected type %T, want %T", are.ExistingCollector, c))
			}
			return existing
		}
		panic(fmt.Sprintf("caddy-redir-dns: failed to register metric collector: %v", err))
	}
	return c
}
