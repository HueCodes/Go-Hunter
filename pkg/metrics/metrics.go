package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "gohunter",
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds.",
			Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		[]string{"method", "route", "status"},
	)

	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gohunter",
			Name:      "http_requests_total",
			Help:      "Total number of HTTP requests.",
		},
		[]string{"method", "route", "status"},
	)

	ActiveScans = promauto.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "gohunter",
			Name:      "active_scans",
			Help:      "Number of currently active scans.",
		},
	)

	AssetsDiscovered = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gohunter",
			Name:      "assets_discovered_total",
			Help:      "Total number of assets discovered.",
		},
		[]string{"provider"},
	)

	FindingsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: "gohunter",
			Name:      "findings_total",
			Help:      "Total number of findings discovered.",
		},
		[]string{"severity"},
	)

	ScanDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "gohunter",
			Name:      "scan_duration_seconds",
			Help:      "Scan duration in seconds.",
			Buckets:   []float64{1, 5, 10, 30, 60, 120, 300, 600},
		},
		[]string{"type"},
	)

	QueueDepth = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "gohunter",
			Name:      "queue_depth",
			Help:      "Number of tasks in the queue.",
		},
		[]string{"queue"},
	)

	DatabaseQueryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: "gohunter",
			Name:      "database_query_duration_seconds",
			Help:      "Database query duration in seconds.",
			Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		},
		[]string{"operation"},
	)
)
