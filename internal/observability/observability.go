package observability

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

func NewLogger(env string) (*zap.Logger, error) {
	if env == "prod" {
		return zap.NewProduction()
	}
	return zap.NewDevelopment()
}

var (
	AuthzTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agentgate_authz_total",
		Help: "Total /authz decisions by outcome.",
	}, []string{"decision"})

	AuthzDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "agentgate_authz_duration_seconds",
		Help:    "Latency of the /authz hot path.",
		Buckets: []float64{0.0005, 0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
	})

	PaymentsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agentgate_payments_total",
		Help: "Payment attempts by outcome.",
	}, []string{"outcome"})

	VerifierDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "agentgate_verifier_duration_seconds",
		Help:    "PaymentVerifier verify/settle latency.",
		Buckets: prometheus.DefBuckets,
	}, []string{"op", "verifier"})

	AnalyticsDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "agentgate_analytics_dropped_total",
		Help: "Analytics events dropped because the buffer was full.",
	})

	DetectTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agentgate_detect_total",
		Help: "Detection verdicts by class.",
	}, []string{"class"})

	BotRangesRefreshTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "agentgate_bot_ranges_refresh_total",
		Help: "Operator IP-range refresh attempts by operator and outcome.",
	}, []string{"operator", "outcome"})

	BotRangesCIDRs = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "agentgate_bot_ranges_cidrs",
		Help: "Current number of CIDR blocks loaded per operator.",
	}, []string{"operator"})

	BotRangesLastSuccess = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "agentgate_bot_ranges_last_success_timestamp_seconds",
		Help: "Unix timestamp of the last successful IP-range refresh per operator.",
	}, []string{"operator"})
)

func MustRegister(r prometheus.Registerer) {
	r.MustRegister(AuthzTotal, AuthzDuration, PaymentsTotal, VerifierDuration, AnalyticsDropped, DetectTotal,
		BotRangesRefreshTotal, BotRangesCIDRs, BotRangesLastSuccess)
}

func Handler() http.Handler { return promhttp.Handler() }
