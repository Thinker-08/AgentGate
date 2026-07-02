package server

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/mihiragrawal/agentgate/internal/analytics"
	"github.com/mihiragrawal/agentgate/internal/config"
	"github.com/mihiragrawal/agentgate/internal/detector"
	"github.com/mihiragrawal/agentgate/internal/observability"
	"github.com/mihiragrawal/agentgate/internal/payment"
	"github.com/mihiragrawal/agentgate/internal/policy"
	"github.com/mihiragrawal/agentgate/internal/store"
	"github.com/mihiragrawal/agentgate/internal/token"
)

type Deps struct {
	Cfg       *config.Config
	Log       *zap.Logger
	Detector  detector.Detector
	Policy    policy.PolicyEngine
	Verifier  payment.PaymentVerifier
	Issuer    token.TokenIssuer
	Store     store.Store
	Replay    store.ReplayStore
	Deny      store.DenyList
	Rate      store.RateLimiter
	Counter   store.Counter
	Analytics analytics.AnalyticsSink
}

type Server struct {
	Deps
}

func New(d Deps) *Server { return &Server{Deps: d} }

func (s *Server) PublicHandler() http.Handler {
	r := chi.NewRouter()
	r.Use(recoverer(s.Log))
	r.Use(accessLog(s.Log))
	r.Use(s.requireEdge)

	r.With(timeout(s.Cfg.AuthTimeout)).Post("/authz", s.handleAuthz)
	r.With(timeout(s.Cfg.AuthTimeout)).Get("/challenge", s.handleChallenge)
	r.Post("/verify", s.handleVerify)
	return r
}

func (s *Server) AdminHandler() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/readyz", s.handleReady)
	r.Handle("/metrics", observability.Handler())
	return r
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Store.Ping(ctx); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "not_ready", "store unavailable")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
