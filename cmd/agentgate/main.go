package main

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"

	"github.com/mihiragrawal/agentgate/internal/analytics"
	"github.com/mihiragrawal/agentgate/internal/config"
	"github.com/mihiragrawal/agentgate/internal/core"
	"github.com/mihiragrawal/agentgate/internal/detector"
	"github.com/mihiragrawal/agentgate/internal/observability"
	"github.com/mihiragrawal/agentgate/internal/payment"
	"github.com/mihiragrawal/agentgate/internal/policy"
	"github.com/mihiragrawal/agentgate/internal/server"
	"github.com/mihiragrawal/agentgate/internal/store"
	"github.com/mihiragrawal/agentgate/internal/token"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err)
	}
	log, err := observability.NewLogger(cfg.Env)
	if err != nil {
		panic(err)
	}
	defer func() { _ = log.Sync() }()

	observability.MustRegister(prometheus.DefaultRegisterer)

	if err := run(cfg, log); err != nil {
		log.Fatal("fatal", zap.Error(err))
	}
}

func run(cfg *config.Config, log *zap.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	initCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pg, err := store.NewPostgres(initCtx, cfg.PostgresDSN)
	if err != nil {
		return err
	}
	defer pg.Close()

	rd, err := store.NewRedis(initCtx, cfg.RedisAddr, cfg.RedisPassword)
	if err != nil {
		return err
	}
	defer func() { _ = rd.Close() }()

	pol := policy.New(pg, core.ActionAllow)
	if err := pol.Reload(initCtx); err != nil {
		return err
	}

	var verifier payment.PaymentVerifier
	if cfg.Verifier == "x402" {
		verifier = payment.NewX402(cfg.FacilitatorURL, 10*time.Second)
	} else {
		verifier = payment.NewMock()
	}

	issuer, err := token.New(cfg.JWTSeedHex)
	if err != nil {
		return err
	}

	ranges := detector.NewIPRanges()
	if cfg.BotRangesFile != "" {
		if err := ranges.LoadFile(cfg.BotRangesFile); err != nil {
			log.Warn("could not load bot ranges file", zap.String("file", cfg.BotRangesFile), zap.Error(err))
		}
	}
	if cfg.BotRefreshInterval > 0 {
		sources := detector.DefaultSources()
		if cfg.BotSourcesFile != "" {
			if s, err := detector.LoadSources(cfg.BotSourcesFile); err != nil {
				log.Warn("could not load bot sources file", zap.String("file", cfg.BotSourcesFile), zap.Error(err))
			} else {
				sources = s
			}
		}
		var unsourced []string
		for _, op := range detector.VerifiableOperators() {
			if _, ok := sources[op]; !ok {
				unsourced = append(unsourced, op)
			}
		}
		if len(unsourced) > 0 {
			log.Warn("verifiable operators have no refresh source; they will use the static seed only",
				zap.Strings("operators", unsourced))
		}
		detector.NewRefresher(ranges, sources, cfg.BotRefreshInterval, log).Start(ctx)
		log.Info("bot range refresher started", zap.Duration("interval", cfg.BotRefreshInterval), zap.Int("operators", len(sources)))
	}
	freq := func(fctx context.Context, key string) int {
		n, err := rd.Incr(fctx, "freq:"+key, time.Minute)
		if err != nil {
			return 0
		}
		return int(n)
	}
	det := detector.New(detector.WithRanges(ranges), detector.WithFrequency(freq, 600))

	sink := analytics.New(pg, log, 10000, 100, 2*time.Second)
	sink.Start()
	defer sink.Stop()

	srv := server.New(server.Deps{
		Cfg:       cfg,
		Log:       log,
		Detector:  det,
		Policy:    pol,
		Verifier:  verifier,
		Issuer:    issuer,
		Store:     pg,
		Replay:    rd,
		Deny:      rd,
		Rate:      rd,
		Counter:   rd,
		Analytics: sink,
	})

	public := &http.Server{Addr: cfg.HTTPAddr, Handler: srv.PublicHandler(), ReadHeaderTimeout: 5 * time.Second}
	admin := &http.Server{Addr: cfg.AdminAddr, Handler: srv.AdminHandler(), ReadHeaderTimeout: 5 * time.Second}

	errCh := make(chan error, 2)
	go func() {
		log.Info("public listener", zap.String("addr", cfg.HTTPAddr), zap.String("verifier", verifier.Name()), zap.Bool("enforce", cfg.Enforce))
		if err := public.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		log.Info("admin listener", zap.String("addr", cfg.AdminAddr))
		if err := admin.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		log.Error("listener error", zap.Error(err))
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = public.Shutdown(shutdownCtx)
	_ = admin.Shutdown(shutdownCtx)
	return nil
}
