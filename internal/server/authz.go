package server

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/mihiragrawal/agentgate/internal/core"
	"github.com/mihiragrawal/agentgate/internal/detector"
	"github.com/mihiragrawal/agentgate/internal/observability"
	"github.com/mihiragrawal/agentgate/internal/payment"
)

func (s *Server) handleAuthz(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	decision := "allow"
	defer func() {
		observability.AuthzDuration.Observe(time.Since(start).Seconds())
		observability.AuthzTotal.WithLabelValues(decision).Inc()
	}()

	ctx := r.Context()
	resource := reqPath(firstNonEmpty(r.Header.Get("X-Original-URI"), r.URL.Path))
	method := firstNonEmpty(r.Header.Get("X-Original-Method"), "GET")
	host := firstNonEmpty(r.Header.Get("X-Original-Host"), r.Host)
	remoteIP := firstNonEmpty(r.Header.Get("X-Real-IP"), r.RemoteAddr)
	normIP := detector.NormalizeIP(remoteIP)

	if !s.Cfg.Enforce {
		w.Header().Set("X-AgentGate-Decision", "allow")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	det := s.Detector.Detect(ctx, detectInput(r, remoteIP))

	var chalID string
	defer func() {
		s.Analytics.Record(core.Event{
			RequestPath: resource,
			AgentClass:  string(det.Class),
			Operator:    det.Operator,
			Decision:    decision,
			IPHash:      hashIP(remoteIP),
			ChallengeID: chalID,
			Confidence:  det.Confidence,
		})
	}()

	if tok := bearer(r.Header.Get("Authorization")); tok != "" {
		if claims, err := s.Issuer.Verify(ctx, tok, resource, method); err == nil {
			denied, derr := s.Deny.IsDenied(ctx, claims.JTI)
			if derr != nil {
				decision = "error"
				w.Header().Set("X-AgentGate-Reason", "denylist_unavailable")
				writeErr(w, http.StatusServiceUnavailable, "unavailable", "could not verify token revocation status")
				return
			}
			if denied {
				decision = "deny"
				w.Header().Set("X-AgentGate-Reason", "revoked")
				writeErr(w, http.StatusForbidden, "revoked", "access token revoked")
				return
			}
			w.Header().Set("X-AgentGate-Decision", "allow")
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}

	dec := s.Policy.Evaluate(ctx, core.PolicyInput{Host: host, Path: resource, Method: method, Detect: det})

	switch dec.Action {
	case core.ActionAllow:
		w.Header().Set("X-AgentGate-Decision", "allow")
		w.WriteHeader(http.StatusNoContent)
	case core.ActionDeny:
		decision = "deny"
		w.Header().Set("X-AgentGate-Reason", "policy_deny")
		writeErr(w, http.StatusForbidden, "forbidden", "denied by policy")
	case core.ActionPay:
		decision = "require_payment"
		if s.abusive(ctx, normIP) {
			decision = "deny"
			w.Header().Set("X-AgentGate-Reason", "abuse")
			writeErr(w, http.StatusForbidden, "forbidden", "temporarily blocked due to repeated failed payments")
			return
		}
		if !s.rateAllow(ctx, normIP) {
			decision = "deny"
			w.Header().Set("X-AgentGate-Reason", "rate_limited")
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		var price int64
		if dec.Policy != nil {
			price = dec.Policy.PriceAtomic
		}
		chalID = challengeID(host, resource)
		w.Header().Set("X-AgentGate-Challenge-Id", chalID)
		w.Header().Set("X-AgentGate-Price", strconv.FormatInt(price, 10))
		w.Header().Set("X-AgentGate-Resource", resource)
		w.Header().Set("X-AgentGate-Reason", "no_grant")
		w.WriteHeader(http.StatusUnauthorized)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	resource := reqPath(firstNonEmpty(r.Header.Get("X-AgentGate-Resource"), r.Header.Get("X-Original-URI"), r.URL.Query().Get("resource")))
	method := firstNonEmpty(r.Header.Get("X-Original-Method"), "GET")
	host := firstNonEmpty(r.Header.Get("X-Original-Host"), r.Host)

	dec := s.Policy.Evaluate(ctx, core.PolicyInput{Host: host, Path: resource, Method: method})
	if dec.Action != core.ActionPay || dec.Policy == nil {
		writeErr(w, http.StatusBadRequest, "not_payable", "resource does not require payment")
		return
	}
	req := payment.BuildRequirements(dec.Policy, resource, s.Cfg.AssetName, s.Cfg.AssetVersion, s.Cfg.MaxTimeoutSecs)
	chalID := firstNonEmpty(r.Header.Get("X-AgentGate-Challenge-Id"), challengeID(host, resource))
	w.Header().Set("X-AgentGate-Challenge-Id", chalID)
	writeJSON(w, http.StatusPaymentRequired, core.Challenge{
		X402Version: 1,
		Accepts:     []core.PaymentRequirements{req},
		Error:       "X-PAYMENT header is required",
		ChallengeID: chalID,
	})
}

func (s *Server) rateAllow(ctx context.Context, ip string) bool {
	if s.Rate == nil || ip == "" {
		return true
	}
	ok, err := s.Rate.Allow(ctx, "ip:"+ip, s.Cfg.DefaultRateRPM, time.Minute)
	if err != nil {
		s.Log.Warn("rate limiter error, allowing")
		return true
	}
	return ok
}
