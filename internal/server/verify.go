package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/mihiragrawal/agentgate/internal/core"
	"github.com/mihiragrawal/agentgate/internal/detector"
	"github.com/mihiragrawal/agentgate/internal/observability"
	"github.com/mihiragrawal/agentgate/internal/payment"
	"github.com/mihiragrawal/agentgate/internal/token"
)

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	normIP := detector.NormalizeIP(firstNonEmpty(r.Header.Get("X-Real-IP"), r.RemoteAddr))
	xpay := r.Header.Get("X-PAYMENT")
	if xpay == "" {
		writeErr(w, http.StatusBadRequest, "missing_payment", "X-PAYMENT header required")
		return
	}
	rawURI := firstNonEmpty(r.Header.Get("X-Resource"), r.Header.Get("X-Original-URI"))
	resource := reqPath(rawURI)
	method := firstNonEmpty(r.Header.Get("X-Method"), r.Header.Get("X-Original-Method"), "GET")
	host := firstNonEmpty(r.Header.Get("X-Original-Host"), r.Host)
	if resource == "" {
		writeErr(w, http.StatusBadRequest, "missing_resource", "X-Resource or X-Original-URI required")
		return
	}

	pay, err := payment.DecodePaymentHeader(xpay)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_payment", err.Error())
		return
	}

	payerKey := "wallet:" + strings.ToLower(pay.Payload.Authorization.From)
	if s.abusive(ctx, payerKey) {
		writeErr(w, http.StatusForbidden, "forbidden", "wallet temporarily blocked due to repeated failed payments")
		return
	}

	dec := s.Policy.Evaluate(ctx, core.PolicyInput{Host: host, Path: resource, Method: method})
	if dec.Action != core.ActionPay || dec.Policy == nil {
		writeErr(w, http.StatusBadRequest, "not_payable", "resource does not require payment")
		return
	}
	req := payment.BuildRequirements(dec.Policy, resource, s.Cfg.AssetName, s.Cfg.AssetVersion, s.Cfg.MaxTimeoutSecs)

	if ok, reason := payment.ValidateLocally(pay, req, time.Now()); !ok {
		s.bumpAbuse(ctx, normIP)
		s.bumpAbuse(ctx, payerKey)
		switch reason {
		case "scheme_mismatch", "network_mismatch", "wrong_pay_to":
			observability.PaymentsTotal.WithLabelValues("mismatch").Inc()
			writeErr(w, http.StatusForbidden, "payment_requirements_mismatch", reason)
		default:
			observability.PaymentsTotal.WithLabelValues("invalid").Inc()
			writeErr(w, http.StatusPaymentRequired, "payment_invalid", reason)
		}
		return
	}

	auth := pay.Payload.Authorization
	validBefore := payment.ValidBeforeTime(auth)
	chalID := firstNonEmpty(r.Header.Get("X-AgentGate-Challenge-Id"), challengeID(host, resource))

	claim := core.Payment{
		Payer:        auth.From,
		Nonce:        auth.Nonce,
		Resource:     resource,
		Method:       method,
		AmountAtomic: dec.Policy.PriceAtomic,
		Network:      dec.Policy.Network,
		Asset:        dec.Policy.Asset,
		ValidBefore:  validBefore.Unix(),
		ChallengeID:  chalID,
	}
	stored, inserted, err := s.Store.InsertPaymentClaim(ctx, claim)
	if err != nil {
		s.Log.Error("payment claim insert failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "internal_error", "could not record payment")
		return
	}
	if !inserted {
		observability.PaymentsTotal.WithLabelValues("duplicate").Inc()
		s.bumpAbuse(ctx, normIP)
		s.bumpAbuse(ctx, payerKey)
		writeErr(w, http.StatusConflict, "payment_already_used", "this authorization has already been used")
		return
	}

	replayKey := payment.ReplayKey(auth.From, auth.Nonce)
	ttl := time.Until(validBefore)
	if ttl <= 0 {
		writeErr(w, http.StatusPaymentRequired, "payment_invalid", "authorization window expired")
		return
	}
	if claimed, rerr := s.Replay.Claim(ctx, replayKey, ttl); rerr != nil {
		s.Log.Warn("replay store error", zap.Error(rerr))
	} else if !claimed {
		observability.PaymentsTotal.WithLabelValues("duplicate").Inc()
		writeErr(w, http.StatusConflict, "payment_already_used", "this authorization has already been used")
		return
	}

	vstart := time.Now()
	vr, err := s.Verifier.Verify(ctx, pay, req)
	observability.VerifierDuration.WithLabelValues("verify", s.Verifier.Name()).Observe(time.Since(vstart).Seconds())
	if err != nil {
		_ = s.Store.UpdatePaymentFailed(ctx, stored.ID, "verify_error")
		observability.PaymentsTotal.WithLabelValues("facilitator_error").Inc()
		writeErr(w, http.StatusBadGateway, "facilitator_unavailable", err.Error())
		return
	}
	if !vr.IsValid {
		_ = s.Store.UpdatePaymentFailed(ctx, stored.ID, vr.InvalidReason)
		observability.PaymentsTotal.WithLabelValues("invalid").Inc()
		s.bumpAbuse(ctx, normIP)
		s.bumpAbuse(ctx, payerKey)
		writeErr(w, http.StatusPaymentRequired, "payment_invalid", vr.InvalidReason)
		return
	}

	sstart := time.Now()
	sr, err := s.Verifier.Settle(ctx, pay, req, replayKey)
	observability.VerifierDuration.WithLabelValues("settle", s.Verifier.Name()).Observe(time.Since(sstart).Seconds())
	if err != nil {
		_ = s.Store.UpdatePaymentFailed(ctx, stored.ID, "settle_error")
		observability.PaymentsTotal.WithLabelValues("facilitator_error").Inc()
		writeErr(w, http.StatusBadGateway, "facilitator_unavailable", err.Error())
		return
	}
	if !sr.Success {
		_ = s.Store.UpdatePaymentFailed(ctx, stored.ID, sr.ErrorReason)
		observability.PaymentsTotal.WithLabelValues("settle_failed").Inc()
		s.bumpAbuse(ctx, normIP)
		s.bumpAbuse(ctx, payerKey)
		writeErr(w, http.StatusPaymentRequired, "settle_failed", sr.ErrorReason)
		return
	}

	if err := s.Store.UpdatePaymentSettled(ctx, stored.ID, sr.TxHash); err != nil {
		s.Log.Error("mark settled failed", zap.Error(err))
	}

	ttlGrant := s.Cfg.TokenTTL
	if dec.Policy.GrantTTL > 0 {
		ttlGrant = dec.Policy.GrantTTL
	}
	grant := core.AccessGrant{
		JTI:       token.NewJTI(),
		Payer:     auth.From,
		Resource:  resource,
		Method:    method,
		PaymentID: stored.ID,
		IssuedAt:  time.Now(),
	}
	jwtStr, exp, err := s.Issuer.Issue(ctx, grant, ttlGrant, validBefore)
	if err != nil {
		s.Log.Error("issue token failed", zap.Error(err))
		writeErr(w, http.StatusInternalServerError, "internal_error", "could not issue token")
		return
	}
	grant.ExpiresAt = exp
	if err := s.Store.SaveGrant(ctx, grant); err != nil {
		s.Log.Error("save grant failed", zap.Error(err))
	}

	observability.PaymentsTotal.WithLabelValues("settled").Inc()
	w.Header().Set("X-PAYMENT-RESPONSE", encodeSettlement(sr))
	if s.Cfg.PaidRedirectPrefix != "" {
		w.Header().Set("X-AgentGate-Token", jwtStr)
		redirect := s.Cfg.PaidRedirectPrefix + resource + "?__agt=" + url.QueryEscape(jwtStr)
		if i := strings.IndexByte(rawURI, '?'); i >= 0 && i+1 < len(rawURI) {
			redirect += "&" + rawURI[i+1:]
		}
		w.Header().Set("X-Accel-Redirect", redirect)
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: jwtStr,
		TokenType:   "Bearer",
		ExpiresIn:   int(time.Until(exp).Seconds()),
		Resource:    resource,
		Method:      method,
	})
}

func encodeSettlement(sr core.SettleResult) string {
	b, _ := json.Marshal(map[string]interface{}{
		"success":     sr.Success,
		"transaction": sr.TxHash,
		"network":     sr.Network,
		"payer":       sr.Payer,
	})
	return base64.StdEncoding.EncodeToString(b)
}
