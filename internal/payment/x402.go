package payment

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mihiragrawal/agentgate/internal/core"
)

type X402Verifier struct {
	base string
	hc   *http.Client
}

func NewX402(facilitatorURL string, timeout time.Duration) *X402Verifier {
	return &X402Verifier{
		base: strings.TrimRight(facilitatorURL, "/"),
		hc:   &http.Client{Timeout: timeout},
	}
}

func (x *X402Verifier) Name() string { return "x402" }

func (x *X402Verifier) Verify(ctx context.Context, p core.PaymentPayload, r core.PaymentRequirements) (core.VerifyResult, error) {
	var out verifyResponse
	if err := x.post(ctx, "/verify", p, r, "", &out); err != nil {
		return core.VerifyResult{}, err
	}
	return core.VerifyResult{IsValid: out.IsValid, InvalidReason: out.InvalidReason, Payer: out.Payer}, nil
}

func (x *X402Verifier) Settle(ctx context.Context, p core.PaymentPayload, r core.PaymentRequirements, idempotencyKey string) (core.SettleResult, error) {
	var out settleResponse
	if err := x.post(ctx, "/settle", p, r, idempotencyKey, &out); err != nil {
		return core.SettleResult{}, err
	}
	return core.SettleResult{
		Success:     out.Success,
		ErrorReason: out.ErrorReason,
		Payer:       out.Payer,
		TxHash:      out.Transaction,
		Network:     out.Network,
	}, nil
}

func (x *X402Verifier) post(ctx context.Context, path string, p core.PaymentPayload, r core.PaymentRequirements, idem string, out interface{}) error {
	body, err := json.Marshal(facilitatorRequest{X402Version: 1, PaymentPayload: p, PaymentRequirements: r})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, x.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if idem != "" {
		req.Header.Set("Idempotency-Key", idem)
	}
	resp, err := x.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("facilitator %s returned %d: %s", path, resp.StatusCode, string(data))
	}
	return json.Unmarshal(data, out)
}
