package payment

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/mihiragrawal/agentgate/internal/core"
)

type MockVerifier struct{}

func NewMock() *MockVerifier { return &MockVerifier{} }

func (m *MockVerifier) Name() string { return "mock" }

func (m *MockVerifier) Verify(ctx context.Context, p core.PaymentPayload, r core.PaymentRequirements) (core.VerifyResult, error) {
	if ok, reason := ValidateLocally(p, r, time.Now()); !ok {
		return core.VerifyResult{IsValid: false, InvalidReason: reason}, nil
	}
	if strings.TrimSpace(p.Payload.Signature) == "" {
		return core.VerifyResult{IsValid: false, InvalidReason: "missing_signature"}, nil
	}
	return core.VerifyResult{IsValid: true, Payer: p.Payload.Authorization.From}, nil
}

func (m *MockVerifier) Settle(ctx context.Context, p core.PaymentPayload, r core.PaymentRequirements, idempotencyKey string) (core.SettleResult, error) {
	return core.SettleResult{
		Success: true,
		Payer:   p.Payload.Authorization.From,
		TxHash:  mockTx(p.Payload.Authorization),
		Network: r.Network,
	}, nil
}

func mockTx(a core.Authorization) string {
	sum := sha256.Sum256([]byte(a.From + "|" + a.Nonce))
	return "0xmock" + hex.EncodeToString(sum[:26])
}
