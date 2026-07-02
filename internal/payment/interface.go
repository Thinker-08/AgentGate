package payment

import (
	"context"

	"github.com/mihiragrawal/agentgate/internal/core"
)

type PaymentVerifier interface {
	Name() string
	Verify(ctx context.Context, p core.PaymentPayload, r core.PaymentRequirements) (core.VerifyResult, error)
	Settle(ctx context.Context, p core.PaymentPayload, r core.PaymentRequirements, idempotencyKey string) (core.SettleResult, error)
}
