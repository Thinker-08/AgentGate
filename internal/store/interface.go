package store

import (
	"context"
	"time"

	"github.com/mihiragrawal/agentgate/internal/core"
)

type Store interface {
	GetPolicies(ctx context.Context) ([]core.Policy, error)
	InsertPaymentClaim(ctx context.Context, p core.Payment) (core.Payment, bool, error)
	UpdatePaymentSettled(ctx context.Context, id int64, txHash string) error
	UpdatePaymentFailed(ctx context.Context, id int64, reason string) error
	SaveGrant(ctx context.Context, g core.AccessGrant) error
	InsertAnalytics(ctx context.Context, evs []core.Event) error
	Ping(ctx context.Context) error
}

type ReplayStore interface {
	Claim(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

type DenyList interface {
	IsDenied(ctx context.Context, jti string) (bool, error)
	Deny(ctx context.Context, jti string, ttl time.Duration) error
}

type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}

type Counter interface {
	Incr(ctx context.Context, key string, ttl time.Duration) (int64, error)
	Get(ctx context.Context, key string) (int64, error)
}
