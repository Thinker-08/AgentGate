package token

import (
	"context"
	"time"

	"github.com/mihiragrawal/agentgate/internal/core"
)

type TokenIssuer interface {
	Issue(ctx context.Context, g core.AccessGrant, ttl time.Duration, validBefore time.Time) (token string, exp time.Time, err error)
	Verify(ctx context.Context, token, resource, method string) (*core.Claims, error)
}
