package policy

import (
	"context"

	"github.com/mihiragrawal/agentgate/internal/core"
)

type PolicyEngine interface {
	Evaluate(ctx context.Context, in core.PolicyInput) core.PolicyDecision
	Reload(ctx context.Context) error
}
