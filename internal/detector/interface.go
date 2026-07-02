package detector

import (
	"context"

	"github.com/mihiragrawal/agentgate/internal/core"
)

type Detector interface {
	Detect(ctx context.Context, in core.DetectInput) core.DetectResult
}
