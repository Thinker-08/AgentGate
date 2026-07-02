package analytics

import "github.com/mihiragrawal/agentgate/internal/core"

type AnalyticsSink interface {
	Record(ev core.Event)
}
