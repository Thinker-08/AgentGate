package policy

import (
	"context"
	"sort"
	"strings"
	"sync"

	"github.com/mihiragrawal/agentgate/internal/core"
	"github.com/mihiragrawal/agentgate/internal/store"
)

type Engine struct {
	st            store.Store
	defaultAction core.Action

	mu   sync.RWMutex
	snap []core.Policy
}

func New(st store.Store, defaultAction core.Action) *Engine {
	if defaultAction == "" {
		defaultAction = core.ActionAllow
	}
	return &Engine{st: st, defaultAction: defaultAction}
}

func (e *Engine) Reload(ctx context.Context) error {
	ps, err := e.st.GetPolicies(ctx)
	if err != nil {
		return err
	}
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].Priority != ps[j].Priority {
			return ps[i].Priority > ps[j].Priority
		}
		return len(ps[i].PathPattern) > len(ps[j].PathPattern)
	})
	e.mu.Lock()
	e.snap = ps
	e.mu.Unlock()
	return nil
}

func (e *Engine) Evaluate(ctx context.Context, in core.PolicyInput) core.PolicyDecision {
	e.mu.RLock()
	snap := e.snap
	e.mu.RUnlock()

	for i := range snap {
		p := &snap[i]
		if !hostMatch(p.Host, in.Host) {
			continue
		}
		if !methodMatch(p.Method, in.Method) {
			continue
		}
		if !pathMatch(p.PathPattern, in.Path) {
			continue
		}
		action, ruleReason := applyClassRules(p, in.Detect)
		reason := "matched:" + p.PathPattern
		if ruleReason != "" {
			reason += ";" + ruleReason
		}
		return core.PolicyDecision{Action: action, Policy: p, Reason: reason}
	}
	return core.PolicyDecision{Action: e.defaultAction, Policy: nil, Reason: "default"}
}

func applyClassRules(p *core.Policy, det core.DetectResult) (core.Action, string) {
	if len(p.BotClassRules) == 0 {
		return p.Action, ""
	}
	for _, k := range classKeys(det) {
		if a, ok := p.BotClassRules[k]; ok {
			return a, "class_rule:" + k
		}
	}
	return p.Action, ""
}

func classKeys(det core.DetectResult) []string {
	var ks []string
	if det.Verified {
		if det.Class == core.ClassSearchCrawler {
			ks = append(ks, "verified_search_crawler")
		}
		if det.Operator != "" {
			ks = append(ks, "verified_"+det.Operator)
		}
	}
	if det.Operator != "" {
		ks = append(ks, det.Operator)
	}
	ks = append(ks, string(det.Class))
	return ks
}

func hostMatch(pattern, host string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	return strings.EqualFold(pattern, host)
}

func methodMatch(pattern, method string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	return strings.EqualFold(pattern, method)
}

func pathMatch(pattern, path string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "*" || pattern == "/*" {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		if strings.HasPrefix(path, prefix) {
			return true
		}
		return path == strings.TrimSuffix(prefix, "/")
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "*"))
	}
	return path == pattern
}
