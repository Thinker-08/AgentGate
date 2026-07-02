package detector

import (
	"context"
	"strings"

	"github.com/mihiragrawal/agentgate/internal/core"
	"github.com/mihiragrawal/agentgate/internal/observability"
)

type FreqFunc func(ctx context.Context, key string) int

type Engine struct {
	ranges        *IPRanges
	freq          FreqFunc
	freqThreshold int
}

type Option func(*Engine)

func WithRanges(r *IPRanges) Option {
	return func(d *Engine) {
		if r != nil {
			d.ranges = r
		}
	}
}

func WithFrequency(f FreqFunc, threshold int) Option {
	return func(d *Engine) {
		d.freq = f
		if threshold > 0 {
			d.freqThreshold = threshold
		}
	}
}

func New(opts ...Option) *Engine {
	d := &Engine{ranges: NewIPRanges(), freqThreshold: 600}
	for _, o := range opts {
		o(d)
	}
	return d
}

func (d *Engine) Detect(ctx context.Context, in core.DetectInput) core.DetectResult {
	res := d.classify(ctx, in)
	observability.DetectTotal.WithLabelValues(string(res.Class)).Inc()
	return res
}

func (d *Engine) classify(ctx context.Context, in core.DetectInput) core.DetectResult {
	ua := strings.ToLower(strings.TrimSpace(in.UserAgent))
	signals := []string{}
	if in.JA4 == "" {
		signals = append(signals, "no_ja4")
	} else if tool, ok := ja4Denylist[in.JA4]; ok {
		return result(core.ClassAutomation, tool, 0.8, false, append(signals, "ja4_denylist"))
	}

	if ua == "" {
		return d.maybeBehavioral(ctx, in, result(core.ClassUnknown, "", 0.5, false, append(signals, "empty_ua")))
	}

	for _, s := range signatures {
		if !strings.Contains(ua, s.token) {
			continue
		}
		signals = append(signals, "ua:"+s.token)
		if s.verifiable {
			if d.ranges.Contains(s.operator, in.RemoteIP) {
				return result(s.class, s.operator, 0.95, true, append(signals, "ip_verified"))
			}
			return result(core.ClassAutomation, "", 0.6, false, append(signals, "ua_ip_mismatch", "spoof_suspected"))
		}
		return result(s.class, s.operator, 0.7, false, signals)
	}

	if looksLikeBrowser(ua, in.Headers) {
		return d.maybeBehavioral(ctx, in, result(core.ClassHuman, "", 0.4, false, append(signals, "browser_ua", "forgeable")))
	}
	return d.maybeBehavioral(ctx, in, result(core.ClassUnknown, "", 0.3, false, append(signals, "unrecognized_ua")))
}

func (d *Engine) maybeBehavioral(ctx context.Context, in core.DetectInput, base core.DetectResult) core.DetectResult {
	if d.freq == nil || in.RemoteIP == "" {
		return base
	}
	if base.Class != core.ClassHuman && base.Class != core.ClassUnknown {
		return base
	}
	if d.freq(ctx, NormalizeIP(in.RemoteIP)) > d.freqThreshold {
		return result(core.ClassAutomation, "", 0.6, false, append(base.Signals, "high_frequency"))
	}
	return base
}

func result(class core.AgentClass, operator string, conf float64, verified bool, signals []string) core.DetectResult {
	return core.DetectResult{
		Class:      class,
		Operator:   operator,
		Confidence: conf,
		Verified:   verified,
		Signals:    signals,
	}
}

func looksLikeBrowser(ua string, headers map[string]string) bool {
	if !strings.Contains(ua, "mozilla/") {
		return false
	}
	if _, ok := headers["sec-fetch-mode"]; ok {
		return true
	}
	return strings.Contains(ua, "chrome") || strings.Contains(ua, "safari") || strings.Contains(ua, "firefox") || strings.Contains(ua, "gecko")
}
