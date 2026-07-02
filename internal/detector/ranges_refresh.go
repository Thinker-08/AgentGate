package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/mihiragrawal/agentgate/internal/observability"
)

type Source struct {
	URL    string `json:"url"`
	Format string `json:"format"`
}

type Refresher struct {
	ranges   *IPRanges
	sources  map[string][]Source
	interval time.Duration
	hc       *http.Client
	log      *zap.Logger
}

func NewRefresher(ranges *IPRanges, sources map[string][]Source, interval time.Duration, log *zap.Logger) *Refresher {
	return &Refresher{
		ranges:   ranges,
		sources:  sources,
		interval: interval,
		hc:       &http.Client{Timeout: 15 * time.Second},
		log:      log,
	}
}

func (rf *Refresher) Start(ctx context.Context) {
	go func() {
		rf.RefreshOnce(ctx)
		t := time.NewTicker(rf.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rf.RefreshOnce(ctx)
			}
		}
	}()
}

func (rf *Refresher) RefreshOnce(ctx context.Context) {
	for operator, srcs := range rf.sources {
		cidrs, err := rf.fetchOperator(ctx, srcs)
		if err != nil || len(cidrs) == 0 {
			observability.BotRangesRefreshTotal.WithLabelValues(operator, "error").Inc()
			if rf.log != nil {
				rf.log.Warn("bot range refresh failed; keeping last-good ranges",
					zap.String("operator", operator), zap.Error(err))
			}
			continue
		}
		n := rf.ranges.Replace(operator, cidrs)
		observability.BotRangesRefreshTotal.WithLabelValues(operator, "success").Inc()
		observability.BotRangesCIDRs.WithLabelValues(operator).Set(float64(n))
		observability.BotRangesLastSuccess.WithLabelValues(operator).SetToCurrentTime()
		if rf.log != nil {
			rf.log.Info("bot ranges refreshed", zap.String("operator", operator), zap.Int("cidrs", n))
		}
	}
}

func (rf *Refresher) fetchOperator(ctx context.Context, srcs []Source) ([]string, error) {
	var all []string
	var firstErr error
	for _, s := range srcs {
		cidrs, err := rf.fetchSource(ctx, s)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		all = append(all, cidrs...)
	}
	if len(all) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, fmt.Errorf("no cidrs parsed")
	}
	return all, nil
}

func (rf *Refresher) fetchSource(ctx context.Context, s Source) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := rf.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s -> %d", s.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return parseRanges(s.Format, body)
}

func parseRanges(format string, body []byte) ([]string, error) {
	switch format {
	case "prefixes":
		var doc struct {
			Prefixes []struct {
				IPv4Prefix string `json:"ipv4Prefix"`
				IPv6Prefix string `json:"ipv6Prefix"`
			} `json:"prefixes"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return nil, err
		}
		out := make([]string, 0, len(doc.Prefixes))
		for _, p := range doc.Prefixes {
			if p.IPv4Prefix != "" {
				out = append(out, p.IPv4Prefix)
			}
			if p.IPv6Prefix != "" {
				out = append(out, p.IPv6Prefix)
			}
		}
		return out, nil
	case "list":
		var out []string
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, err
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown range format %q", format)
	}
}

func DefaultSources() map[string][]Source {
	return map[string][]Source{
		"google": {
			{URL: "https://developers.google.com/static/search/apis/ipranges/googlebot.json", Format: "prefixes"},
		},
		"microsoft": {
			{URL: "https://www.bing.com/toolbox/bingbot.json", Format: "prefixes"},
		},
		"openai": {
			{URL: "https://openai.com/gptbot.json", Format: "prefixes"},
			{URL: "https://openai.com/searchbot.json", Format: "prefixes"},
			{URL: "https://openai.com/chatgpt-user.json", Format: "prefixes"},
		},
	}
}

func LoadSources(path string) (map[string][]Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string][]Source
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}
