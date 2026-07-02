package detector

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
)

type IPRanges struct {
	mu   sync.RWMutex
	nets map[string][]*net.IPNet
}

func NewIPRanges() *IPRanges {
	r := &IPRanges{nets: map[string][]*net.IPNet{}}
	r.loadDefaults()
	return r
}

func (r *IPRanges) Add(operator string, cidrs []string) {
	parsed := parseCIDRs(cidrs)
	if len(parsed) == 0 {
		return
	}
	r.mu.Lock()
	r.nets[operator] = append(r.nets[operator], parsed...)
	r.mu.Unlock()
}

func (r *IPRanges) Replace(operator string, cidrs []string) int {
	parsed := parseCIDRs(cidrs)
	r.mu.Lock()
	r.nets[operator] = parsed
	r.mu.Unlock()
	return len(parsed)
}

func (r *IPRanges) Contains(operator, addr string) bool {
	ip := net.ParseIP(StripPort(addr))
	if ip == nil {
		return false
	}
	r.mu.RLock()
	nets := r.nets[operator]
	r.mu.RUnlock()
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (r *IPRanges) Operators() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.nets)
}

func parseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func (r *IPRanges) LoadFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m map[string][]string
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	for op, cidrs := range m {
		r.Add(op, cidrs)
	}
	return nil
}

func (r *IPRanges) loadDefaults() {
	r.Add("google", []string{"66.249.64.0/19", "34.100.182.96/28", "2001:4860:4801::/48"})
	r.Add("microsoft", []string{"40.77.167.0/24", "207.46.13.0/24", "157.55.39.0/24"})
	r.Add("openai", []string{"23.98.142.176/28", "172.203.190.128/28", "20.171.206.0/24"})
	r.Add("anthropic", []string{"160.79.104.0/23"})
	r.Add("perplexity", []string{"107.21.0.0/16"})
}

func StripPort(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func NormalizeIP(addr string) string {
	host := StripPort(addr)
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
