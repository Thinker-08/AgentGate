package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/mihiragrawal/agentgate/internal/core"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func reqPath(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}
	return uri
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func bearer(authz string) string {
	const p = "bearer "
	if len(authz) > len(p) && strings.EqualFold(authz[:len(p)], p) {
		return strings.TrimSpace(authz[len(p):])
	}
	return ""
}

func detectInput(r *http.Request, remoteIP string) core.DetectInput {
	headers := map[string]string{}
	for _, h := range []string{"accept", "accept-language", "sec-fetch-mode", "sec-fetch-site", "sec-ch-ua"} {
		if v := r.Header.Get(h); v != "" {
			headers[h] = v
		}
	}
	return core.DetectInput{
		UserAgent: r.Header.Get("User-Agent"),
		RemoteIP:  remoteIP,
		Headers:   headers,
		JA4:       r.Header.Get("X-JA4"),
	}
}

func hashIP(ip string) string {
	if ip == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ip))
	return hex.EncodeToString(sum[:12])
}

func challengeID(host, resource string) string {
	sum := sha256.Sum256([]byte(host + "|" + resource))
	return "chal:" + hex.EncodeToString(sum[:16])
}

func (s *Server) abusive(ctx context.Context, ip string) bool {
	if s.Counter == nil || s.Cfg.AbuseThreshold <= 0 || ip == "" {
		return false
	}
	n, err := s.Counter.Get(ctx, "abuse:"+ip)
	if err != nil {
		return false
	}
	return int(n) >= s.Cfg.AbuseThreshold
}

func (s *Server) bumpAbuse(ctx context.Context, ip string) {
	if s.Counter == nil || ip == "" {
		return
	}
	_, _ = s.Counter.Incr(ctx, "abuse:"+ip, 10*time.Minute)
}
