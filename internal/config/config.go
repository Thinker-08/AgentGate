package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr  string
	AdminAddr string

	PostgresDSN   string
	RedisAddr     string
	RedisPassword string

	JWTSeedHex string
	TokenTTL   time.Duration

	Verifier       string
	Network        string
	Asset          string
	AssetName      string
	AssetVersion   string
	PayTo          string
	FacilitatorURL string
	MaxTimeoutSecs int

	Enforce        bool
	AuthTimeout    time.Duration
	DefaultRateRPM int
	Env            string

	EdgeSecret         string
	BotRangesFile      string
	BotSourcesFile     string
	BotRefreshInterval time.Duration
	AbuseThreshold     int
	PaidRedirectPrefix string
}

func Load() (*Config, error) {
	loadDotEnv(".env")
	c := &Config{
		HTTPAddr:           env("AGENTGATE_HTTP_ADDR", ":8080"),
		AdminAddr:          env("AGENTGATE_ADMIN_ADDR", ":9090"),
		PostgresDSN:        env("AGENTGATE_POSTGRES_DSN", "postgres://agentgate:agentgate@localhost:5432/agentgate?sslmode=disable"),
		RedisAddr:          env("AGENTGATE_REDIS_ADDR", "localhost:6379"),
		RedisPassword:      env("AGENTGATE_REDIS_PASSWORD", ""),
		JWTSeedHex:         env("AGENTGATE_JWT_SEED_HEX", ""),
		TokenTTL:           envDur("AGENTGATE_TOKEN_TTL", 120*time.Second),
		Verifier:           strings.ToLower(env("AGENTGATE_VERIFIER", "mock")),
		Network:            env("AGENTGATE_NETWORK", "base-sepolia"),
		Asset:              env("AGENTGATE_ASSET", "0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
		AssetName:          env("AGENTGATE_ASSET_NAME", "USDC"),
		AssetVersion:       env("AGENTGATE_ASSET_VERSION", "2"),
		PayTo:              env("AGENTGATE_PAY_TO", "0x0000000000000000000000000000000000000000"),
		FacilitatorURL:     env("AGENTGATE_FACILITATOR_URL", "https://x402.org/facilitator"),
		MaxTimeoutSecs:     envInt("AGENTGATE_MAX_TIMEOUT_SECS", 120),
		Enforce:            envBool("AGENTGATE_ENFORCE", true),
		AuthTimeout:        envDur("AGENTGATE_AUTH_TIMEOUT", 1500*time.Millisecond),
		DefaultRateRPM:     envInt("AGENTGATE_DEFAULT_RATE_RPM", 120),
		Env:                env("AGENTGATE_ENV", "dev"),
		EdgeSecret:         env("AGENTGATE_EDGE_SECRET", ""),
		BotRangesFile:      env("AGENTGATE_BOT_RANGES_FILE", ""),
		BotSourcesFile:     env("AGENTGATE_BOT_SOURCES_FILE", ""),
		BotRefreshInterval: envDur("AGENTGATE_BOT_REFRESH_INTERVAL", 0),
		AbuseThreshold:     envInt("AGENTGATE_ABUSE_THRESHOLD", 5),
		PaidRedirectPrefix: env("AGENTGATE_PAID_REDIRECT_PREFIX", ""),
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) Validate() error {
	if c.Verifier != "mock" && c.Verifier != "x402" {
		return fmt.Errorf("AGENTGATE_VERIFIER must be 'mock' or 'x402', got %q", c.Verifier)
	}
	if c.Verifier == "x402" && c.FacilitatorURL == "" {
		return fmt.Errorf("AGENTGATE_FACILITATOR_URL required when verifier=x402")
	}
	if c.TokenTTL <= 0 {
		return fmt.Errorf("AGENTGATE_TOKEN_TTL must be > 0")
	}
	if c.AuthTimeout <= 0 {
		return fmt.Errorf("AGENTGATE_AUTH_TIMEOUT must be > 0")
	}
	if c.PaidRedirectPrefix != "" {
		if !strings.HasPrefix(c.PaidRedirectPrefix, "/") ||
			strings.ContainsAny(c.PaidRedirectPrefix, "?# \t") ||
			strings.Contains(c.PaidRedirectPrefix, "..") {
			return fmt.Errorf("AGENTGATE_PAID_REDIRECT_PREFIX must be a clean absolute internal path (got %q)", c.PaidRedirectPrefix)
		}
	}
	return nil
}

func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			val = val[1 : len(val)-1]
		}
		if key == "" {
			continue
		}
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(k string, def bool) bool {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
