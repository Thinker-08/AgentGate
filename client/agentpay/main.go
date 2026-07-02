package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

type requirements struct {
	Scheme            string            `json:"scheme"`
	Network           string            `json:"network"`
	MaxAmountRequired string            `json:"maxAmountRequired"`
	Resource          string            `json:"resource"`
	Description       string            `json:"description"`
	MimeType          string            `json:"mimeType"`
	PayTo             string            `json:"payTo"`
	MaxTimeoutSeconds int               `json:"maxTimeoutSeconds"`
	Asset             string            `json:"asset"`
	Extra             map[string]string `json:"extra"`
}

type challenge struct {
	X402Version int            `json:"x402Version"`
	Accepts     []requirements `json:"accepts"`
	Error       string         `json:"error"`
	ChallengeID string         `json:"challengeId"`
}

type authorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

type payloadInner struct {
	Signature     string        `json:"signature"`
	Authorization authorization `json:"authorization"`
}

type paymentPayload struct {
	X402Version int          `json:"x402Version"`
	Scheme      string       `json:"scheme"`
	Network     string       `json:"network"`
	Payload     payloadInner `json:"payload"`
}

type config struct {
	base     string
	resource string
	method   string
	keyHex   string
	chainID  int64
	window   int
	access   bool
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "\nagentpay: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.base, "base", env("AGENTPAY_BASE", "http://localhost:8088"), "gateway base URL")
	flag.StringVar(&cfg.resource, "resource", env("AGENTPAY_RESOURCE", "/premium/report"), "protected resource path")
	flag.StringVar(&cfg.method, "method", env("AGENTPAY_METHOD", "GET"), "HTTP method for the resource")
	flag.StringVar(&cfg.keyHex, "key", env("AGENTPAY_PRIVATE_KEY", ""), "payer private key hex (or AGENTPAY_PRIVATE_KEY)")
	flag.Int64Var(&cfg.chainID, "chain-id", 0, "EVM chain id (0 = derive from challenge network)")
	flag.IntVar(&cfg.window, "window", 0, "authorization window seconds (0 = use challenge maxTimeoutSeconds)")
	flag.BoolVar(&cfg.access, "access", true, "after payment, retry the resource with the issued token")
	flag.Parse()
	return cfg
}

func run(cfg config) error {
	if strings.TrimSpace(cfg.keyHex) == "" {
		return fmt.Errorf("payer private key required (-key or AGENTPAY_PRIVATE_KEY)")
	}
	key, err := crypto.HexToECDSA(strings.TrimPrefix(strings.TrimSpace(cfg.keyHex), "0x"))
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}
	payer := crypto.PubkeyToAddress(key.PublicKey)
	fmt.Printf("payer wallet     : %s\n", payer.Hex())
	fmt.Printf("gateway          : %s\n", cfg.base)
	fmt.Printf("resource         : %s %s\n", cfg.method, cfg.resource)

	req, chalID, err := fetchChallenge(cfg.base, cfg.resource)
	if err != nil {
		return err
	}
	fmt.Printf("\n[1] challenge received\n")
	fmt.Printf("    scheme/network : %s / %s\n", req.Scheme, req.Network)
	fmt.Printf("    price (atomic) : %s\n", req.MaxAmountRequired)
	fmt.Printf("    pay_to         : %s\n", req.PayTo)
	fmt.Printf("    asset          : %s\n", req.Asset)
	fmt.Printf("    domain         : name=%q version=%q\n", req.Extra["name"], req.Extra["version"])
	fmt.Printf("    challenge id   : %s\n", chalID)

	chainID := cfg.chainID
	if chainID == 0 {
		chainID, err = chainIDForNetwork(req.Network)
		if err != nil {
			return err
		}
	}
	window := cfg.window
	if window == 0 {
		window = req.MaxTimeoutSeconds
	}
	if window <= 0 {
		window = 600
	}

	pp, err := signPayment(key, payer.Hex(), req, chainID, window)
	if err != nil {
		return err
	}
	fmt.Printf("\n[2] payment signed (EIP-712 TransferWithAuthorization)\n")
	fmt.Printf("    chain id       : %d\n", chainID)
	fmt.Printf("    value          : %s\n", pp.Payload.Authorization.Value)
	fmt.Printf("    valid window   : %s .. %s\n", pp.Payload.Authorization.ValidAfter, pp.Payload.Authorization.ValidBefore)
	fmt.Printf("    nonce          : %s\n", pp.Payload.Authorization.Nonce)
	fmt.Printf("    signature      : %s...\n", truncate(pp.Payload.Signature, 26))

	header, err := encodePayment(pp)
	if err != nil {
		return err
	}

	status, body, token, payResp, err := submitPayment(cfg, header)
	if err != nil {
		return err
	}
	fmt.Printf("\n[3] paid retry %s %s (X-PAYMENT) -> HTTP %d\n", cfg.method, cfg.resource, status)
	if status != http.StatusOK {
		fmt.Printf("    body           : %s\n", strings.TrimSpace(string(body)))
		return fmt.Errorf("payment not accepted (HTTP %d)", status)
	}
	fmt.Printf("    resource body  : %s\n", strings.TrimSpace(string(body)))
	fmt.Printf("    access token   : %s...\n", truncate(token, 24))
	printSettlement(payResp)

	if cfg.access && token != "" {
		st, ab, err := accessWithToken(cfg, token)
		if err != nil {
			return err
		}
		fmt.Printf("\n[4] %s %s (fast path, with token) -> HTTP %d\n", cfg.method, cfg.resource, st)
		fmt.Printf("    body           : %s\n", strings.TrimSpace(string(ab)))
		if st != http.StatusOK {
			return fmt.Errorf("token did not grant access (HTTP %d)", st)
		}
	}
	fmt.Printf("\nOK: live x402 payment settled and access granted.\n")
	return nil
}

func fetchChallenge(base, resource string) (requirements, string, error) {
	resp, err := http.Get(strings.TrimRight(base, "/") + resource)
	if err != nil {
		return requirements{}, "", fmt.Errorf("fetch challenge: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusPaymentRequired {
		return requirements{}, "", fmt.Errorf("expected 402 challenge, got HTTP %d: %s", resp.StatusCode, string(body))
	}
	var ch challenge
	if err := json.Unmarshal(body, &ch); err != nil {
		return requirements{}, "", fmt.Errorf("decode challenge: %w (body=%s)", err, string(body))
	}
	for _, r := range ch.Accepts {
		if strings.EqualFold(r.Scheme, "exact") {
			return r, ch.ChallengeID, nil
		}
	}
	if len(ch.Accepts) > 0 {
		return ch.Accepts[0], ch.ChallengeID, nil
	}
	return requirements{}, "", fmt.Errorf("challenge has no payment requirements")
}

func signPayment(key *ecdsa.PrivateKey, from string, req requirements, chainID int64, window int) (paymentPayload, error) {
	nonce, err := randomNonce()
	if err != nil {
		return paymentPayload{}, err
	}
	now := time.Now().Unix()
	validAfter := strconv.FormatInt(now-60, 10)
	validBefore := strconv.FormatInt(now+int64(window), 10)

	auth := authorization{
		From:        from,
		To:          req.PayTo,
		Value:       req.MaxAmountRequired,
		ValidAfter:  validAfter,
		ValidBefore: validBefore,
		Nonce:       nonce,
	}

	name := req.Extra["name"]
	version := req.Extra["version"]
	typedData := apitypes.TypedData{
		Types: apitypes.Types{
			"EIP712Domain": []apitypes.Type{
				{Name: "name", Type: "string"},
				{Name: "version", Type: "string"},
				{Name: "chainId", Type: "uint256"},
				{Name: "verifyingContract", Type: "address"},
			},
			"TransferWithAuthorization": []apitypes.Type{
				{Name: "from", Type: "address"},
				{Name: "to", Type: "address"},
				{Name: "value", Type: "uint256"},
				{Name: "validAfter", Type: "uint256"},
				{Name: "validBefore", Type: "uint256"},
				{Name: "nonce", Type: "bytes32"},
			},
		},
		PrimaryType: "TransferWithAuthorization",
		Domain: apitypes.TypedDataDomain{
			Name:              name,
			Version:           version,
			ChainId:           math.NewHexOrDecimal256(chainID),
			VerifyingContract: req.Asset,
		},
		Message: apitypes.TypedDataMessage{
			"from":        auth.From,
			"to":          auth.To,
			"value":       auth.Value,
			"validAfter":  auth.ValidAfter,
			"validBefore": auth.ValidBefore,
			"nonce":       auth.Nonce,
		},
	}

	digest, _, err := apitypes.TypedDataAndHash(typedData)
	if err != nil {
		return paymentPayload{}, fmt.Errorf("eip-712 hash: %w", err)
	}
	sig, err := crypto.Sign(digest, key)
	if err != nil {
		return paymentPayload{}, fmt.Errorf("sign: %w", err)
	}
	if sig[64] < 27 {
		sig[64] += 27
	}

	return paymentPayload{
		X402Version: 1,
		Scheme:      "exact",
		Network:     req.Network,
		Payload: payloadInner{
			Signature:     hexutil.Encode(sig),
			Authorization: auth,
		},
	}, nil
}

func encodePayment(pp paymentPayload) (string, error) {
	raw, err := json.Marshal(pp)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func submitPayment(cfg config, header string) (int, []byte, string, string, error) {
	req, err := http.NewRequest(cfg.method, strings.TrimRight(cfg.base, "/")+cfg.resource, nil)
	if err != nil {
		return 0, nil, "", "", err
	}
	req.Header.Set("X-PAYMENT", header)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, "", "", fmt.Errorf("submit payment: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, resp.Header.Get("X-AgentGate-Token"), resp.Header.Get("X-PAYMENT-RESPONSE"), nil
}

func accessWithToken(cfg config, token string) (int, []byte, error) {
	req, err := http.NewRequest(cfg.method, strings.TrimRight(cfg.base, "/")+cfg.resource, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("access with token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func printSettlement(payResp string) {
	if payResp == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(payResp)
	if err != nil {
		return
	}
	var s struct {
		Success     bool   `json:"success"`
		Transaction string `json:"transaction"`
		Network     string `json:"network"`
		Payer       string `json:"payer"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return
	}
	fmt.Printf("    settlement     : success=%v network=%s\n", s.Success, s.Network)
	fmt.Printf("    tx hash        : %s\n", s.Transaction)
}

func chainIDForNetwork(network string) (int64, error) {
	switch strings.ToLower(network) {
	case "base-sepolia":
		return 84532, nil
	case "base":
		return 8453, nil
	default:
		return 0, fmt.Errorf("unknown network %q; pass -chain-id explicitly", network)
	}
}

func randomNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hexutil.Encode(b), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}
