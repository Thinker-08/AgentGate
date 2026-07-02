package payment

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/mihiragrawal/agentgate/internal/core"
)

const clockLeeway = 5 * time.Second

func BuildRequirements(pol *core.Policy, resource, assetName, assetVersion string, maxTimeoutSecs int) core.PaymentRequirements {
	return core.PaymentRequirements{
		Scheme:            "exact",
		Network:           pol.Network,
		MaxAmountRequired: strconv.FormatInt(pol.PriceAtomic, 10),
		Resource:          resource,
		Description:       fmt.Sprintf("Access to %s", resource),
		MimeType:          "application/json",
		PayTo:             pol.PayTo,
		MaxTimeoutSeconds: maxTimeoutSecs,
		Asset:             pol.Asset,
		Extra:             map[string]string{"name": assetName, "version": assetVersion},
	}
}

func DecodePaymentHeader(b64 string) (core.PaymentPayload, error) {
	var p core.PaymentPayload
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return p, fmt.Errorf("X-PAYMENT not valid base64: %w", err)
		}
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return p, fmt.Errorf("X-PAYMENT not valid json: %w", err)
	}
	return p, nil
}

func ValidateLocally(p core.PaymentPayload, r core.PaymentRequirements, now time.Time) (bool, string) {
	if !strings.EqualFold(p.Scheme, r.Scheme) {
		return false, "scheme_mismatch"
	}
	if !strings.EqualFold(p.Network, r.Network) {
		return false, "network_mismatch"
	}
	a := p.Payload.Authorization
	if !strings.EqualFold(a.To, r.PayTo) {
		return false, "wrong_pay_to"
	}
	val, ok := new(big.Int).SetString(a.Value, 10)
	if !ok {
		return false, "bad_value"
	}
	req, ok := new(big.Int).SetString(r.MaxAmountRequired, 10)
	if !ok {
		return false, "bad_required_amount"
	}
	switch val.Cmp(req) {
	case -1:
		return false, "underpayment"
	case 1:
		return false, "overpayment"
	}
	va, err := strconv.ParseInt(a.ValidAfter, 10, 64)
	if err != nil {
		return false, "bad_valid_after"
	}
	vb, err := strconv.ParseInt(a.ValidBefore, 10, 64)
	if err != nil {
		return false, "bad_valid_before"
	}
	nowU := now.Unix()
	if nowU < va-int64(clockLeeway.Seconds()) {
		return false, "not_yet_valid"
	}
	if nowU >= vb {
		return false, "expired"
	}
	return true, ""
}

func ReplayKey(payer, nonce string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(payer) + "|" + strings.ToLower(nonce)))
	return "nonce:" + hex.EncodeToString(sum[:])
}

func ValidBeforeTime(a core.Authorization) time.Time {
	vb, err := strconv.ParseInt(a.ValidBefore, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(vb, 0)
}
