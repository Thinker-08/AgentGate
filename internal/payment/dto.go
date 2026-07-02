package payment

import "github.com/mihiragrawal/agentgate/internal/core"

type facilitatorRequest struct {
	X402Version         int                      `json:"x402Version"`
	PaymentPayload      core.PaymentPayload      `json:"paymentPayload"`
	PaymentRequirements core.PaymentRequirements `json:"paymentRequirements"`
}

type verifyResponse struct {
	IsValid       bool   `json:"isValid"`
	InvalidReason string `json:"invalidReason"`
	Payer         string `json:"payer"`
}

type settleResponse struct {
	Success     bool   `json:"success"`
	ErrorReason string `json:"errorReason"`
	Payer       string `json:"payer"`
	Transaction string `json:"transaction"`
	Network     string `json:"network"`
}
