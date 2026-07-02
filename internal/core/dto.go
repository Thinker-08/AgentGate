package core

import "time"

type Decision int

const (
	DecisionAllow Decision = iota
	DecisionRequirePayment
	DecisionDeny
)

func (d Decision) String() string {
	switch d {
	case DecisionAllow:
		return "allow"
	case DecisionRequirePayment:
		return "require_payment"
	case DecisionDeny:
		return "deny"
	default:
		return "unknown"
	}
}

type AgentClass string

const (
	ClassHuman         AgentClass = "human"
	ClassSearchCrawler AgentClass = "search_crawler"
	ClassAIAgent       AgentClass = "ai_agent"
	ClassAutomation    AgentClass = "automation_framework"
	ClassUnknown       AgentClass = "unknown"
)

type DetectInput struct {
	UserAgent string
	RemoteIP  string
	Headers   map[string]string
	JA4       string
}

type DetectResult struct {
	Class      AgentClass
	Operator   string
	Confidence float64
	Verified   bool
	Signals    []string
}

type Action string

const (
	ActionAllow Action = "allow"
	ActionPay   Action = "pay"
	ActionDeny  Action = "deny"
)

type GrantOn string

const (
	GrantOnSettle GrantOn = "settle"
	GrantOnVerify GrantOn = "verify"
)

type Policy struct {
	ID            int64
	Host          string
	PathPattern   string
	Method        string
	Action        Action
	PriceAtomic   int64
	Network       string
	Asset         string
	PayTo         string
	GrantTTL      time.Duration
	GrantOn       GrantOn
	Priority      int
	Version       int64
	BotClassRules map[string]Action
}

type PolicyInput struct {
	Host   string
	Path   string
	Method string
	Detect DetectResult
}

type PolicyDecision struct {
	Action Action
	Policy *Policy
	Reason string
}

type Authorization struct {
	From        string `json:"from"`
	To          string `json:"to"`
	Value       string `json:"value"`
	ValidAfter  string `json:"validAfter"`
	ValidBefore string `json:"validBefore"`
	Nonce       string `json:"nonce"`
}

type PaymentPayloadInner struct {
	Signature     string        `json:"signature"`
	Authorization Authorization `json:"authorization"`
}

type PaymentPayload struct {
	X402Version int                 `json:"x402Version"`
	Scheme      string              `json:"scheme"`
	Network     string              `json:"network"`
	Payload     PaymentPayloadInner `json:"payload"`
}

type PaymentRequirements struct {
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

type Challenge struct {
	X402Version int                   `json:"x402Version"`
	Accepts     []PaymentRequirements `json:"accepts"`
	Error       string                `json:"error,omitempty"`
	ChallengeID string                `json:"challengeId,omitempty"`
}

type VerifyResult struct {
	IsValid       bool
	InvalidReason string
	Payer         string
}

type SettleResult struct {
	Success     bool
	ErrorReason string
	Payer       string
	TxHash      string
	Network     string
}

type PaymentStatus string

const (
	PaymentPending  PaymentStatus = "pending"
	PaymentVerified PaymentStatus = "verified"
	PaymentSettled  PaymentStatus = "settled"
	PaymentFailed   PaymentStatus = "failed"
)

type Payment struct {
	ID            int64
	Payer         string
	Nonce         string
	Resource      string
	Method        string
	AmountAtomic  int64
	Network       string
	Asset         string
	ValidBefore   int64
	Status        PaymentStatus
	TxHash        string
	InvalidReason string
	ChallengeID   string
}

type AccessGrant struct {
	JTI       string
	Payer     string
	Resource  string
	Method    string
	PaymentID int64
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type Claims struct {
	Subject   string
	Audience  string
	Resource  string
	Method    string
	JTI       string
	PayID     string
	ExpiresAt time.Time
}

type Event struct {
	RequestPath string
	AgentClass  string
	Operator    string
	Decision    string
	IPHash      string
	ChallengeID string
	Confidence  float64
	Ts          time.Time
}
