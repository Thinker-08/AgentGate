package token

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/mihiragrawal/agentgate/internal/core"
)

const (
	issuer = "agentgate"
	leeway = 5 * time.Second
)

type Issuer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	kid  string
}

type claims struct {
	jwt.RegisteredClaims
	Resource string `json:"resource"`
	Method   string `json:"method"`
	PayID    string `json:"pay_id"`
}

func New(seedHex string) (*Issuer, error) {
	var priv ed25519.PrivateKey
	if seedHex == "" {
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		priv = p
	} else {
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			return nil, fmt.Errorf("invalid AGENTGATE_JWT_SEED_HEX: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("AGENTGATE_JWT_SEED_HEX must be %d bytes, got %d", ed25519.SeedSize, len(seed))
		}
		priv = ed25519.NewKeyFromSeed(seed)
	}
	pub := priv.Public().(ed25519.PublicKey)
	return &Issuer{priv: priv, pub: pub, kid: keyID(pub)}, nil
}

func (i *Issuer) Ephemeral() bool { return false }

func (i *Issuer) Issue(ctx context.Context, g core.AccessGrant, ttl time.Duration, validBefore time.Time) (string, time.Time, error) {
	now := time.Now()
	exp := now.Add(ttl)
	if !validBefore.IsZero() {
		clamp := validBefore.Add(-leeway)
		if clamp.Before(exp) {
			exp = clamp
		}
	}
	if !exp.After(now) {
		return "", time.Time{}, errors.New("token window already expired (validBefore too close)")
	}
	jti := g.JTI
	if jti == "" {
		jti = NewJTI()
	}
	c := claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   g.Payer,
			Audience:  jwt.ClaimStrings{Audience(g.Method, g.Resource)},
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
		Resource: g.Resource,
		Method:   g.Method,
		PayID:    fmt.Sprintf("%d", g.PaymentID),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	tok.Header["kid"] = i.kid
	signed, err := tok.SignedString(i.priv)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, exp, nil
}

func (i *Issuer) Verify(ctx context.Context, tokenStr, resource, method string) (*core.Claims, error) {
	aud := Audience(method, resource)
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithLeeway(leeway),
		jwt.WithAudience(aud),
		jwt.WithIssuer(issuer),
	)
	var c claims
	_, err := parser.ParseWithClaims(tokenStr, &c, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return i.pub, nil
	})
	if err != nil {
		return nil, err
	}
	expAt := time.Time{}
	if c.ExpiresAt != nil {
		expAt = c.ExpiresAt.Time
	}
	return &core.Claims{
		Subject:   c.Subject,
		Audience:  aud,
		Resource:  c.Resource,
		Method:    c.Method,
		JTI:       c.ID,
		PayID:     c.PayID,
		ExpiresAt: expAt,
	}, nil
}

func Audience(method, resource string) string {
	return method + ":" + resource
}

func NewJTI() string { return uuid.NewString() }

func keyID(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub[:6])
}
