package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mihiragrawal/agentgate/internal/core"
)

type Postgres struct {
	pool *pgxpool.Pool
}

func NewPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 10
	cfg.MinConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &Postgres{pool: pool}, nil
}

func (p *Postgres) Close() { p.pool.Close() }

func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

func (p *Postgres) GetPolicies(ctx context.Context) ([]core.Policy, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, host, path_pattern, method, action,
		       COALESCE(price_atomic,0), network, COALESCE(asset,''), COALESCE(pay_to,''),
		       grant_ttl_s, grant_on, priority, policy_version, bot_class_rules
		FROM policies`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []core.Policy
	for rows.Next() {
		var pol core.Policy
		var grantTTLs int
		var action, grantOn string
		var rules []byte
		if err := rows.Scan(&pol.ID, &pol.Host, &pol.PathPattern, &pol.Method, &action,
			&pol.PriceAtomic, &pol.Network, &pol.Asset, &pol.PayTo,
			&grantTTLs, &grantOn, &pol.Priority, &pol.Version, &rules); err != nil {
			return nil, err
		}
		pol.Action = core.Action(action)
		pol.GrantOn = core.GrantOn(grantOn)
		pol.GrantTTL = time.Duration(grantTTLs) * time.Second
		if len(rules) > 0 {
			m := map[string]string{}
			if err := json.Unmarshal(rules, &m); err == nil {
				bcr := make(map[string]core.Action, len(m))
				for k, v := range m {
					bcr[k] = core.Action(v)
				}
				pol.BotClassRules = bcr
			}
		}
		out = append(out, pol)
	}
	return out, rows.Err()
}

func (p *Postgres) InsertPaymentClaim(ctx context.Context, pay core.Payment) (core.Payment, bool, error) {
	var id int64
	err := p.pool.QueryRow(ctx, `
		INSERT INTO payments (payer, nonce, resource, method, amount_atomic, network, asset, valid_before, status, challenge_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9)
		ON CONFLICT (payer, nonce) DO NOTHING
		RETURNING id`,
		pay.Payer, pay.Nonce, pay.Resource, pay.Method, pay.AmountAtomic, pay.Network, pay.Asset, pay.ValidBefore, pay.ChallengeID,
	).Scan(&id)
	if err == nil {
		pay.ID = id
		pay.Status = core.PaymentPending
		return pay, true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return core.Payment{}, false, err
	}

	var existing core.Payment
	var status, txHash string
	err = p.pool.QueryRow(ctx, `
		SELECT id, payer, nonce, resource, method, amount_atomic, network, asset, valid_before, status, COALESCE(tx_hash,'')
		FROM payments WHERE payer=$1 AND nonce=$2`,
		pay.Payer, pay.Nonce,
	).Scan(&existing.ID, &existing.Payer, &existing.Nonce, &existing.Resource, &existing.Method,
		&existing.AmountAtomic, &existing.Network, &existing.Asset, &existing.ValidBefore, &status, &txHash)
	if err != nil {
		return core.Payment{}, false, err
	}
	existing.Status = core.PaymentStatus(status)
	existing.TxHash = txHash
	return existing, false, nil
}

func (p *Postgres) UpdatePaymentSettled(ctx context.Context, id int64, txHash string) error {
	_, err := p.pool.Exec(ctx, `UPDATE payments SET status='settled', tx_hash=$2, settled_at=now() WHERE id=$1`, id, txHash)
	return err
}

func (p *Postgres) UpdatePaymentFailed(ctx context.Context, id int64, reason string) error {
	_, err := p.pool.Exec(ctx, `UPDATE payments SET status='failed', invalid_reason=$2 WHERE id=$1`, id, reason)
	return err
}

func (p *Postgres) SaveGrant(ctx context.Context, g core.AccessGrant) error {
	_, err := p.pool.Exec(ctx, `
		INSERT INTO access_grants (jti, payer, resource, method, payment_id, issued_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		g.JTI, g.Payer, g.Resource, g.Method, g.PaymentID, g.IssuedAt, g.ExpiresAt)
	return err
}

func (p *Postgres) InsertAnalytics(ctx context.Context, evs []core.Event) error {
	if len(evs) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, e := range evs {
		b.Queue(`INSERT INTO analytics_events (request_path, agent_class, operator, decision, ip_hash, challenge_id, confidence, ts)
		         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			e.RequestPath, e.AgentClass, e.Operator, e.Decision, e.IPHash, e.ChallengeID, e.Confidence, e.Ts)
	}
	br := p.pool.SendBatch(ctx, b)
	defer br.Close()
	for range evs {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}
