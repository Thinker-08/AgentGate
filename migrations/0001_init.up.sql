CREATE TABLE IF NOT EXISTS policies (
    id              BIGSERIAL PRIMARY KEY,
    host            TEXT        NOT NULL,
    path_pattern    TEXT        NOT NULL,
    method          TEXT        NOT NULL DEFAULT '*',
    action          TEXT        NOT NULL CHECK (action IN ('allow','pay','deny')),
    price_atomic    BIGINT,
    network         TEXT        NOT NULL DEFAULT 'base-sepolia',
    asset           TEXT,
    pay_to          TEXT,
    grant_ttl_s     INTEGER     NOT NULL DEFAULT 120,
    grant_on        TEXT        NOT NULL DEFAULT 'settle' CHECK (grant_on IN ('verify','settle')),
    bot_class_rules JSONB,
    priority        INTEGER     NOT NULL DEFAULT 100,
    policy_version  BIGINT      NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_policies_lookup ON policies (host, method, priority);

CREATE TABLE IF NOT EXISTS payments (
    id             BIGSERIAL PRIMARY KEY,
    payer          TEXT        NOT NULL,
    nonce          TEXT        NOT NULL,
    resource       TEXT        NOT NULL,
    method         TEXT        NOT NULL,
    amount_atomic  BIGINT      NOT NULL,
    network        TEXT        NOT NULL,
    asset          TEXT        NOT NULL,
    valid_before   BIGINT      NOT NULL,
    status         TEXT        NOT NULL CHECK (status IN ('pending','verified','settled','failed')),
    tx_hash        TEXT,
    invalid_reason TEXT,
    challenge_id   TEXT,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    settled_at     TIMESTAMPTZ,
    UNIQUE (payer, nonce)
);

CREATE TABLE IF NOT EXISTS access_grants (
    id          BIGSERIAL PRIMARY KEY,
    jti         TEXT        NOT NULL UNIQUE,
    payer       TEXT        NOT NULL,
    resource    TEXT        NOT NULL,
    method      TEXT        NOT NULL,
    payment_id  BIGINT      NOT NULL REFERENCES payments(id),
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN     NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS idx_grants_active ON access_grants (payer, resource, method, expires_at) WHERE NOT revoked;

CREATE TABLE IF NOT EXISTS analytics_events (
    id           BIGSERIAL PRIMARY KEY,
    request_path TEXT        NOT NULL,
    agent_class  TEXT,
    operator     TEXT,
    decision     TEXT,
    ip_hash      TEXT,
    challenge_id TEXT,
    confidence   DOUBLE PRECISION,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_analytics_ts ON analytics_events (ts);
