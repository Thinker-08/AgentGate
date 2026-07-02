# AgentGate

AI-agent monetization gateway using x402 payments, deployed as a **forward-auth sidecar** behind your existing **nginx / OpenResty** reverse proxy. nginx asks AgentGate for a per-request decision — **allow / require-payment (402) / deny** — and after an agent pays via x402, AgentGate issues a short-lived signed JWT so subsequent requests are allowed until it expires.

This is the **Phase-1 MVP** (Mock verifier by default, real x402 verifier scaffolded).

## Quickstart

```bash
cp .env.example .env        # optional; compose sets its own env
make up                     # build + start: nginx gateway, agentgate, postgres, redis, demo upstream
make e2e                    # prove the live allow -> 402 -> pay(mock) -> grant flow
make logs                   # tail agentgate logs
make down                   # tear down
```

The gateway listens on `http://localhost:8088`. Try it by hand:

```bash
curl -i localhost:8088/public/info                 # 200  (public, no auth)
curl -i localhost:8088/blocked/x                    # 403  (denied by policy)
curl -i localhost:8088/premium/report               # 402  + x402 challenge JSON
# pay (mock): re-request the SAME resource with the signed X-PAYMENT header.
# nginx routes any X-PAYMENT request to AgentGate internally; on success it returns
# the RESOURCE itself (200 + body) plus a reusable JWT in the X-AgentGate-Token
# response header. No AgentGate-specific URL is ever exposed.
curl -i localhost:8088/premium/report -H "X-PAYMENT: <base64 x402 payload>"   # 200 + content
# optional fast path: ride that token on later requests instead of paying again:
curl -i localhost:8088/premium/report -H "Authorization: Bearer <token-from-X-AgentGate-Token>"   # 200
```

`test/e2e.sh` does all of this automatically (including replay, underpayment, and wrong-pay_to rejection).

## How it works

```
client ─▶ nginx (auth_request) ─▶ AgentGate /authz ─▶ 204 allow | 401 pay | 403 deny
                │  on 401: error_page 401 = @challenge ─▶ AgentGate /challenge ─▶ 402 + x402 JSON
                │  agent pays: re-requests the resource w/ X-PAYMENT ─▶ nginx routes to verify+settle
                │             ─▶ on success X-Accel-Redirect serves the ORIGIN resource (200 + body)
                │                + reusable JWT in X-AgentGate-Token; on failure 402/409/403
                └─▶ upstream origin (when allowed, or after a successful paid retry)
```

- **Detection** (`internal/detector`) classifies callers (human / search_crawler / ai_agent / automation / unknown), cross-checks UA claims against published operator **IP ranges** (a UA claiming Googlebot from a non-Google IP is treated as a spoof, never "verified"), reads an optional **JA4** from the edge, and never lets forgeable browser signals produce a confident "human" verdict.
- **Policy** (`internal/policy`) matches path globs by priority and supports per-class carve-outs (e.g. verified search crawlers get `allow` on a paid path for SEO).
- **Payment** (`internal/payment`) is a pluggable `PaymentVerifier`: `MockVerifier` (default, enforces the same local checks as the real one) and `X402Verifier` (EIP-3009 / USDC on Base via an x402 facilitator). Replay is keyed on `sha256(payer|nonce)` only; grant is issued **after settle**.
- **Access** (`internal/token`, `internal/store`) issues EdDSA JWTs scoped to `METHOD:resource` with `exp` clamped inside the EIP-3009 `validBefore`; the durable `payments` table (UNIQUE `(payer, nonce)`) is the financial source of truth.

## Configuration

All via `AGENTGATE_*` env vars — see [`.env.example`](.env.example). Key ones:

| Var | Default | Notes |
|---|---|---|
| `AGENTGATE_VERIFIER` | `mock` | `mock` or `x402` |
| `AGENTGATE_NETWORK` | `base-sepolia` | x402 network |
| `AGENTGATE_PAY_TO` | demo addr | merchant receiving address |
| `AGENTGATE_FACILITATOR_URL` | `https://x402.org/facilitator` | used when `verifier=x402` |
| `AGENTGATE_EDGE_SECRET` | empty | shared secret nginx injects (`X-AgentGate-Edge`); enforces the trusted-edge boundary |
| `AGENTGATE_ENFORCE` | `true` | runtime kill-switch; `false` => /authz always allows |
| `AGENTGATE_TOKEN_TTL` | `120s` | grant lifetime (clamped inside `validBefore`) |

Policies live in the `policies` table (seeded from [`deploy/docker/seed.sql`](deploy/docker/seed.sql)): `/public/*` allow, `/premium/*` & `/research/*` pay, `/blocked/*` deny.

## Switching to real x402

Set `AGENTGATE_VERIFIER=x402`, `AGENTGATE_NETWORK=base-sepolia`, a real `AGENTGATE_PAY_TO` wallet, and (Base Sepolia) keep `AGENTGATE_FACILITATOR_URL=https://x402.org/facilitator`. AgentGate will then call the facilitator's `/verify` and `/settle` instead of the mock. Get testnet USDC from a Base Sepolia faucet.

## Integrating with YOUR nginx

`deploy/nginx/agentgate.conf` is the documented drop-in for an existing nginx (staged shadow → enforce rollout, static public-path fail-open, secret-free logging, CORS). `deploy/nginx/compose-nginx.conf` is the concrete config the demo stack uses. See [`deploy/nginx/README.md`](deploy/nginx/README.md).

## Layout

```
cmd/agentgate        entrypoint + wiring
internal/core        shared types + interfaces (the contract)
internal/detector    agent detection (UA, IP-range verify, JA4, behavioral)
internal/policy      path/class policy engine
internal/payment     PaymentVerifier: mock + x402, requirements + validation
internal/token       EdDSA JWT issuer/verifier
internal/store       postgres (durable) + redis (replay/denylist/rate/counter)
internal/analytics   async, droppable telemetry sink
internal/server      chi router, /authz /challenge /verify, middleware
internal/observability  zap logger + prometheus metrics
migrations           canonical schema
deploy/              Dockerfile, nginx configs, demo upstream, seed
```
