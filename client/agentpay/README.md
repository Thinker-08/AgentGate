# agentpay — x402 paying-agent client

`agentpay` is the **buyer side** of the x402 flow: a standalone Go tool that produces a real,
cryptographically valid `X-PAYMENT` so AgentGate can be exercised end-to-end against the live
Base Sepolia facilitator (not just the mock verifier).

It is a **separate Go module** (its own `go.mod`) so that `go-ethereum` never enters the
AgentGate sidecar's dependency graph. The root `go build ./...` does not descend into it.

## What it does

1. `GET {base}{resource}` and parse the **402 x402 challenge** (network, asset, payTo, price, `extra.{name,version}`).
2. Build an **EIP-3009 `TransferWithAuthorization`** and sign it with the payer key (**EIP-712**),
   using the domain `{name, version, chainId, verifyingContract}` derived from the challenge.
3. Assemble the v1 `PaymentPayload`, base64-encode it, and **re-request the same resource**
   (`{method} {base}{resource}`) carrying it in the `X-PAYMENT` header. This is stock x402 client
   behaviour — the agent pays by retrying the resource it wants, not by calling any AgentGate URL.
   On success the response is **the resource itself** (`200` + body); the reusable access token comes
   back in the **`X-AgentGate-Token`** response header (and the settlement in `X-PAYMENT-RESPONSE`).
4. Print the resource body, the issued token, and the on-chain settlement (`transaction` hash).
5. Optionally re-request the resource with `Authorization: Bearer <token>` to confirm the fast path
   (`200` without paying again).

The payer wallet needs **USDC only — no ETH**: EIP-3009 is gasless, the facilitator relays the
transfer and pays gas. The `payTo` address does not need to be funded.

## Usage

```bash
# from the repo root
AGENTPAY_PRIVATE_KEY=0x<payer-key> make pay

# or directly, with flags
cd client/agentpay
go run . -key 0x<payer-key> -base http://localhost:8088 -resource /premium/report
```

| flag / env | default | meaning |
|---|---|---|
| `-key` / `AGENTPAY_PRIVATE_KEY` | — (required) | payer private key hex |
| `-base` / `AGENTPAY_BASE` | `http://localhost:8088` | gateway base URL |
| `-resource` / `AGENTPAY_RESOURCE` | `/premium/report` | protected path to pay for |
| `-method` / `AGENTPAY_METHOD` | `GET` | HTTP method |
| `-chain-id` | `0` (derive from network) | override EVM chain id |
| `-window` | `0` (use challenge `maxTimeoutSeconds`) | authorization validity window, seconds |
| `-access` | `true` | after paying, retry the resource with the token |

## Security

The private key is read from a flag or env var and is never written to disk. Use a throwaway
testnet wallet. Do not commit keys.
