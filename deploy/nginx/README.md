# Integrating AgentGate into your existing nginx

AgentGate is a **forward-auth sidecar**: your existing nginx keeps terminating TLS and proxying to
your origin, and simply asks AgentGate (via `auth_request`) for a per-request decision —
**allow / require-payment(402) / deny**. You do **not** replace your reverse proxy.

```
client ──▶ [ your nginx ] ──auth_request──▶ AgentGate /authz
                │                              └─▶ 204 allow │ 401→402 pay │ 403 deny
                └──▶ origin app  (only on allow)
```

## Why `auth_request` needs the `error_page` trick

`auth_request` only reads the subrequest **status code** and **discards its body**. So `/authz`
cannot return the `402` + x402 JSON challenge directly (that would surface as a client `500`).
Instead `/authz` returns **`401`**, and `error_page 401 = @agentgate_challenge` re-enters a named
location that proxies to AgentGate's `/challenge`, whose genuine **402 + body + headers** are
forwarded to the agent verbatim. This is implemented in [`agentgate.conf`](agentgate.conf).
(If you can run **OpenResty**, the `access_by_lua_block` variant is cleaner — AgentGate returns the
full 402 and Lua relays it; see the **01 · System Architecture** design page in Notion, §4.)

## How the agent submits payment (no AgentGate URL exposed)

The agent pays by **re-issuing its original request to the resource it wants, carrying the signed
`X-PAYMENT` header** — exactly what stock x402 clients (`x402-fetch`, `x402-axios`) do. There is **no
public `/agentgate/verify` endpoint**; the gateway name never leaks to the client. The protected
location detects the header and internally routes the request to AgentGate's settle path:

```nginx
location / {
    ...
    if ($http_x_payment) { rewrite ^ /_agentgate_settle last; }   # pay path
    auth_request /authz;                                          # normal path
    ...
}
location = /_agentgate_settle {            # internal; clients get 404 if they hit it directly
    internal;
    proxy_pass http://agentgate/verify;
    proxy_method POST;
    proxy_set_header X-PAYMENT        $http_x_payment;
    proxy_set_header X-Original-URI   $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Original-Host  $host;
    ...
}
location /_agentgate_origin/ {             # internal; X-Accel-Redirect lands here on a paid 200
    internal;
    set $agt  $arg___agt;                  # capture the minted JWT from the redirect query
    set $args "";                          # drop it so the origin never sees the token
    rewrite ^/_agentgate_origin/(.*)$ /$1 break;
    proxy_pass http://backend_app;         # serve the real resource
    add_header X-AgentGate-Token $agt always;
}
```

On **success**, `/verify` (with `AGENTGATE_PAID_REDIRECT_PREFIX=/_agentgate_origin`) replies `200` with
`X-Accel-Redirect: /_agentgate_origin<resource>?__agt=<jwt>`; nginx then serves the **origin resource
itself** (200 + body) from an `internal` location that re-emits the JWT as `X-AgentGate-Token` and
strips `__agt` so the token never reaches your origin. The agent gets its data in one request and can
*optionally* ride that token on later requests. On **failure**, `/verify` returns `402/409/403`
verbatim (`X-Accel-Redirect` is emitted only on `200`), so error codes survive — which a plain
`auth_request` could not do (it collapses non-`2xx`/`401`/`403` into `500`).

This works in **stock nginx** (no OpenResty): `X-PAYMENT` rides a request **header** (so `auth_request`'s
body-discard is irrelevant), and `X-Accel-Redirect` is a core-module feature. If
`AGENTGATE_PAID_REDIRECT_PREFIX` is empty, `/verify` returns the token as JSON instead (for direct,
non-nginx callers).

## Staged rollout (do this in order)

1. **Merge the `http{}` blocks** from `agentgate.conf` (upstreams, `map`s, `log_format`, `real_ip`,
   `proxy_cache_path`). Run `nginx -t`.
2. **Shadow first.** Deploy server block #2 (mirror-based). nginx always serves the origin; AgentGate
   only *records* what it would decide. Watch analytics for false positives for a few days.
3. **Enforce one path.** Point a single priced `location` at the enforcing block #1. Never enable
   site-wide on day one.
4. **Expand** path-by-path as you gain confidence.

## Safety properties baked into the config

| Concern | How it's handled | Ref |
|---|---|---|
| Redis/AgentGate outage 503-ing free content | Public paths are matched **statically in nginx** and never call `/authz` | B9/D3 |
| Outage on paid paths | Fail-**closed** → `503 Retry-After` (never serve paid content free) | §10 |
| Cache serving one caller's ALLOW to another | Auth caching enabled **only** when a bearer token is present; class-conditional paths never cached | B7 |
| Spoofed client IP / fingerprint / decision headers | `set_real_ip_from` trusted CIDRs only; inbound `X-JA4`/`X-AgentGate-*` overwritten | B8 |
| Leaking the signed `X-PAYMENT` | `log_format agentgate_safe` omits `Authorization`/`X-PAYMENT` | B6/A9 |
| Exposing the gateway to clients | No public `/agentgate/*` route; payment is a transparent retry of the resource with `X-PAYMENT`, routed to an `internal` settle location | A9 |
| Broken traces across the auth hop | `traceparent` propagated into the subrequest | B5 |
| Browser/agent CORS preflight gated | `OPTIONS` short-circuited to `204` before `auth_request` | B11 |

## Things to check against YOUR existing nginx

- Duplicate `set_real_ip_from` / `real_ip_header` directives (yours may already set these — reconcile).
- An existing `error_page` handler for `401/403/5xx` on the same locations.
- An existing `proxy_cache_path` re-using the `agentgate_auth` keys_zone name.
- Your `auth_request` proxy timeout must be **longer** than AgentGate's internal request deadline
  (set AgentGate ≈ 70–80% of it) so AgentGate fails fast and nginx returns a definitive 402/503.

## Kill-switch

Runtime, no reload: set AgentGate `AGENTGATE_ENFORCE=false` → every `/authz` returns `204` (ALLOW).
Per-path disable: remove `auth_request` from the location and `nginx -s reload`.

> All directive choices and their rationale are in the
> **09 · Design Review & Resolved Decisions** design page in Notion, §B.
