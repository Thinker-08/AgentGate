#!/usr/bin/env bash
set -uo pipefail

BASE="${BASE:-http://localhost:8088}"
PAYTO="${PAYTO:-0x209693Bc6afc0C5328bA36FaF03C514EF312287C}"
NET="${NET:-base-sepolia}"
PASS=0
FAIL=0

note() { printf "\n\033[1m%s\033[0m\n" "$1"; }
ok()   { printf "  \033[32mPASS\033[0m %s\n" "$1"; PASS=$((PASS+1)); }
bad()  { printf "  \033[31mFAIL\033[0m %s\n" "$1"; FAIL=$((FAIL+1)); }

code() { curl -s -o /dev/null -w "%{http_code}" "$@"; }

build_payment() {
  local value="$1" payto="$2" net="$3"
  python3 - "$value" "$payto" "$net" <<'PY'
import base64, json, sys, time, secrets
value, payto, net = sys.argv[1], sys.argv[2], sys.argv[3]
now = int(time.time())
payload = {
  "x402Version": 1, "scheme": "exact", "network": net,
  "payload": {
    "signature": "0x" + secrets.token_hex(65),
    "authorization": {
      "from": "0x" + secrets.token_hex(20),
      "to": payto,
      "value": value,
      "validAfter": str(now - 10),
      "validBefore": str(now + 300),
      "nonce": "0x" + secrets.token_hex(32),
    },
  },
}
print(base64.b64encode(json.dumps(payload).encode()).decode())
PY
}

note "1) public path is allowed without auth"
c=$(code "$BASE/public/info")
[ "$c" = "200" ] && ok "GET /public/info -> 200" || bad "GET /public/info -> $c (want 200)"

note "2) blocked path is denied"
c=$(code "$BASE/blocked/secret")
[ "$c" = "403" ] && ok "GET /blocked/secret -> 403" || bad "GET /blocked/secret -> $c (want 403)"

note "3) protected path returns 402 x402 challenge"
chal=$(curl -s -D - -o /tmp/ag_chal.json "$BASE/premium/report")
c=$(printf "%s" "$chal" | awk 'NR==1{print $2}')
[ "$c" = "402" ] && ok "GET /premium/report -> 402" || bad "GET /premium/report -> $c (want 402)"
if grep -q '"maxAmountRequired"' /tmp/ag_chal.json && grep -q '"x402Version"' /tmp/ag_chal.json; then
  ok "402 body is a valid x402 challenge"
  echo "    challenge: $(cat /tmp/ag_chal.json)"
else
  bad "402 body missing x402 fields"; cat /tmp/ag_chal.json
fi

note "4) pay via X-PAYMENT on the resource -> receive the RESOURCE itself + token header"
XPAY=$(build_payment "10000" "$PAYTO" "$NET")
hdr=$(curl -s -D - -o /tmp/ag_paid_body "$BASE/premium/report" -H "X-PAYMENT: $XPAY")
pc=$(printf "%s" "$hdr" | awk 'NR==1{print $2}')
TOKEN=$(printf "%s" "$hdr" | tr -d '\r' | awk 'tolower($1)=="x-agentgate-token:"{print $2}')
echo "    paid response body: $(cat /tmp/ag_paid_body)"
if [ "$pc" = "200" ] && grep -q '"upstream":"demo"' /tmp/ag_paid_body; then
  ok "GET /premium/report (X-PAYMENT) -> 200 + origin content"
else
  bad "paid retry did not return origin content (HTTP $pc)"
fi
[ -n "$TOKEN" ] && ok "paid response carries X-AgentGate-Token (fast-path JWT)" || bad "no X-AgentGate-Token on paid response"

note "5) access granted with token"
if [ -n "$TOKEN" ]; then
  c=$(code -H "Authorization: Bearer $TOKEN" "$BASE/premium/report")
  [ "$c" = "200" ] && ok "GET /premium/report (with token) -> 200" || bad "GET /premium/report (with token) -> $c (want 200)"
else
  bad "skipped grant check (no token)"
fi

note "6) replayed payment is rejected (409)"
c=$(code "$BASE/premium/report" -H "X-PAYMENT: $XPAY")
[ "$c" = "409" ] && ok "replayed X-PAYMENT -> 409" || bad "replayed X-PAYMENT -> $c (want 409)"

note "7) underpayment is rejected (402)"
XLOW=$(build_payment "1" "$PAYTO" "$NET")
c=$(code "$BASE/premium/report" -H "X-PAYMENT: $XLOW")
[ "$c" = "402" ] && ok "underpayment -> 402" || bad "underpayment -> $c (want 402)"

note "8) wrong pay_to is rejected (403 requirements mismatch)"
XBAD=$(build_payment "10000" "0x0000000000000000000000000000000000000001" "$NET")
c=$(code "$BASE/premium/report" -H "X-PAYMENT: $XBAD")
[ "$c" = "403" ] && ok "wrong pay_to -> 403" || bad "wrong pay_to -> $c (want 403)"

printf "\n\033[1mRESULT: %d passed, %d failed\033[0m\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
