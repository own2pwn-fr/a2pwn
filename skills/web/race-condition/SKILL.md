---
name: web-race-condition
description: >
  Detect and exploit race conditions / TOCTOU. USE WHEN a state-changing endpoint
  enforces a limit (apply coupon once, redeem gift card, withdraw balance, one
  OTP attempt) or two endpoints share state. Covers limit-overrun double-spend,
  multi-endpoint collisions, single-request->multi-object, partial-construction,
  rate-limit/OTP bypass, single-packet-attack (HTTP/2), and 0-RTT replay.
tags: [web, race-condition, toctou, single-packet-attack, business-logic, owasp-a04]
tools: [curl, httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Race Condition/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/race-condition.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: differential
references:
  - "https://portswigger.net/research/smashing-the-state-machine"
  - "https://portswigger.net/web-security/race-conditions"
license: AGPL-3.0-or-later
version: 1.0.0
---
# Race conditions — collapse the TOCTOU window

The finding is **more successful state changes than the limit allows**: a coupon
applied twice, a balance withdrawn concurrently, one OTP tried 500 times. The
proof is counting the successful responses in the burst.

## Preconditions / triggers
- A state-changing endpoint with a per-user/per-object limit, or two endpoints
  that read-then-write shared state.

## Methodology
1. **Pick the limited action.** Apply coupon, redeem, transfer, confirm — one
   whose success is normally capped (usually to 1).
2. **Fire the burst into one window.** Open a **dedicated workspace** for the
   batch (`exec --workspace race-coupon`) and send N identical requests timed to
   land together:
   - **Single-packet attack (HTTP/2, preferred):** ~20–30 requests in one TCP
     packet eliminates network jitter — run a turbo-intruder script under
     `burpwn exec` (still captured), or `fuzz run --concurrency 30 --delay 0`.
   - **Last-byte sync (HTTP/1.1):** hold back the final byte of each request,
     release together.
3. **Count successes.** `req list --workspace race-coupon` — if more than the
   allowed number returned `2xx/3xx` (coupon applied, balance changed), the limit
   was overrun. `compare` pre/post state to confirm the effect stuck.
4. **Multi-endpoint collision.** Race two *different* endpoints that share state
   (e.g. `add-to-cart` vs `checkout`) — the TOCTOU is between them.
5. **Rate-limit / OTP bypass.** Race the verification endpoint to exceed the
   attempt cap before the counter increments.

## Confirmation oracle (0-FP)
`verify.py` counts the successful (`2xx/3xx`) state-changing flows in the burst
workspace (`workspace_id`, optional `path` filter) and confirms only when the
count **exceeds** the intended limit (`expect_max`, default 1). A single success
— the normal outcome — is rejected.

## Cross-chain
- Race + IDOR (`web-idor-bola`) to double-act on another user’s object; race →
  auth (OTP/reset brute); race + business-logic; 0-RTT replay (HTTP/3).

## burpwn recipes
- `exec --workspace race-<slug> -- <turbo-intruder script>` — jitter-free
  single-packet burst, fully captured.
- `fuzz run --concurrency N --delay 0` — parallel burst for limit-overrun.
- `req list --workspace race-<slug>` + `compare` — count successes / confirm state.

## False-positive traps
- Idempotent endpoints (same result whether hit once or N times) are not
  exploitable even if all return `2xx`.
- N `2xx` that the server later reconciles/rolls back are not an overrun —
  confirm the *final* state exceeded the limit.
- Requires authorization: bursts are load; only run within scope.
