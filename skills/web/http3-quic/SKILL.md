---
name: web-http3-quic
description: >
  Detect and exploit HTTP/3 / QUIC connection contamination and downgrade desync.
  USE WHEN a target advertises h3 / alt-svc, when one QUIC/h3 connection is reused
  for multiple hosts (coalescing → requests routed to the wrong back-end / auth-
  context bleed), or when h3 falls back to h2/h1 where the real desync lives.
  Covers connection coalescing/contamination, h3→h2/h1 downgrade desync, 0-RTT
  early-data replay, and alt-svc-forced protocol confusion.
tags: [web, http3, quic, desync, coalescing, downgrade, infra]
tools: [httpx]
payloads:
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/http-request-smuggling/README.md", license: CC-BY-SA-4.0, credit: "HackTricks — Carlos Polop"}
verification:
  kind: differential
  expect: {signal: any}
  signals: ["wrong-host", "cross-host", "X-Served-By", "0-RTT", "early-data"]
references:
  - https://portswigger.net/research/http2
  - https://datatracker.ietf.org/doc/html/rfc9114
  - https://datatracker.ietf.org/doc/html/rfc9001
license: AGPL-3.0-or-later
version: 1.0.0
---

# HTTP/3 / QUIC Connection Contamination

When several hosts share one QUIC/h3 connection (same cert/IP), a request for
host A sent on host B's connection can be routed to the wrong back-end — leaking
auth context or bypassing host-based routing. Where h3 is unavailable, the target
downgrades to h2/h1 and the classic desync surface reappears.

## Sub-variants
- **Connection coalescing / contamination** — one QUIC/h3 conn serves multiple
  authorities; a swapped `:authority`/Host cross-routes to another back-end.
- **h3→h2/h1 downgrade desync** — the fallback path carries the real smuggling.
- **0-RTT early-data replay** — resend an early-data request → double-processing.
- **alt-svc-forced protocol confusion** — steer the client's protocol choice.

## Methodology (recon → probe → confirm → exploit → chain)

1. **Recon.** Detect `alt-svc`/h3 advertisement. Note burpwn's sandbox
   **fail-fast QUIC egress**: h3 is *downgraded*, so you observe the h1/h2 fallback
   (h3-downgrade metadata in capture) — that fallback is where most exploitable
   desync lives.
2. **Probe coalescing.** Same cert/IP for multiple hosts → send a host-A request
   over host-B's connection with a swapped `:authority`/`Host` (`req replay`).
3. **Confirm (differential — primary).** `compare` the response served for the
   swapped host against the response the correct host returns. A body/route served
   for the *wrong* host proves cross-routing → 0-FP. Fallback `signature`
   (a `X-Served-By`/back-end marker for the wrong host).
4. **0-RTT.** Resend an early-data request; confirm double-processing (chain with
   race / logic).

## Cross-chain notes
- Contamination → host-header attacks (`web-host-header`): auth-context bleed.
- Downgrade path → `web-http2-desync` / `web-request-smuggling`.
- 0-RTT replay → race conditions.

## False-positive traps
- The sandbox downgrades QUIC — a "no h3" result is a *capture limitation*, not
  "target not vulnerable"; report `blocked` and test the fallback path.
- A shared cert alone is not contamination — require a response served for the
  wrong host.

## Key payload sources
- PortSwigger h2/h3 research; QUIC/h3 desync writeups; Cloudflare/Akamai 2025
  desync CVEs — `references`. HackTricks smuggling (path-only).

## Verification oracle
Primary `differential` (cross-host response bleed); fallback `signature`
(wrong-host back-end marker). `verify.py` selects the strongest oracle the caller
wired inputs for.
