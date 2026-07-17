---
name: web-request-smuggling
description: >
  Detect and exploit HTTP/1.1 request smuggling / desync between a front-end and
  back-end that disagree on message length. USE WHEN a request path traverses a
  reverse proxy / CDN / load-balancer, when a crafted Content-Length vs
  Transfer-Encoding request stalls the socket, or when a follow-up request gets a
  foreign prefix. Covers CL.TE, TE.CL, TE.TE, CL.CL, 0.CL / CL.0 (2025 desync
  endgame), client-side desync, and H2→H1 downgrade smuggling.
tags: [web, smuggling, desync, http1, proxy, infra]
tools: [httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Request Smuggling/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/http-request-smuggling/README.md", license: CC-BY-SA-4.0, credit: "HackTricks — Carlos Polop"}
verification:
  kind: differential
  expect: {signal: any}
  signals: ["GPOST", "Unrecognized method", "400 Bad Request", "421 Misdirected Request"]
references:
  - https://portswigger.net/web-security/request-smuggling
  - https://portswigger.net/research/http1-must-die
  - https://http1mustdie.com
license: AGPL-3.0-or-later
version: 1.0.0
---

# HTTP Request Smuggling / Desync (HTTP/1.1)

Front-end and back-end disagree on where one request ends and the next begins.
The smuggled prefix then poisons the *next* visitor's request. **Raw-byte control
is mandatory** — hand-build CL/TE-malformed requests and send them via
`fuzz run --request <raw>` / `intercept` (crafted CRLF and header framing that a
normal client library would "fix").

## Sub-variants
- **CL.TE** — front-end uses Content-Length, back-end uses Transfer-Encoding.
- **TE.CL** — the reverse.
- **TE.TE** — both support TE but one is fooled by obfuscation
  (`Transfer-Encoding: chunked\r\nTransfer-Encoding: x`, ` chunked`, tab tricks).
- **CL.CL** — duplicate Content-Length disagreement.
- **0.CL / CL.0** — front-end treats CL as 0 (or implicit 0), back-end reads a
  body as a new request (James Kettle 2025 "HTTP/1.1 must die"; CVE-2025-4366
  Cloudflare Pingora, CVE-2025-32094 Akamai).
- **Client-side / browser-powered desync** — victim's own browser sends the
  poisoning request.
- **H2→H1 downgrade** — smuggle CL/TE inside an h2 request the h1 back-end mis-reads
  (see `web-http2-desync`).

## Methodology (recon → probe → confirm → exploit → chain)

1. **Recon.** Confirm a multi-tier path (proxy/CDN via `Server`/`Via`/`X-Cache`).
   Note the target protocol (`req list --protocol h1`).
2. **Probe (timing).** Send a TE.CL/CL.TE probe that *stalls* the socket if a
   desync exists (the back-end waits for bytes that never arrive). `fuzz run
   --request /tmp/base.raw` with a hand-built raw request; the `timing` oracle
   flags the stall.
3. **Confirm (differential — primary).** The "socket poisoning" test: send the
   smuggling request, then a benign follow-up (`req replay`); `compare` the
   follow-up's response against a clean baseline. If your smuggled prefix (e.g.
   `GPOST` → "Unrecognized method GPOST") appears in the *victim/baseline*
   response, the desync is proven. A prefix landing in another request cannot be
   a coincidence → 0-FP.
4. **Exploit.** Prefix a request that captures the next visitor's headers/cookies
   (store to a controlled endpoint), poison the cache, or bypass front-end
   auth/access-control.

## Cross-chain notes
- Smuggling → cache poisoning (`web-cache-poisoning`): store a malicious response.
- Smuggling → access-control bypass (front-end auth skipped on the smuggled req).
- Smuggling → credential/session capture → auth compromise.
- H2/H3 downgrade variants: `web-http2-desync`, `web-http3-quic`.

## False-positive traps
- A single 400/timeout is not proof — a normal malformed request also errors.
  Confirmation is the **prefix appearing in a foreign/baseline response**.
- Retries/keep-alive noise: repeat the poison→victim differential to rule out
  connection reuse artefacts.

## Key payload sources
- PortSwigger "HTTP Desync Attacks" + "HTTP/1.1 must die" — `references`.
- `vendor/PayloadsAllTheThings/Request Smuggling/`; smuggler.py / HTTP Request
  Smuggler; HackTricks smuggling (path-only).

## Verification oracle
Primary `differential` (smuggled prefix in a foreign/baseline response); fallback
`timing` (socket stall) and `signature` (prefix error string). `verify.py` selects
the strongest oracle the caller wired inputs for.
