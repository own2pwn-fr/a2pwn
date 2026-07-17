---
name: web-cors
description: >
  Detect and exploit CORS misconfiguration that allows credentialed cross-origin
  reads. USE WHEN an authenticated JSON/API endpoint echoes an attacker-supplied
  Origin into Access-Control-Allow-Origin while Access-Control-Allow-Credentials
  is true, trusts the `null` origin, or trusts a sibling/regex-weak subdomain.
  Covers reflected-origin+creds, null-origin, subdomain/regex bypass, pre-flight
  and insecure-http trust, and Vary:Origin cache interplay.
tags: [web, cors, sop, cross-origin, owasp-a05, client]
tools: [httpx, curl]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/CORS Misconfiguration/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/cors-bypass.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: signature
  signals: ["access-control-allow-credentials: true", "access-control-allow-origin: null"]
references:
  - "https://portswigger.net/web-security/cors"
  - "https://portswigger.net/web-security/cors/access-control-allow-origin"
license: AGPL-3.0-or-later
version: 1.0.0
---
# CORS misconfiguration — credentialed cross-origin read

CORS only matters when it lets an *attacker origin* read a *credentialed*
response. `Access-Control-Allow-Origin: *` **without** credentials is not this
skill — browsers refuse to send cookies to a wildcard. The exploitable shape is
a server that **reflects the request `Origin`** into `ACAO` (or trusts `null`)
**and** sets `Access-Control-Allow-Credentials: true`.

## Preconditions / triggers
- An endpoint that returns per-user secrets (profile, API keys, tokens, cart).
- A response that carries `Access-Control-Allow-Origin` at all (grep captures).
- Cookie/`Authorization`-based auth (so credentials ride cross-origin).

## Methodology
1. **Inventory ACAO endpoints.** Browse the app under `burpwn exec`, then
   `req search "access-control-allow-origin"` to list every endpoint that speaks
   CORS. Prioritise ones whose bodies hold secrets.
2. **Reflection probe.** `req replay <id> --set-header 'Origin: https://evil.example'`
   on an authenticated flow. Read the response headers with `req show <newid>`:
   - `ACAO: https://evil.example` + `ACAC: true` → **reflected-origin exploit**.
   - `ACAO: null` + `ACAC: true` → **null-origin exploit** (reachable from a
     sandboxed iframe / `data:`/`about:blank` document).
3. **Regex/subdomain fuzz.** When the server does not reflect verbatim, `fuzz`
   an origin wordlist to find the trust rule’s edges:
   `https://evil-victim.com`, `https://victim.com.evil.com`,
   `https://victim.com%60.evil.com`, `https://sub.victim.com` (any XSS-able
   subdomain becomes a pivot), and insecure `http://victim.com`. `compare` the
   ACAO header against baseline to isolate which pattern is accepted.
4. **Pre-flight path.** For non-simple requests, confirm the `OPTIONS`
   pre-flight also reflects the origin and allows the method/headers you need;
   some servers only botch the simple-request path.
5. **Prove exploitability.** A reflected header is not a finding until a real
   cross-origin `fetch(url,{credentials:'include'})` from the attacker origin
   returns the victim body. Drive that with the Playwright MCP (`browser_navigate`
   to a PoC page → `browser_evaluate` the fetch → read the secret) so the oracle
   sees the credentialed read actually succeed.

## Confirmation oracle (0-FP)
`verify.py` inspects the replayed flow’s response headers and confirms **only**
when the attacker origin is reflected into `ACAO` (or `null` is allowed) **and**
`ACAC: true`. Wildcard-without-credentials and echoed-but-uncredentialed origins
are rejected — they cannot exfiltrate a logged-in user’s data.

## Cross-chain
- CORS on a **trusted subdomain** you also have **XSS** on (class web-xss) →
  same-site read with no Origin gate.
- CORS read of a session/JWT bearer → **auth takeover** (`web-jwt-auth`).
- `Vary: Origin` mishandled by a cache → poison the CORS headers for all users
  (compose with cache-poisoning).

## burpwn recipes
- `req replay <id> --set-header 'Origin: https://evil.example'` — the core probe.
- `fuzz run --flow <id> --position <Origin-value> --payloads origins.txt` — sweep
  the trust regex; results anomaly-ranked by header/length delta.
- `req show <id>` — read `ACAO`/`ACAC` verbatim; `compare <a> <b>` isolates the
  accepted pattern. `session auth` keeps credentials live so the creds path is
  actually testable.

## False-positive traps
- `ACAO: *` alone → **not** exploitable (no credentials). Do not report.
- ACAO reflected but `ACAC` absent/false → no cookie exfil; downgrade to info.
- A dev CORS proxy or public, unauthenticated endpoint has nothing to steal.
