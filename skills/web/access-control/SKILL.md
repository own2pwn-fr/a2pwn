---
name: web-access-control
description: >
  Detect and exploit broken access control / authorization (the cross-chain
  engine). USE WHEN a privileged action, admin route, or state change is reachable
  by a lower-privileged or anonymous identity. Covers vertical priv-esc, forced
  browsing, X-Original-URL/X-Rewrite-URL override, verb tampering, path/case/
  normalization bypass, referer trust, multi-step flow skipping, mass-assignment
  role escalation, GraphQL field-level auth, and front-end-only enforcement.
tags: [web, access-control, authorization, bfla, 403-bypass, owasp-a01, auth]
tools: [curl, httpx, ffuf]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Account Takeover/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Insecure Direct Object References/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/403-and-401-bypasses.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: two_identity
  signals: ["\"role\":\"admin\"", "isAdmin", "dashboard"]
references:
  - "https://portswigger.net/web-security/access-control"
  - "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"
license: AGPL-3.0-or-later
version: 1.0.0
---
# Broken access control — the authorization matrix

This is the **cross-chain engine**: it reuses every other primitive (IDOR,
host-header, hop-by-hop headers, JWT role, smuggling) to reach an action the
current identity should not perform. The test is a matrix: *for each privileged
action × each identity, is it allowed?*

## Preconditions / triggers
- Any admin/privileged endpoint, or a state change gated by role/ownership.
- A route inventory (from `req list` + de-bundled JS revealing hidden endpoints).

## Methodology
1. **Build the route map.** `req list` gives every captured endpoint; feed it
   with hidden routes recovered from de-bundled JS (`recon-js-supplychain`) and
   `recon-content-discovery`. This is the set of actions to test.
2. **Replay each privileged action as a lesser identity.** `session auth` swap
   to a low-priv / anonymous session and `req replay` the action. `compare`
   allowed-vs-denied. A `2xx` with privileged content served to the lesser
   identity = **vertical priv-esc**.
3. **Header-override bypass.** Add `X-Original-URL: /admin`, `X-Rewrite-URL`,
   `X-Forwarded-For: 127.0.0.1`, `X-Forwarded-Host` — front-ends that route on
   these skip the gate (chain hop-by-hop / host-header primitives).
4. **Verb tampering.** The gate may cover `GET` but not `POST`/`PUT`/`PATCH`/
   `DELETE`/`HEAD`. Replay the action with each method.
5. **Path/normalization fuzz.** `/admin` → `/Admin`, `/admin/`, `/admin/.`,
   `/admin%2f`, `/%2e/admin`, `/admin;/`, trailing `..;/`. `fuzz` the 403-bypass
   wordlist, anomaly-ranked.
6. **Multi-step skip.** Jump straight to the `confirm`/`finalize` endpoint,
   skipping the `authorize` step the UI enforces.
7. **Mass-assignment / front-end-only.** The API may expose fields/actions the UI
   hides; add `role`/`isAdmin` (compose `web-idor-bola`), or call the API route
   directly.

## Confirmation oracle (0-FP)
`verify.py` prefers the **two-identity** oracle (privileged response reproduced
for the unprivileged identity — needs `a_ref`/`b_ref`). Where only a single
anonymous flow exists, it confirms only when that flow is `2xx` **and** the body
carries privileged markers (`role:admin`, `dashboard`, admin-only content) — a
`403` page that merely contains the word “admin” is rejected.

## Cross-chain
- Horizontal case = `web-idor-bola`; JWT `role` forge = `web-jwt-auth`;
  `X-Original-URL` = hop-by-hop; `Host: localhost` = host-header; front-end auth
  skipped via request smuggling. This skill orchestrates all of them.

## burpwn recipes
- `session auth` multi-identity + `req replay` + `compare` = the authZ matrix.
- `match-replace` to inject an override header (`X-Original-URL`) across all flows.
- `fuzz run --payloads 403bypass.txt` on protected paths; `tag add`/`note add`
  to seal a confirmed bypass batch.

## False-positive traps
- A `2xx` returning the same content the lesser identity already sees ≠ priv-esc.
- A 200 “access denied” body (soft-403) is not access — check the body, not just
  the status.
- Debug/dev endpoints intentionally open are not findings without impact.
