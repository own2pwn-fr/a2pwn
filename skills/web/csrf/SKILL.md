---
name: web-csrf
description: >
  Detect and exploit Cross-Site Request Forgery. USE WHEN a state-changing request
  (change email/password, transfer funds, change role, update settings, delete)
  can be replayed from a cross-site context without an unpredictable, session-bound
  anti-CSRF token. Covers missing/optional tokens, tokens not tied to the session,
  missing SameSite cookie protection, method/content-type toggles, and JSON-CSRF
  where a simple request smuggles a JSON-ish body past CORS.
tags: [web, csrf, xsrf, session, samesite, owasp-a01, access-control]
tools: [httpx, nuclei]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/CSRF Injection/**/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/CSRF Injection/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: inline, inline: ["<form action=\"https://target.example/account/email\" method=POST><input name=email value=attacker@evil.example></form><script>document.forms[0].submit()</script>", "csrf_token=", "csrf_token=INVALID", "<img src=\"https://target.example/account/delete?confirm=1\">", "Content-Type: text/plain", "Content-Type: application/x-www-form-urlencoded", "{\"email\":\"attacker@evil.example\"}", "SameSite=None", "X-Requested-With: (removed)"], license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
verification:
  kind: state_change
  expect: {extract: server_side_value}
  signals:
    - "email"
    - "role"
    - "balance"
    - "updated"
references:
  - https://portswigger.net/web-security/csrf
  - https://owasp.org/www-community/attacks/csrf
  - https://portswigger.net/web-security/csrf/bypassing-token-validation
license: AGPL-3.0-or-later
version: 1.0.0
---
# CSRF — Cross-Site Request Forgery

Prove that a state-changing action executes when driven from an attacker-controlled
origin with **no valid anti-CSRF token**. The 0-FP discipline: a request that
returns `200` from a cross-site context proves nothing on its own — the app might
have silently rejected it. The oracle is a **semantic state change**: extract a
server-side value (victim's email, role, balance, setting) *before* the forged
action and *after*, and confirm it changed to the attacker's value without a token.
Detect broadly, confirm deterministically.

## Sub-variants
- **Missing token** — the state-changing request carries no anti-CSRF token at all.
- **Token not validated / optional** — supplying an empty or garbage token, or
  dropping the field entirely, still succeeds.
- **Token not bound to the session** — a token from another session (or a static/
  predictable token) is accepted, so the attacker can mint or reuse one.
- **Missing SameSite protection** — session cookie is `SameSite=None`/unset, so it
  rides cross-site POSTs/top-level GETs.
- **Method / Content-Type toggle** — protection enforced only on POST → try GET;
  or only on `application/json` → send `text/plain`/urlencoded (a *simple* request
  that dodges a CORS preflight).
- **JSON-CSRF** — the endpoint accepts a JSON body via a form with
  `enctype=text/plain` padding, so a cross-site form forges the JSON action.

## Methodology (recon → probe → confirm → exploit → chain)
1. **Recon.** `exec` capture the sensitive action as the victim identity; note the
   token field, the cookie's `SameSite` attribute, the method and Content-Type, and
   a **read endpoint** that reflects the value the action changes (profile/settings).
2. **Probe.** Replay the action with the token removed, blanked, or swapped for one
   minted in a different session; downgrade method/Content-Type; strip
   `X-Requested-With`. Keep only the ambient session cookie (the cross-site model).
3. **Confirm (deterministic).**
   - *State-change (primary, `verify.py` default):* read the target value **before**
     (e.g. `GET /account` → `email=victim@...`), issue the token-less forged action
     changing it to a marker (`attacker@evil.example`), then read **after**. The
     `state_change` oracle compares the extracted value before vs after and confirms
     only when it flipped to the attacker's value *and* no valid token was present.
     A cross-site `200` with the value unchanged is **rejected**.
   - Corroborate that the change was truly token-less: the successful flow must carry
     no session-bound token (removed/blanked/foreign), captured in the evidence batch.
4. **Exploit.** Build the minimal auto-submitting PoC (form + `document.forms[0]
   .submit()`, or `<img>` for GET) proving a victim's browser fires the action. For
   JSON-CSRF, pad with `enctype=text/plain` so the body parses server-side.
5. **Evasion.** Token tied to a double-submit cookie → check if the cookie is
   settable cross-site (subdomain, `SameSite=None`); Referer-only check → strip/spoof
   `Referer`; SameSite=Lax → use a top-level GET-based state change.

## Cross-chain notes
- CSRF on the OAuth callback (missing `state`) overlaps `web-authentication`.
- CSRF + stored/reflected XSS (`web-xss`) defeats token protection entirely (same-
  origin script reads the token) — note it but classify each finding distinctly.
- Cross-site cookie behaviour interacts with `web-cors` (credentialed cross-origin
  reads) — CSRF is *write*, CORS misconfig is *read*.

## False-positive traps
- A `200`/`302` from a cross-site request is **not** CSRF — the server may have
  ignored or rejected it silently. Only a confirmed *state change* counts.
- The action succeeding *with* a valid token present is expected behaviour, not a
  finding — the proof requires the token to be absent, blank, or foreign.
- A `SameSite=Lax` cookie blocks cross-site POST by default; a POST-only sensitive
  action may be effectively protected — verify with a real cross-site replay.
- Login CSRF / logout CSRF are low-impact unless they chain to something; judge the
  state change's actual security relevance.

## Key payload sources
- PortSwigger CSRF labs (token validation bypass, SameSite, method/Content-Type) —
  `references`.
- `vendor/PayloadsAllTheThings/CSRF Injection/` (auto-submit form PoCs, token-drop
  and swap cases, JSON-CSRF `text/plain` templates, SameSite notes).

## Verification oracle
Primary `state_change`: extract a server-side value (email / role / balance /
setting) before and after the token-less cross-site action and confirm it changed
to the attacker-chosen value, with the successful request carrying no valid
session-bound token. A bare `200` from a cross-site context, or a change made with
a valid token present, is rejected.
