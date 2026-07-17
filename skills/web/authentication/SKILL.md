---
name: web-authentication
description: >
  Detect and exploit authentication weaknesses leading to account takeover. USE
  WHEN the target has login, registration, password-reset, MFA/OTP, or OAuth/OIDC
  flows. Covers password-reset poisoning (Host/X-Forwarded-Host header), username
  enumeration (response/timing differential), MFA/OTP bypass and brute-force,
  OAuth redirect_uri / state / implicit-flow flaws, and session fixation. Pairs
  with web-jwt-auth for token forgery.
tags: [web, authentication, account-takeover, oauth, mfa, session, owasp-a07]
tools: [httpx, nuclei, ffuf]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Account Takeover/**/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Account Takeover/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: inline, inline: ["Host: attacker.CID.OOBHOST", "X-Forwarded-Host: attacker.CID.OOBHOST", "X-Forwarded-For: 127.0.0.1", "redirect_uri=https://attacker.example/cb", "redirect_uri=https://target.example.attacker.example/cb", "response_type=token", "state=", "otp=000000", "email=victim@target.example&email=attacker@evil.example"], license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
verification:
  kind: differential
  expect: {signal: any, min_len_delta: 16}
  signals:
    - "No account found"
    - "already registered"
    - "Invalid password"
    - "reset link has been sent"
references:
  - https://portswigger.net/web-security/authentication
  - https://portswigger.net/web-security/oauth
  - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README
license: AGPL-3.0-or-later
version: 1.0.0
---
# Authentication weaknesses → account takeover

Prove a concrete auth break, not a hunch. The 0-FP discipline: the oracle is a
**deterministic differential** — access flips denied→accepted, an enumeration
response is measurably distinct (status/length/timing) between a valid and an
invalid identity, or a poisoned reset link lands an **OOB callback** on your host.
Detect broadly, confirm deterministically.

## Sub-variants
- **Password-reset poisoning** — inject `Host` / `X-Forwarded-Host` so the reset
  email's link points at your domain; the token leaks to your listener when the
  victim (or the mailer's link-preview) fetches it.
- **Username / account enumeration** — login, registration, or reset responses
  differ for valid vs invalid users (message text, status, length, or **timing**
  when a valid user triggers an expensive hash).
- **MFA / OTP bypass & brute-force** — missing rate limit on the OTP step,
  code reuse, response that leaks success before the code, or skipping the 2FA
  request entirely and hitting the post-auth endpoint.
- **OAuth / OIDC** — weak `redirect_uri` validation (suffix/subdomain/open-redirect
  chain) to steal the code/token; missing/replayable `state` (CSRF on the callback);
  implicit-flow token leak via `response_type=token`.
- **Session fixation** — the session id is not rotated on login, so a
  pre-seeded id survives authentication.

## Methodology (recon → probe → confirm → exploit → chain)
1. **Recon.** `exec` capture login, register, reset, MFA, and OAuth flows. Note
   which responses vary by identity and whether any rate limit exists.
2. **Probe.** Reset poisoning: replay the reset request with `Host`/
   `X-Forwarded-Host: attacker.<cid>.<oobhost>`. Enumeration: submit a known-valid
   vs a random user. OAuth: tamper `redirect_uri`/`state`. MFA: replay the OTP step
   past the intended attempt cap.
3. **Confirm (deterministic).**
   - *Differential (primary, `verify.py` default):* `compare` valid-vs-invalid
     identity responses (enumeration) — set `signal: body_change`/`length_delta`;
     or the privileged/post-auth endpoint flipping denied→accepted after the bypass
     — `signal: status_change`.
   - *Timing (fallback):* for timing-based enumeration, the `timing` oracle asserts
     the valid-user path is reliably slower past `threshold_ms` (expensive hash on
     hit) — use only with a stable baseline.
   - *OOB (fallback):* reset-poisoning proof — the `oob` oracle catches the reset
     link fetch carrying the correlation id on your host.
   - *Two-identity (fallback):* session fixation — hold a fixed id, authenticate,
     and confirm the *same* id now grants the victim's authenticated context.
4. **Exploit.** Poisoned reset → capture token → set new password → takeover.
   OAuth `redirect_uri` → exfiltrate `code`/`token` to your host → session as
   victim. Enumeration → targeted credential-stuffing / reset abuse.
5. **Evasion.** Rate limits → rotate IP headers (`X-Forwarded-For`), alias-batch
   (`web-graphql`), or race the OTP window (`web-race-condition`).

## Cross-chain notes
- Stolen OAuth token / forged claim → `web-jwt-auth`; enumerated users seed
  credential brute-force; taken-over account → `web-idor-bola` / `web-access-control`.
- Reset poisoning shares the tainted-`Host` primitive with `web-host-header`.
- OAuth callback CSRF (missing `state`) overlaps `web-csrf`.

## False-positive traps
- A login that returns `200` for both valid and invalid users is **not**
  enumeration — the differential must be stable and identity-driven, not random.
- Timing enumeration is fragile: network jitter mimics it. Require a repeatable,
  large delta or fall back to the response differential.
- A reset email "sent" message is not poisoning — you must prove the link points
  at *your* host (OOB callback), not merely that the header was reflected.
- An OAuth `redirect_uri` that is accepted but still lands on the legit app (no
  token leak to your host) is not exploitable.

## Key payload sources
- PortSwigger authentication & OAuth labs / OWASP WSTG auth — `references`.
- `vendor/PayloadsAllTheThings/Account Takeover/` (reset-poisoning headers,
  OAuth `redirect_uri`/`state` cases, OTP-bypass and enumeration notes).

## Verification oracle
Primary `differential` (access denied→accepted, or valid-vs-invalid enumeration
delta). Fallbacks: `timing` (user-enum via hash cost), `oob` (reset-link
poisoning callback), `two_identity` (session fixation). `verify.py` selects the
strongest oracle the caller wired inputs for; an ambiguous 200 is rejected.
