---
name: web-jwt-auth
description: >
  Detect and exploit JWT / token authentication flaws. USE WHEN the app carries a
  JWT (three base64url segments) in a cookie/Authorization header, or an OAuth/OIDC
  flow. Covers alg:none, RS256->HS256 algorithm confusion, jwk/jku/x5u header
  injection, kid injection (path-traversal/SQLi/command), weak-HMAC crack, missing
  exp/nbf/aud checks, claim tampering (role/sub/admin), non-invalidated logout,
  and OAuth redirect_uri / PKCE / state issues.
tags: [web, jwt, authentication, oauth, oidc, owasp-a07, auth]
tools: [curl, httpx, hashcat]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/JSON Web Token/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/hacking-jwt-json-web-tokens.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: differential
  signals: ["\"alg\":\"none\"", "\"alg\":\"HS256\""]
references:
  - "https://portswigger.net/web-security/jwt"
  - "https://portswigger.net/web-security/jwt/algorithm-confusion"
license: AGPL-3.0-or-later
version: 1.0.0
---
# JWT / authentication flaws — forge a token the server accepts

The whole class reduces to one oracle: **a token you minted grants access that
the un-forged/anonymous request does not.** Everything below is a way to mint
that token; the confirmation is always the privileged endpoint flipping from
`401/403` to `2xx`.

## Preconditions / triggers
- A value that `decode jwt` parses into `{header, payload, signature}`.
- Auth decisions that read a JWT claim (`role`, `sub`, `admin`, `scope`).
- A JWKS endpoint (`/.well-known/jwks.json`, `/jwks`), or `jku`/`kid` in the header.

## Methodology
1. **Read it.** `decode jwt <token>` (burpwn native) → note `alg`, `kid`, `jku`,
   `jwk`, and the claims. Establish the **baseline denial**: `req replay` the
   privileged endpoint with a stripped/low-priv token and record the `401/403`.
2. **alg:none.** Rebuild the token with header `{"alg":"none"}`, tamper a claim
   (`"role":"admin"`), drop the signature (keep the trailing dot). `req replay`
   with it. Accepted `2xx` = broken.
3. **RS256 → HS256 confusion.** Fetch the RSA **public** key (JWKS, TLS cert, or
   `/pem`). Re-sign the token with `HS256` using the public key *bytes* as the
   HMAC secret. If the server verifies HS256 with the same key material, it
   accepts your forgery. (`encode`/a small script under `burpwn exec`.)
4. **jwk / jku / x5u injection.** Embed your own `jwk`, or point `jku`/`x5u` at a
   JWKS you host — the **in-sandbox listener** (`burpwn exec -- python -m
   a2pwn._oob_listener`) captures the server’s fetch as a `dns`/`rawtcp` flow,
   proving the header is trusted. Test allowlist bypasses on `jku`
   (`https://trusted.com.evil.example`, open-redirect off a trusted host).
5. **kid injection.** `kid` often indexes a key file or a DB row → try
   path-traversal (`../../../../dev/null` → empty/known key), SQLi, and command
   injection in `kid`. Cross-chain into `web-path-traversal-lfi` / SQLi.
6. **Weak HMAC.** `exec hashcat -m 16500 token.txt wordlist` — a cracked secret
   lets you sign arbitrary claims.
7. **Lifecycle.** Replay a token after logout / past `exp`; tamper `aud`/`nbf`.
   A still-accepted stale token is a finding on its own.

## Confirmation oracle (0-FP)
`verify.py` runs the **denied→accepted differential**: it requires the baseline
flow to be `401/403` and the forged-token flow to be `2xx/3xx` on the same
privileged endpoint. If only the forged flow is supplied it confirms on a `2xx`
but flags the weaker signal. `jku`/`x5u` trust is additionally provable via the
OOB oracle (the server’s JWKS fetch reaching the in-sandbox listener).

## Cross-chain
- `kid` SQLi → SQL injection; `jku`/`x5u` → SSRF; token stolen via XSS
  (`web-cors`/XSS) → replay here; forged `role` claim → `web-access-control`.

## burpwn recipes
- `decode jwt <token>` / `encode` — read and re-craft segments.
- `req replay <id> --set-header 'Authorization: Bearer <forged>'` — swap the token.
- `session auth set/refresh` — automate re-auth and diff privileged access.
- in-sandbox listener + `req list --protocol dns|rawtcp` — prove `jku`/`x5u` fetch.

## False-positive traps
- A `2xx` that returns the **same** public/unauth content is not priv-esc — the
  baseline must have been denied. Verify the response actually contains
  privileged data, not a generic 200 landing page.
- `alg:none` accepted by a *client-side* decoder only ≠ server trust.
