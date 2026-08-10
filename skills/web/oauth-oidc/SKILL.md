---
name: web-oauth-oidc
description: >
  Attack OAuth 2.0 / OpenID Connect flows for account takeover. USE WHEN login goes
  through an authorization server (Google/Azure/Auth0/Keycloak/in-house) and the app
  exchanges a code or token. Covers redirect_uri validation bypass, missing/absent
  state (CSRF on the callback), code/token leakage via Referer, implicit-flow token
  swap, PKCE downgrade, id_token signature and audience confusion, and
  email-claim-based account linking.
tags: [web, oauth, oidc, sso, authentication, account-takeover, jwt, auth, redirect]
tools: [curl, httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/OAuth Misconfiguration/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
verification:
  kind: two_identity
references:
  - "https://portswigger.net/web-security/oauth"
  - "https://datatracker.ietf.org/doc/html/rfc6749#section-10"
  - "https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation"
license: AGPL-3.0-or-later
version: 1.0.0
---
# OAuth / OIDC — federated login as an attack surface

Federated login is where the interesting auth bugs migrated to, and it is the one
class that a purely unauthenticated crawl never reaches. Every step below needs at
least one working identity; declare identities in the engagement config and drive
them with `as_identity` rather than hand-copying tokens.

## Preconditions / triggers
- A redirect to `/authorize?client_id=…&redirect_uri=…&response_type=…`.
- A callback endpoint receiving `?code=` or `#access_token=`.
- An `id_token` (JWT) parsed by the application.

## Methodology

### 1. redirect_uri validation
Capture the legitimate authorization request, then replay it with a mutated
`redirect_uri`, one mutation at a time so you know which one the server accepted:
- suffix append: `https://app.example.com.attacker.tld`, `https://app.example.com@attacker.tld`
- path traversal within an allowed prefix: `https://app.example.com/callback/../../open-redirect?u=`
- subdomain wildcard abuse: `https://anything.app.example.com/`
- scheme/port swap, trailing-slash and case variance, encoded `%2f` / `%5c`
- localhost allowances left over from development

A server that issues a code to a redirect target you control is the finding. **Chain
it**: an in-scope open redirect on the allowed origin turns a "strict" allow-list
into a full leak — record the open redirect as an `enables` edge.

### 2. state / CSRF on the callback
Drop the `state` parameter entirely and replay the callback. If the app completes
the login, the attacker can force the victim's browser to link the ATTACKER's
provider account to the victim's session (or vice versa). Prove it as a
`state_change`: capture the account's linked-identities view before and after.

### 3. Code and token leakage
Look for the code/token surviving into places it must not: `Referer` on any
third-party asset loaded by the callback page, `window.name`, the browser history
via a 302 chain, or server logs echoed back. A code that is **reusable** (replay the
exchange twice and get two valid sessions) is a finding on its own.

### 4. id_token validation
The `jwt-auth` skill covers signature stripping (`alg: none`), key confusion and
`kid` injection — apply all of it here, plus the OIDC-specific checks:
- `aud` confusion: an id_token minted for a DIFFERENT client_id accepted by this app.
- `iss` not pinned: a token from an attacker-controlled issuer accepted.
- `email` / `email_verified`: an account linked purely on an `email` claim with
  `email_verified` unchecked is pre-auth account takeover of any known user.

### 5. PKCE downgrade
If the client uses PKCE, remove `code_challenge` from the authorization request and
`code_verifier` from the exchange. A server that still issues tokens has PKCE as
decoration, re-opening code interception.

## Oracle
- `two_identity` for the account-takeover outcome: identity A ends up holding
  identity B's session/data. Capture A-on-B, B-on-B, and the anonymous control.
- `state_change` for account linking / unlinking (`must_appear` the attacker's
  provider identifier in the victim's linked-accounts response).
- `differential` for redirect_uri acceptance: baseline (legitimate URI) vs mutated,
  comparing whether a code was issued.

## Pitfalls
- A 302 to your mutated `redirect_uri` is NOT proof unless a **code or token was
  actually issued to it**. An error redirect carrying `?error=invalid_request` is
  the server behaving correctly.
- Test the authorization server only insofar as it is IN SCOPE. A third-party IdP
  (Google, Microsoft) is someone else's system: attack the client's handling of the
  response, never the IdP itself.
