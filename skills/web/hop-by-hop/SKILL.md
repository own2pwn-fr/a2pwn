---
name: web-hop-by-hop
description: >
  Detect and exploit hop-by-hop header abuse and proxy-header injection. USE WHEN
  a request traverses a proxy that honours `Connection: <header>` (stripping a
  security header before the back-end), or when `X-Forwarded-*` / `Forwarded` /
  `X-Real-IP` / `X-Original-URL` / `X-Rewrite-URL` change routing, access, rate
  limits or cache keys. Covers Connection-header stripping, Authorization/Cookie
  removal, proxy-header spoofing, and TE/Upgrade abuse.
tags: [web, headers, hop-by-hop, proxy, access-control, infra]
tools: [httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/CRLF Injection/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/abusing-hop-by-hop-headers.md", license: CC-BY-SA-4.0, credit: "HackTricks — Carlos Polop"}
verification:
  kind: differential
  expect: {signal: any}
  signals: ["Unauthorized", "Forbidden", "403", "401", "X-Forwarded-For"]
references:
  - https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers
  - https://portswigger.net/web-security/access-control
license: AGPL-3.0-or-later
version: 1.0.0
---

# Hop-by-Hop Header Injection / Abuse

A `Connection: X` request tells an intermediary to treat header `X` as
hop-by-hop and **strip it before the back-end**. If the back-end relies on that
header (`Authorization`, `Cookie`, a rate-limit token, a security marker), the
app's behaviour changes exploitably. Proxy headers (`X-Forwarded-*`,
`X-Original-URL`) additionally spoof identity and override routing.

## Sub-variants
- **Connection-header stripping** — `Connection: Authorization` drops auth before
  the origin; `Connection: Cookie` drops the session; strip a rate-limit header.
- **Proxy-header spoofing** — `X-Forwarded-For` / `X-Real-IP` IP spoof (bypass
  IP allowlists / rate limits); `X-Forwarded-Host`/`-Scheme` (feeds cache/host).
- **Routing override** — `X-Original-URL` / `X-Rewrite-URL` to reach `/admin`.
- **TE / Upgrade abuse** — stripping/injecting transfer/upgrade semantics.

## Methodology (recon → probe → confirm → exploit → chain)

1. **Recon.** Identify an intermediary (`Via`, `Server`, `X-Cache`) and a header
   the app depends on (auth, rate-limit, security marker).
2. **Probe.** `fuzz` a hop-by-hop wordlist as `Connection: X` for each candidate
   header; also test `X-Forwarded-For: 127.0.0.1` and `X-Original-URL: /admin`.
   `match-replace` can inject a header across every flow at once for scale.
3. **Confirm (differential — primary).** `compare` the baseline response to the
   response with the hop-by-hop / proxy header. A behavioural change — auth now
   dropped (401→different), rate-limit reset, access newly granted, or a changed
   cache key — proves the abuse. The `signature` oracle backs this by matching
   the auth-state string (`Unauthorized`/`403`) that flipped.
4. **Exploit.** Strip the security header the app relies on, then exploit the
   now-exposed sink; or spoof `X-Forwarded-For` to bypass IP rate limits / reach
   `/admin` via `X-Original-URL`.

## Cross-chain notes
- → Access-control bypass (`X-Original-URL`/`X-Rewrite-URL` to hidden endpoints).
- → Cache poisoning (`web-cache-poisoning`): unkeyed forwarded headers.
- → Host-header attacks (`web-host-header`): `X-Forwarded-Host`.

## False-positive traps
- A stripped header that changes nothing is not a finding — require a *behavioural
  differential* (access, rate-limit, or cache-key change), not mere reflection.
- WAF quirks: confirm with a clean-vs-injected `compare`, repeated.

## Key payload sources
- Nathan Davison "Abusing HTTP hop-by-hop request headers" — `references`.
- `vendor/PayloadsAllTheThings/CRLF Injection/` + header lists; HackTricks
  hop-by-hop (path-only); 403-bypass header wordlists.

## Verification oracle
Primary `differential` (behavioural change from the injected/stripped header);
fallback `signature` (auth-state string). `verify.py` selects the strongest oracle
the caller wired inputs for.
