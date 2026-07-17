---
name: web-host-header
description: >
  Detect and exploit HTTP Host-header attacks. USE WHEN the app trusts the Host /
  X-Forwarded-Host to build links, redirects or cache keys, when a password-reset
  link embeds the Host, when the front-end routes by Host to internal vhosts, or
  when `Host: localhost`/`127.0.0.1` reaches an admin surface. Covers password-
  reset poisoning, routing-based SSRF, cache-key/cache-poisoning via Host, Host
  auth bypass, and X-Forwarded-Host / absolute-URI / duplicate-Host tricks.
tags: [web, host-header, routing, ssrf, cache, access-control, infra]
tools: [httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Web Cache Deception/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/http-request-smuggling/README.md", license: CC-BY-SA-4.0, credit: "HackTricks — Carlos Polop"}
verification:
  kind: marker
  expect: {}
  signals: ["evil", "attacker.com", "collaborator", "Location:", "reset"]
references:
  - https://portswigger.net/web-security/host-header
  - https://portswigger.net/web-security/host-header/exploiting
license: AGPL-3.0-or-later
version: 1.0.0
---

# Host-Header Attacks

The app trusts the client-controlled `Host` (or `X-Forwarded-Host`) to build
absolute links, redirects, reset URLs or routing decisions. Tamper it and the
trust leaks: a poisoned reset link, a request routed to an internal vhost, a
cache keyed to an attacker host, or an admin surface reached via `Host: localhost`.

## Sub-variants
- **Password-reset poisoning** — reset email link built from the tampered Host →
  victim clicks → token to attacker.
- **Routing-based SSRF** — `Host: internal-service` reaches an internal vhost.
- **Cache-poisoning via Host** — Host reflected into a cached response/redirect.
- **Auth bypass** — `Host: localhost`/`127.0.0.1` unlocks `/admin`.
- **Injection variants** — `X-Forwarded-Host`, `X-Host`, absolute-URI request
  line, duplicate `Host` headers, `Host: victim:@evil`.
- **Virtual-host brute** — discover internal apps behind the same IP.

## Methodology (recon → probe → confirm → exploit → chain)

1. **Recon.** Capture flows; note where the Host appears in bodies, links,
   redirects (`req search <host>`), and whether a reset/cache path exists.
2. **Probe.** `req replay --set-header 'Host: evil.<cid>'` (and the
   `X-Forwarded-Host` variant); `match-replace host` rewrites Host wholesale for
   scale. For reset poisoning, trigger the reset with the tampered Host.
3. **Confirm (deterministic).**
   - *Reflection (primary):* the `marker` oracle — `req_search` the injected host
     token across decrypted history; a hit in a link/redirect/reset body proves
     the Host is trusted into output.
   - *Behavioural:* the `differential` oracle — `compare` baseline vs
     tampered-Host response for a changed `Location`/link/access decision.
   - *Routing SSRF:* the `oob` oracle — a `Host: <collaborator>` that causes a
     callback (`dns`/`http`) confirms routing to an attacker-influenced host.
   - `signature` backs reflection by matching `evil`/`Location:` markers.
4. **Exploit.** Password-reset ATO (link to attacker host), internal-vhost SSRF,
   cached poisoned redirect, `Host: localhost` admin bypass.

## Cross-chain notes
- → Cache poisoning (`web-cache-poisoning`): Host reflected into cache.
- → SSRF (`web-ssrf`): routing-based Host SSRF.
- → password-reset ATO → authentication / access-control.
- Fed by hop-by-hop `X-Forwarded-Host` (`web-hop-by-hop`) and h3 coalescing
  (`web-http3-quic`).

## False-positive traps
- Host reflected into a *non-security* context (a debug echo) is not exploitation
  — require it in a link/redirect/reset the victim will use, or a behavioural change.
- Many stacks normalise Host to a fixed canonical value — confirm the *tampered*
  value actually survived (`req search`), not the canonical one.

## Key payload sources
- PortSwigger "Host header attacks" academy — `references`.
- `vendor/PayloadsAllTheThings/` Host-header lists; HackTricks host-header
  (path-only).

## Verification oracle
Primary `marker` (injected host reflected into a link/redirect/reset across
history); fallbacks `differential` (behavioural change), `oob` (routing-SSRF
callback), `signature` (host marker). `verify.py` selects the strongest oracle the
caller wired inputs for.
