---
name: web-cache-poisoning
description: >
  Detect and exploit web cache poisoning and CPDoS. USE WHEN a response is cached
  (Age / X-Cache / CF-Cache-Status) and an unkeyed input — `X-Forwarded-Host`,
  `X-Forwarded-Scheme`, an unkeyed query/port, or a delimiter-cloaked param —
  reflects into the cached response, or when an oversized/meta-char/method-override
  request caches an error for all users. Covers unkeyed-header poisoning, fat-GET,
  parameter cloaking, cache-key normalization abuse, and CPDoS (HHO/HMC/HMO).
tags: [web, cache, poisoning, cpdos, unkeyed, infra]
tools: [httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Web Cache Deception/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/cache-deception/README.md", license: CC-BY-SA-4.0, credit: "HackTricks — Carlos Polop"}
verification:
  kind: differential
  expect: {signal: reflection}
  signals: ["X-Cache", "Age:", "hit", "evil", "X-Forwarded-Host"]
references:
  - https://portswigger.net/web-security/web-cache-poisoning
  - https://portswigger.net/research/practical-web-cache-poisoning
  - https://portswigger.net/research/gotta-cache-em-all
license: AGPL-3.0-or-later
version: 1.0.0
---

# Web Cache Poisoning / CPDoS

Get a malicious response stored in a shared cache under a key a *victim* will
request. The definitive oracle is **persistence**: a payload sent once must appear
in a subsequent **clean** request that carried no payload.

## Sub-variants
- **Unkeyed-header poisoning** — `X-Forwarded-Host`/`-Scheme` reflect into a
  cached body/redirect but aren't part of the cache key.
- **Unkeyed query / port / fat-GET** — a body/param on a GET that the origin uses
  but the cache ignores.
- **Cache-key normalization abuse / parameter cloaking** — delimiter/parser
  discrepancies (2024 "Gotta cache 'em all") let you slip an unkeyed param.
- **CPDoS** — HHO (oversized header), HMC (meta-char), HMO (method override): the
  origin errors, the cache stores the error → all users get a 400/redirect.

## Methodology (recon → probe → confirm → exploit → chain)

1. **Recon.** Identify a cache (`Age`, `X-Cache`, `CF-Cache-Status`,
   `Cache-Control`). Add a unique cache-buster so you don't pollute the shared key
   during probing.
2. **Probe (unkeyed inputs).** Send `X-Forwarded-Host: evil` (+ buster), then
   request the same URL twice; watch whether `evil` reflected into the response
   and whether the second (cached) hit still carries it. `fuzz` the unkeyed-header
   wordlist (Param-Miner-style); watch for reflection into body/redirect.
3. **Confirm (differential — primary, persistence oracle).** Send the payload,
   then fetch the URL **clean** (`req replay`, no payload) and `compare` against a
   pristine baseline. If the poison persists for the clean request, poisoning is
   proven — a clean request cannot spontaneously contain attacker bytes → 0-FP.
   `signature` backs this by matching the injected marker in the cached response.
4. **CPDoS.** Send an oversized/meta-char header the origin rejects; confirm the
   error is *cached* for a clean request (same persistence oracle on a 4xx).
5. **Exploit.** Poisoned `<script src>` (XSS), poisoned `Location` (redirect),
   poisoned host in links.

## Cross-chain notes
- + XSS (`web-xss`): poisoned `<script>`/resource served to every visitor.
- + open-redirect: poisoned `Location`.
- + host-header (`web-host-header`) / hop-by-hop (`web-hop-by-hop`): unkeyed
  forwarded headers are the injection vector.
- Smuggling → cache poisoning (`web-request-smuggling`): store via a desync.

## False-positive traps
- Reflection in *your own* payloaded response is not poisoning — confirmation is
  persistence into a **clean** request.
- Your cache-buster keying the response separately masks real poisoning; verify
  against the *shared* key, carefully.

## Key payload sources
- PortSwigger "Practical Web Cache Poisoning" + "Web Cache Entanglement" + "Gotta
  cache 'em all" — `references`. Param Miner (unkeyed input discovery);
  `vendor/PayloadsAllTheThings/`; HackTricks (path-only).

## Verification oracle
Primary `differential` (poison persists for a clean request); fallback `signature`
(marker in cached response) and `marker` (FTS for the injected token). `verify.py`
selects the strongest oracle the caller wired inputs for.
