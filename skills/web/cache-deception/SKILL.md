---
name: web-cache-deception
description: >
  Detect and exploit web cache deception. USE WHEN an authenticated dynamic page
  returns secrets and a cache can be tricked into storing that private response
  under a URL an attacker can fetch — via a static-extension suffix
  (`/account.php/x.css`), a path delimiter (`;`, `%2F`, `%3F`, `%23`, `//`), or a
  front-end/origin path-normalization discrepancy. Covers static-extension
  confusion, delimiter/path-parameter confusion, and encoded-dot/slash tricks.
tags: [web, cache, deception, normalization, delimiter, infra]
tools: [httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Web Cache Deception/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/cache-deception/README.md", license: CC-BY-SA-4.0, credit: "HackTricks — Carlos Polop"}
verification:
  kind: differential
  expect: {signal: any}
  signals: ["email", "csrf", "api_key", "apiKey", "X-Cache", "Set-Cookie"]
references:
  - https://portswigger.net/web-security/web-cache-deception
  - https://portswigger.net/research/gotta-cache-em-all
license: AGPL-3.0-or-later
version: 1.0.0
---

# Web Cache Deception

Trick a cache into storing a *victim's* private, authenticated response under a
URL the attacker can then fetch **unauthenticated**. The confirmation oracle:
fetch that URL with no session and receive the victim's private data.

## Sub-variants
- **Static-extension confusion** — `/account.php/nonexistent.css`: origin serves
  the dynamic page; the cache keys on the `.css` and stores it.
- **Path-parameter / delimiter confusion** — `;`, `%2F`, `%3F`, `%23`, `//`
  between the real path and a cacheable suffix.
- **Path-normalization discrepancy** — front-end vs origin parse the path
  differently (2024 "Gotta cache 'em all" delimiter methodology).
- **Encoded-dot / encoded-slash** tricks to smuggle the suffix past the origin.

## Methodology (recon → probe → confirm → exploit → chain)

1. **Recon.** Find an authenticated dynamic page that returns secrets (profile,
   API key, CSRF token). Hold the victim session via `session auth`.
2. **Probe.** Append cache-triggering suffixes/delimiters
   (`/account/x.css`, `/account;x.css`, `/account%2Fx.css`). Map the delimiter set
   the **origin ignores** but the **cache keys on** — `fuzz` the delimiter list.
3. **Confirm (differential — primary).** As the victim, request the crafted URL
   (populates the cache), then fetch the **same URL with no session cookie**
   (`req replay` stripping auth) and `compare` to the authed response. If the
   unauthenticated fetch returns the victim's private body, deception is proven —
   an anonymous request receiving another user's data is unambiguous → 0-FP.
   `signature` backs it by matching a private marker (`email`, `csrf`, `api_key`).
4. **Exploit.** Harvest the cached private data (tokens/API keys) → account
   takeover.

## Cross-chain notes
- → token/API-key theft → authentication / access-control compromise.
- Shares the front-end/origin path-normalization discrepancy with
  `web-cache-poisoning` and access-control normalization bypasses.

## False-positive traps
- A cached *public* page is not deception — the stored response must be the
  *victim's private* content.
- Some caches strip `Set-Cookie`/`Cache-Control: private` — verify the anonymous
  fetch actually returns private fields, not a login redirect.

## Key payload sources
- PortSwigger "Web cache deception" + "Gotta cache 'em all" (delimiter tables) —
  `references`. `vendor/PayloadsAllTheThings/Web Cache Deception/`; HackTricks
  cache deception (path-only).

## Verification oracle
Primary `differential` (unauthenticated fetch returns the victim's private
response); fallback `signature` (private marker in the cached copy). `verify.py`
selects the strongest oracle the caller wired inputs for.
