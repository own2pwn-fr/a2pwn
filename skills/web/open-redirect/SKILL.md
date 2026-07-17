---
name: web-open-redirect
description: >
  Detect and exploit open redirects (a chaining primitive). USE WHEN a parameter
  or header controls a redirect target (?next=, ?url=, ?returnTo=, redirect_uri,
  Location). Covers parameter/header/JS-based redirects, protocol-relative //evil,
  whitelist bypasses (trusted@evil.com, trusted.evil.com, \/\/, %2f%2f, unicode),
  data:/javascript: -> XSS, and OAuth redirect_uri token theft.
tags: [web, open-redirect, redirect, oauth, chaining, owasp-a01]
tools: [curl, httpx, ffuf]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Open Redirect/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/open-redirect.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: signature
  signals: ["location:"]
references:
  - "https://portswigger.net/web-security/dom-based/open-redirection"
  - "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
license: AGPL-3.0-or-later
version: 1.0.0
---
# Open redirect — get the app to send the user to *your* host

Confirmation is a **3xx whose `Location` (or a JS redirect) resolves to an
attacker-controlled host**. Open redirect is rarely the prize itself; it’s a
chaining primitive for OAuth token theft, SSRF, and XSS.

## Preconditions / triggers
- A param/header that steers a redirect: `?next=`, `?url=`, `?returnTo=`,
  `?dest=`, `redirect_uri`, or a reflected `Location`.

## Methodology
1. **Inventory redirects.** `req search` for redirect-param names and capture the
   `3xx` flows (`req list --status 302`).
2. **Fuzz the target.** `fuzz` the parameter with a bypass wordlist and inspect
   the resulting `Location`:
   - absolute `https://evil.example`
   - protocol-relative `//evil.example`
   - userinfo trick `https://trusted.com@evil.example`
   - subdomain trick `https://trusted.com.evil.example`
   - backslash/encoded `https:/\evil.example`, `%2f%2fevil.example`, `\/\/evil.example`
   - unicode/whitespace normalization tricks
3. **Confirm the destination host.** `req show`/`compare` the `Location` header;
   the effective authority must be attacker-controlled (parse past `@`, resolve
   `//`). A `3xx` that still points at the trusted host is not a finding.
4. **JS/DOM redirect.** When redirection is client-side (`location = ...`), pull
   the JS and drive Playwright MCP (`browser_navigate` → observe the final URL).
5. **Escalate (chain).** `javascript:`/`data:` targets → XSS; `redirect_uri` in an
   OAuth flow → deliver the `code`/token to the attacker host (`web-jwt-auth`);
   a server that *follows* the redirect → SSRF; poisoned `Location` in a cached
   response → cache poisoning.

## Confirmation oracle (0-FP)
`verify.py` parses the response `Location` header, resolves the effective host
(handling `//`, `@`, encoded slashes), and confirms only when the status is a
redirect (`301/302/303/307/308`) **and** that host equals (or is a subdomain of)
the attacker host. When there is no `Location` header it falls back to a JS-redirect
check in the body. A redirect that stays on-site is rejected.

## Cross-chain
- Open redirect ↔ XSS (`javascript:`/`data:`), ↔ OAuth token theft
  (`web-jwt-auth`), ↔ SSRF (server-follows), ↔ cache-poisoned redirect, ↔ JWT
  `jku` allowlist bypass.

## burpwn recipes
- `fuzz run --flow <id> --position <redirect-value> --payloads openredirect.txt`.
- `req show <id>` / `compare <a> <b>` — read and diff the `Location`.
- Playwright MCP for JS/DOM redirects.

## False-positive traps
- A `3xx` back to the same origin/host is safe.
- A redirect that URL-encodes/strips the attacker host before use is not exploitable.
- Reflected-in-body-only (no navigation) needs the Playwright check to count.
