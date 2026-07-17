---
name: recon-js-supplychain
description: >
  Recon the JS supply chain: de-bundle the app's JavaScript, identify the bundled
  libraries and versions, pull known CVEs, and PROVE the vulnerable path fires on
  the live site (version-match alone is not a finding). USE WHEN a target ships a
  webpack/Vite/Rollup SPA, exposes source maps, or loads third-party CDN scripts.
  Also harvests hidden API endpoints and leaked secrets from the bundle to seed
  every other class. Covers known-CVE deps, exposed source-maps, missing-SRI/CDN
  takeover, dependency-confusion, and DOM-clobbering-vulnerable runtimes.
tags: [recon, js, supply-chain, sca, cve, source-map, debundle]
tools: [webcrack, jsdebundle, httpx, curl]
payloads:
  - {kind: inline, inline: ["/static/js/*.js", "/assets/*.js", "*.js.map", "/main.*.js", "/vendor.*.js"], license: AGPL-3.0-or-later, credit: "a2pwn"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/pentesting-web-vulnerabilities-methodology.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: signature
references:
  - "https://osv.dev/"
  - "https://deps.dev/"
  - "https://github.com/RetireJS/retire.js"
license: AGPL-3.0-or-later
version: 1.0.0
---
# JS supply-chain — de-bundle → identify → CVE → **prove on the live site**

This skill seeds the whole engagement (hidden routes, secrets, gadgets) *and* is
itself a finding class when a bundled dependency’s vulnerable path is reachable.
The non-negotiable rule: **a version match is not a finding.** Confirm the
vulnerable code path fires on the live target, or that a leaked secret authorizes.

## Methodology
1. **Collect every JS asset.** Browse under `burpwn exec`; `req list --host <cdn>`
   / `req search '\.js'` gathers all scripts, decrypted (even over h2/CDN).
2. **De-bundle.**
   - **Source maps exposed** (`.map`, `sourceMappingURL`) → reconstruct the
     original tree (`exec unwebpack-sourcemap`/`sourcemapper`). Full source +
     often secrets.
   - **No maps** → split the webpack/Vite bundle into modules
     (`exec webcrack <bundle.js>` / `wakaru`).
3. **Identify libraries + versions.** Version banners, `package.json` fragments
   in maps, or AST fingerprint (Retire.js / library-detector) → `name@version`.
4. **Pull known CVEs.** Query OSV.dev / deps.dev / GitHub Advisory for each
   `name@version` (do this **outside** the sandbox — it’s not target traffic).
   Candidates: webpack CVE-2024-43788 (DOM-clobbering XSS), lodash proto-pollution,
   Vue CVE-2024-6783, Next.js SSR bugs, etc.
5. **PROVE on the live target (the oracle step).**
   - **Reachable gadget** (DOM-clobbering / proto-pollution) → drive it with the
     Playwright MCP and observe the real effect; chain to
     `web-prototype-pollution` / XSS. A gadget that fires OOB (SSRF/RCE) →
     in-sandbox listener callback.
   - **SSR/endpoint CVE** → probe the endpoint under `burpwn exec` and confirm the
     exploited behaviour in the response.
   - **Leaked secret** → `req replay` it against the live API; a `2xx` on a
     privileged endpoint validates the leak.
6. **Harvest for the rest of the engagement.** `req search` / grep the
   reconstructed source for hidden API routes (→ `web-access-control`), keys (→
   `web-jwt-auth`), and gadgets. This is the recon spine.

## Confirmation oracle (0-FP)
`verify.py` refuses to confirm on a version match. It confirms only when: an OOB
gadget callback carries the `correlation_id` (gadget fired), **or** a leaked
secret authorizes (`secret_flow` returns `2xx`), **or** an exploited-behaviour
marker (`signals`) appears in a live response flow. Otherwise it abstains with an
explicit “do NOT report” note.

## Cross-chain
- De-bundle → hidden endpoints/secrets → `web-access-control`, `web-jwt-auth`,
  `web-idor-bola`; universal gadgets → `web-prototype-pollution` / XSS.

## burpwn recipes
- `exec -- webcrack main.<hash>.js -o out/` — split the bundle in-session.
- `req search '<endpoint-or-key>'` — mine reconstructed source across all flows.
- `req replay <id> --set-header 'Authorization: Bearer <leaked>'` — validate a secret.

## False-positive traps
- **Version-match ≠ vulnerable.** The vulnerable function may be tree-shaken out
  or never reached with attacker input.
- A secret that is a public/publishable key (e.g. a Stripe *publishable* key,
  Firebase config) is expected client-side — not a leak.
- A CVE requiring a config the target doesn’t use is not applicable.
