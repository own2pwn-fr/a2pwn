---
name: web-prototype-pollution
description: >
  Detect and exploit prototype pollution (server-side SSPP and client-side CSPP).
  USE WHEN a JSON body or query is deep-merged / Object.assign'd into an object,
  or client JS merges attacker-controlled data into Object.prototype. Covers
  __proto__ and constructor.prototype vectors, response-formatting SSPP oracle,
  gadget-to-RCE/SSRF (child_process opts), and CSPP source->prototype->DOM-XSS.
tags: [web, prototype-pollution, sspp, cspp, nodejs, owasp-a03, injection]
tools: [curl, httpx, webcrack]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Prototype Pollution/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/deserialization/nodejs-proto-prototype-pollution/README.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: differential
  signals: ["__proto__", "constructor"]
references:
  - "https://portswigger.net/web-security/prototype-pollution"
  - "https://portswigger.net/research/server-side-prototype-pollution"
license: AGPL-3.0-or-later
version: 1.0.0
---
# Prototype pollution — pollute a global, observe the gadget

Pollution alone is invisible; you confirm it by making a **polluted global change
observable server-side behaviour** (the SSPP differential) or by driving a
**gadget** to RCE/SSRF/DOM-XSS. A reflected `__proto__` that changes nothing is
not a finding.

## Preconditions / triggers
- A JSON endpoint whose body is deep-merged (`_.merge`, `_.defaultsDeep`,
  `Object.assign`, `$.extend(true,...)`, custom recursive merge).
- Client JS that merges `location`/`postMessage`/JSON into an object.

## Methodology (server-side, SSPP)
1. **Baseline.** Capture a normal request/response pair (this is `flow_a`).
2. **Pollute + observe.** Inject `{"__proto__":{"<prop>":"<val>"}}` and the
   filter-bypass twin `{"constructor":{"prototype":{"<prop>":"<val>"}}}`. Use
   PortSwigger’s **response-reformatting probe**: pollute a property the JSON
   serialiser honours (e.g. `{"__proto__":{"json spaces":10}}` reformats the
   response with indentation; `{"__proto__":{"status":510}}` may change the
   status). Capture this as `flow_b`.
3. **Differential.** `compare <flow_a> <flow_b>` — a status change, a body
   reformat (length delta from added whitespace), or new/echoed properties = the
   **SSPP oracle**. This is a real global mutation, not mere reflection.
4. **Gadget hunt.** Look for a polluted property that reaches a sink:
   `child_process` `exec`/`spawn` `shell`/`env`/`NODE_OPTIONS` (→ RCE), a
   template option (→ SSTI), or an HTTP client option (→ SSRF, confirm via the
   OOB oracle / in-sandbox listener).

## Methodology (client-side, CSPP)
1. Pull the JS (`recon-js-supplychain`), find source → `Object.prototype` → sink.
2. Inject via URL/`postMessage`/hash and drive with Playwright MCP; a gadget that
   reaches `innerHTML`/`src`/`Function` → DOM-XSS (compose XSS).

## Confirmation oracle (0-FP)
`verify.py` runs the **differential** oracle between the baseline (`flow_a`) and
the polluted (`flow_b`) response — confirmed on a status change, a body
reformat, or a length delta. When a gadget produces an out-of-band callback
(RCE/SSRF), it uses the **OOB** oracle (`collab` + `correlation_id`) instead.
Version-match on a known-vulnerable library is **not** confirmation.

## Cross-chain
- SSPP → RCE / SSRF (`web-deserialization`-style gadgets, class SSRF); CSPP →
  DOM-XSS; universal gadgets from de-bundled deps (`recon-js-supplychain`).

## burpwn recipes
- `req replay <id> --set-body '{"__proto__":{"json spaces":10}}'` then `compare`
  against baseline = the SSPP oracle.
- `fuzz` the pollution-vector set (`__proto__[x]`, `constructor.prototype.x`).
- in-sandbox listener + `req list --protocol dns|rawtcp` for a SSRF gadget.

## False-positive traps
- `__proto__` echoed in the response with **no** behaviour change ≠ pollution.
- A framework that safely stores `__proto__` as an own-property key is not polluted.
- Library CVE match without a reachable, attacker-driven merge is not confirmed.
