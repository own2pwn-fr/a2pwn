---
name: web-ssti
description: >
  Detect and exploit Server-Side Template Injection. USE WHEN a parameter is
  rendered by a server-side template and arithmetic/expression payloads evaluate
  (`{{7*7}}`→49, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`), when a reflection looks like
  XSS but math renders, or when user input reaches an email/PDF/filename template.
  Covers Jinja2 / Twig / Freemarker / Velocity / ERB / Handlebars / Pug / Go
  text-template / Razor, reflected + blind, and sandbox-escape → RCE.
tags: [web, injection, ssti, rce, owasp-a03, server-side]
tools: [httpx, nuclei]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Server Side Template Injection/Intruder/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Server Side Template Injection/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/ssti-server-side-template-injection/README.md", license: CC-BY-SA-4.0, credit: "HackTricks — Carlos Polop"}
verification:
  kind: differential
  expect: {signal: reflection, marker: "49"}
  signals: ["49", "uid=", "gid=", "root:x:0:0", "1337", "7777777"]
references:
  - https://portswigger.net/web-security/server-side-template-injection
  - https://portswigger.net/research/server-side-template-injection
license: AGPL-3.0-or-later
version: 1.0.0
---

# SSTI — Server-Side Template Injection

Prove that input is *evaluated* by a server-side template engine — not merely
reflected. The differentiator from XSS: `{{7*7}}` renders `49`. From there,
walk engine-specific gadget chains to RCE.

## Sub-variants
- **Per-engine** — Jinja2 (`{{}}`), Twig (`{{}}`), Freemarker (`${}`), Velocity
  (`#set`), ERB (`<%= %>`), Handlebars, Pug, Mustache (logic-less — limited),
  Go `text/template`, Razor (`@`).
- **Reflected vs blind** — blind SSTI confirmed via an OOB engine gadget.
- **Sandbox-escape → RCE** — Jinja `{{cycler.__init__.__globals__.os.popen}}`,
  Freemarker `freemarker.template.utility.Execute`, Velocity `Runtime.exec`.
- **Indirect sinks** — template rendered in an email body, PDF export, generated
  filename, or report — injection point and render point differ.

## Methodology (recon → probe → confirm → exploit → chain)

1. **Recon / probe.** Inject the polyglot `${{<%[%'"}}%\` — a syntax error or a
   render anomaly (`fuzz` + `compare`) flags a template context.
2. **Fingerprint engine (arithmetic differential).** Send `{{7*7}}`, `${7*7}`,
   `#{7*7}`, `<%= 7*7 %>` in a pitchfork; whichever yields **`49`** identifies the
   engine. `compare` the payloaded vs literal (`{{7*'7'}}` distinguishes Jinja=`49`
   from Twig=`7777777`). This is the confirmation oracle — a literal `7*7` string
   can't become `49` without evaluation → 0-FP.
3. **Confirm (deterministic).** Primary: the `differential` oracle with
   `marker="49"` (or the engine-specific expected value) proves evaluation.
   Fallback: the `signature` oracle matches the rendered value / RCE output
   (`uid=`, `root:x:0:0`). Blind: the `oob` oracle via the engine's HTTP/DNS gadget.
4. **Exploit.** Walk the engine's escalation to RCE; capture `id`/`whoami` output
   verbatim in `req show --raw`. Bypass sandboxes with the documented gadget for
   the fingerprinted engine.

## Cross-chain notes
- SSTI hides behind XSS-looking reflection — **always test `49` before concluding
  "just XSS"** (see `web-xss`).
- SSTI → RCE → SSRF pivot to cloud metadata (see `web-ssrf`).
- SSTI in email/reset templates → chain with host-header / account takeover.

## False-positive traps
- Reflection of the literal `{{7*7}}` string (unrendered) is NOT SSTI — require
  the evaluated value.
- `49` appearing coincidentally: use a unique product (e.g. `{{1337*7}}`=`9359`)
  the caller wires into `expect.marker`.

## Key payload sources
- PortSwigger SSTI research + academy — `references`.
- `vendor/PayloadsAllTheThings/Server Side Template Injection/` (per-engine
  detection + RCE); tplmap payloads; HackTricks SSTI (path-only).

## Verification oracle
Primary `differential` (arithmetic render, `marker="49"`); fallbacks `signature`
(rendered value / RCE output) and `oob` (blind engine gadget). `verify.py` selects
the strongest oracle the caller wired inputs for.
