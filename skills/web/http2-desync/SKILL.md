---
name: web-http2-desync
description: >
  Detect and exploit HTTP/2 desync and H2→H1 downgrade smuggling. USE WHEN a
  target speaks h2 to the edge but an HTTP/1.1 back-end recomputes message length,
  when h2 header/pseudo-header values accept CRLF that h1 must escape, or when the
  h2 message-length is ambiguous. Covers H2.CL / H2.TE downgrade smuggling,
  pseudo-header (`:path`/`:authority`) CRLF injection, request splitting, and
  connection-preface confusion.
tags: [web, smuggling, desync, http2, h2, downgrade, infra]
tools: [httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Request Smuggling/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/http-request-smuggling/README.md", license: CC-BY-SA-4.0, credit: "HackTricks — Carlos Polop"}
verification:
  kind: differential
  expect: {signal: any}
  signals: ["GPOST", "Unrecognized method", "400 Bad Request", "smuggled", "X-Injected"]
references:
  - https://portswigger.net/research/http2
  - https://portswigger.net/web-security/request-smuggling/advanced
license: AGPL-3.0-or-later
version: 1.0.0
---

# HTTP/2 Desync (and H2→H1 downgrade)

HTTP/2's built-in length makes classic CL/TE moot *at the edge* — but the moment
the edge downgrades to an HTTP/1.1 back-end, its recomputed framing can be
smuggled. h2 also permits characters (CRLF) in header/pseudo-header values that h1
must escape, enabling splitting the edge never sees.

## Sub-variants
- **H2.CL / H2.TE** — smuggle a Content-Length / Transfer-Encoding inside an h2
  request; the h1 back-end honours it after downgrade.
- **Pseudo-header CRLF injection** — CR/LF in `:path`, `:authority`, or a regular
  header value splits the downstream h1 request.
- **Request splitting via length ambiguity** — declared vs actual body mismatch.
- **Connection-preface / cleartext confusion** — malformed frames parsed as h2.
- **DoS variants** (authorization required only): CONTINUATION flood
  (CVE-2024-27316), Rapid Reset (CVE-2023-44487).

## Methodology (recon → probe → confirm → exploit → chain)

1. **Recon.** Confirm the target speaks h2 (`req list --protocol h2`) and that a
   downgrade to an h1 back-end is plausible (edge/CDN + origin).
2. **Probe.** Craft an h2 request carrying a hidden CL/TE or a CRLF-injected
   pseudo-header; send frame-level via raw replay. Watch for the h1 back-end
   mis-reading the implicit length.
3. **Confirm (differential — primary).** Same as HTTP/1.1 smuggling: send the
   smuggling h2 request, then a benign follow-up (`req replay`), and `compare` the
   follow-up against a clean baseline for the injected prefix / header. A prefix
   crossing into a foreign response is unambiguous → 0-FP. Fallback `timing`
   (socket stall) and `signature` (injected header/prefix string).
4. **Exploit.** Identical weaponisation to class HTTP/1.1: cache poisoning,
   credential capture, front-end auth/access-control bypass.

## Cross-chain notes
- Shares weaponisation with `web-request-smuggling` (cache/credential/access).
- H2 downgrade → cache poisoning (`web-cache-poisoning`).
- H3/QUIC coalescing is the next layer up: `web-http3-quic`.

## False-positive traps
- A malformed h2 request that just errors is not desync — require the smuggled
  content in a *foreign/baseline* response.
- DoS classes (CONTINUATION/Rapid-Reset) are out of scope without explicit
  authorization; never fire them opportunistically.

## Key payload sources
- PortSwigger "HTTP/2: The Sequel is Always Worse" — `references`.
- HTTP Request Smuggler (h2 mode); `vendor/PayloadsAllTheThings/Request Smuggling/`;
  HackTricks (path-only).

## Verification oracle
Primary `differential` (smuggled prefix/header in a foreign/baseline response);
fallback `timing` (stall) and `signature`. `verify.py` selects the strongest
oracle the caller wired inputs for.
