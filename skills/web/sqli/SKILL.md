---
name: web-sqli
description: >
  Detect and exploit SQL injection in web/API parameters, headers and cookies.
  USE WHEN a parameter reaches a query, when responses leak SQL error strings, or
  when numeric / boolean / time-based responses shift under quote / arithmetic /
  AND-OR / SLEEP perturbation. Covers error-based, UNION, boolean-blind,
  time-blind, OOB (DNS/HTTP exfil), stacked, second-order and NoSQL operator
  injection across MySQL / Postgres / MSSQL / Oracle / SQLite / Mongo.
tags: [web, injection, sqli, nosqli, owasp-a03, db, blind]
tools: [sqlmap, httpx, nuclei]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/SQL Injection/Intruder/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/SQL Injection/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/sql-injection/README.md", license: CC-BY-SA-4.0, credit: "HackTricks — Carlos Polop"}
verification:
  kind: timing
  expect: {threshold_ms: 5000}
  signals:
    - "you have an error in your SQL syntax"
    - "SQLITE_ERROR"
    - "ORA-0"
    - "PG::"
    - "SQLSTATE"
    - "Unclosed quotation mark"
    - "quoted string not properly terminated"
references:
  - https://portswigger.net/web-security/sql-injection
  - https://portswigger.net/web-security/sql-injection/cheat-sheet
  - https://portswigger.net/web-security/sql-injection/blind
license: AGPL-3.0-or-later
version: 1.0.0
---

# SQL Injection

Prove that attacker input alters SQL semantics. The 0-FP discipline: a boolean or
error *could* be a coincidence — a **controlled time delay** or an **OOB DNS
exfil** is the unambiguous oracle. Detect broadly, confirm deterministically.

## Sub-variants
- **Error-based** — DB error string leaks (fastest signal, per-DBMS grammar).
- **UNION-based** — column-count + type alignment to exfiltrate rows in-band.
- **Boolean-blind** — TRUE vs FALSE payloads produce differentiable responses.
- **Time-blind** — `SLEEP(5)` / `pg_sleep(5)` / `WAITFOR DELAY` / `dbms_pipe`.
- **OOB** — DNS/HTTP exfil via `LOAD_FILE`+UNC, `xp_dirtree`, `UTL_HTTP`,
  Postgres `COPY … PROGRAM`, `dblink`.
- **Stacked queries** — `; INSERT/UPDATE/…` when the driver allows multi-statement.
- **Second-order** — stored via one endpoint, executed in another later flow.
- **NoSQL** — Mongo operator injection (`$ne`, `$gt`, `$where`, `$regex`), auth
  bypass with `{"$ne": null}`.
- **Header/cookie-borne** — injection via `User-Agent`, `Referer`,
  `X-Forwarded-For`, session cookie; **WAF-evasion** via comment/case/encoding.

## Methodology (recon → probe → confirm → exploit → chain)

1. **Recon.** `exec` capture the request; enumerate *every* sink — query params,
   JSON keys, path segments, headers, cookies. `decode` any base64/url-encoded
   values so the real injection point is visible.
2. **Probe.** `fuzz` a quote / double-quote / arithmetic set (`'`, `''`, `"`,
   ` AND 1=1`, ` AND 1=2`, `*/`, ` OR 'a'='a`). Anomaly ranking flags the param
   whose **status / length / time** diverges — that is your candidate.
3. **Confirm (deterministic).**
   - *Time-blind (primary, `verify.py` default):* `fuzz` a `SLEEP(5)` payload,
     then the `timing` oracle asserts the slowest result crosses `threshold_ms`.
     A controllable delay cannot be a coincidence — 0-FP.
   - *Error-based:* the `signature` oracle matches DBMS error strings in the flow.
   - *Boolean-blind:* pitchfork TRUE/FALSE pairs → `differential`/`compare` the
     two responses (length/reflection delta).
   - *OOB:* the `oob` oracle — DNS/HTTP exfil to the collaborator (`req list
     --protocol dns`); the strongest signal for firewalled back-ends.
   - *Second-order:* the `marker` oracle — `req_search` your token across later
     flows to find where the stored value re-executes.
4. **Exploit.** For heavy extraction, `exec sqlmap --batch` against the confirmed
   param (still captured in-session). Fingerprint the DBMS first (per-DBMS grammar
   differs; UNION column count via `ORDER BY n`).
5. **WAF evasion.** Layer comments (`/**/`), case randomisation, inline hints,
   and sqlmap tamper scripts; re-run the timing oracle to confirm the bypass.

## Cross-chain notes
- SQLi in a JWT `kid` header → forge / traverse (JWT skill).
- SQLi → dumped credentials → authentication bypass / access-control.
- SSRF via `LOAD_FILE` / `OPENROWSET` / `COPY … PROGRAM` → pivot to `web-ssrf`.
- Second-order SQLi shares the stored-then-executed pattern with stored XSS.

## False-positive traps
- A reflected quote that only changes a *rendered* error page is not SQLi —
  require a differential/timing/OOB signal, never a lone reflected string.
- WAF 403s can masquerade as boolean differentials; confirm with timing or OOB.

## Key payload sources
- PortSwigger SQLi cheat sheet (per-DBMS grammar) — `references`.
- `vendor/PayloadsAllTheThings/SQL Injection/` (per-DBMS intruders, auth-bypass,
  time-based, NoSQL); sqlmap tamper scripts; HackTricks SQLi + NoSQL (path-only).

## Verification oracle
Primary `timing` (controlled SLEEP); fallbacks `signature` (DBMS error strings),
`oob` (DNS/HTTP exfil), `differential` (boolean TRUE/FALSE), `marker`
(second-order). `verify.py` selects the strongest oracle the caller wired inputs for.
