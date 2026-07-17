---
name: web-graphql
description: >
  Detect and exploit GraphQL API weaknesses. USE WHEN an endpoint speaks GraphQL
  (/graphql, /graphiql, /v1/graphql, application/json with a `query` field, an
  Apollo/Hasura/graphql-yoga server). Covers introspection left enabled, field
  suggestion leakage when introspection is off, alias/batching-based DoS and
  rate-limit bypass, injection through variables into downstream SQL/NoSQL, and
  authorization gaps in queries/mutations (BOLA/IDOR at the field level).
tags: [web, graphql, api, introspection, idor, injection, owasp-api1, owasp-api3]
tools: [httpx, nuclei]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/GraphQL Injection/**/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/GraphQL Injection/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: inline, inline: ["{__schema{types{name}}}", "{__schema{queryType{name},mutationType{name}}}", "query{__type(name:\"User\"){fields{name type{name}}}}", "{user(id:1){id email} u2:user(id:2){id email}}", "{a:__typename b:__typename c:__typename}", "query($id:ID!){user(id:$id){email role}}", "{getUsr(id:1){id}}", "mutation{updateUser(id:2,role:\"admin\"){id role}}", "{users(first:100000){id}}"], license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
verification:
  kind: signature
  signals:
    - "__schema"
    - "queryType"
    - "mutationType"
    - "\"types\":["
    - "Did you mean"
references:
  - https://portswigger.net/web-security/graphql
  - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL
  - https://graphql.org/learn/introspection/
license: AGPL-3.0-or-later
version: 1.0.0
---
# GraphQL — introspection, batching, injection, field-level IDOR

Prove a concrete weakness, not just "GraphQL is present". The 0-FP discipline
per class: **introspection open** = the response literally contains `__schema`/
`queryType`; **field-suggestion leak** = a typo query returns a `Did you mean`
hint that names a hidden field; **mutation IDOR** = a two-identity differential
where A mutates/reads B's object. Detect broadly, confirm deterministically.

## Sub-variants
- **Introspection enabled** — `{__schema{types{name}}}` returns the full type
  system; map the attack surface for free.
- **Field-suggestion leak** — introspection disabled but the engine still answers
  malformed queries with `Did you mean "<field>"`, leaking schema piecemeal.
- **Batching / alias DoS & rate-limit bypass** — many aliased root fields in one
  request (or a JSON array of operations) multiply work / retry attempts past a
  per-request limit (e.g. brute-force login via aliases).
- **Injection via variables** — a resolver passes a variable into SQL/NoSQL/OS —
  chain to the relevant injection skill.
- **Authorization gaps (BOLA/IDOR)** — a query/mutation that reads or writes
  another user's object because auth was only checked at the top level.

## Methodology (recon → probe → confirm → exploit → chain)
1. **Recon.** `exec` capture a legit GraphQL request; confirm the endpoint and
   whether it accepts `GET`?query=, POST JSON, or `application/graphql`.
2. **Probe.** Send the introspection query. If blocked, send a deliberately
   misspelled field to elicit `Did you mean` suggestions; try alias batching to see
   if multiple operations run in one request.
3. **Confirm (deterministic).**
   - *Signature (primary, `verify.py` default):* the `signature` oracle matches
     `__schema`/`queryType`/`mutationType`/`"types":[` in the response — proof
     introspection is open — or a `Did you mean` suggestion when it is off.
   - *Differential (fallback):* for field-suggestion enumeration, `compare` a
     valid vs typo query to confirm the engine leaks names it should not.
   - *Two-identity (fallback):* for mutation/query IDOR, supply `a_ref` (A reaching
     B's object) and `b_ref` (B's own access); the `two_identity` oracle confirms
     A reproduced B's data or mutation. This is the BOLA proof.
4. **Exploit.** Use the mapped schema to reach unlinked queries/mutations
   (`updateUser(role:"admin")`, hidden admin fields); alias-batch a login mutation
   to bypass rate limits; drive variable injection into the backing store.
5. **Evasion.** Introspection filtered on POST → try `GET`, alternate content
   types, or `__schema` under a fragment; obfuscate with directives.

## Cross-chain notes
- Variable injection → `web-sqli` / `web-nosql-injection` / `web-command-injection`
  (share the OOB host / differential harness).
- Field/mutation IDOR is `web-idor-bola` at the GraphQL layer — reuse the identity
  matrix and `two_identity` oracle.
- Alias-batching rate-limit bypass feeds credential brute-force in
  `web-authentication`.

## False-positive traps
- The mere presence of `/graphql` is not a vulnerability. Introspection must
  actually return the schema — a `403`/`introspection disabled` is not a finding.
- A `Did you mean` hint is a leak only if it discloses a field the anonymous schema
  would hide; on an open schema it is redundant.
- A mutation that returns `200` but was performed on A's *own* object is not IDOR —
  the `two_identity` oracle requires B's object reproduced.

## Key payload sources
- PortSwigger GraphQL labs / OWASP WSTG GraphQL — `references`.
- `vendor/PayloadsAllTheThings/GraphQL Injection/` (introspection queries, batching/
  alias templates, suggestion-leak probes, injection-through-variable payloads).

## Verification oracle
Primary `signature` (`__schema`/`queryType`/`mutationType` present = introspection
open, or `Did you mean` = suggestion leak). Fallbacks: `differential` (field-name
enumeration), `two_identity` (mutation/query IDOR). `verify.py` selects the
strongest oracle the caller wired inputs for; "GraphQL is present" is never enough.
