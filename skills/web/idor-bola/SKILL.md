---
name: web-idor-bola
description: >
  Detect and exploit IDOR / BOLA (broken object-level authorization). USE WHEN a
  request references an object by id (numeric, UUID, hashid, filename, export id)
  and swapping that reference to another user's object returns their data or
  mutates their state. Covers horizontal vs vertical refs, mass-assignment,
  nested/GraphQL field IDOR, blind write-only IDOR, and predictable export ids.
tags: [web, idor, bola, authorization, access-control, owasp-api1, auth]
tools: [curl, httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Insecure Direct Object References/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/idor.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: two_identity
references:
  - "https://portswigger.net/web-security/access-control/idor"
  - "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
license: AGPL-3.0-or-later
version: 1.0.0
---
# IDOR / BOLA — the two-identity differential

The definitive test needs **two identities**: attacker **A** and victim **B**.
A finding exists when **A**, using A’s own session, reaches **B**’s object and
gets B’s data (or successfully mutates B’s state). Everything else is noise.

## Preconditions / triggers
- Any request carrying an object reference: `?id=`, `/orders/1043`, `/users/{uuid}`,
  `?file=export_88.csv`, a GraphQL `node(id:)`, a hidden form field.
- Two accounts you control (or one account + a known second object id).

## Methodology
1. **Establish two sessions.** `session auth set` per identity, or hold two
   cookie sets. Capture B doing the legitimate access to B’s object → this is
   the **ground-truth** flow.
2. **Swap the reference as A.** `req replay <A-flow> --set-header '<A cookie>'`
   with the id changed to B’s object. Keep everything else identical.
3. **Differential.** `compare <A-on-B-object> <B-on-B-object>`. Identical body
   (or A’s 2xx body is a superset of B’s) = **IDOR confirmed**; a `401/403` or a
   divergent “not yours” body = access control held.
4. **Enumerate.** `fuzz` the id position over a sequential/UUID/hashid list,
   anomaly-ranked by status/length, to map every accessible object.
5. **Mass-assignment.** Add unexpected fields to the write body (`"role":"admin"`,
   `"isAdmin":true`, `"price":0`, `"userId":<B>`) and check they take effect.
6. **Blind / write-only IDOR.** Perform the write as A on B’s object, then verify
   the side-effect **as B** (or via a read endpoint) — the mutation is the proof.
7. **Nested / GraphQL.** IDOR often hides one field deep (`order.customer.email`)
   or in a batched GraphQL query where the top-level auth passed.

## Confirmation oracle (0-FP)
`verify.py` delegates to the **two-identity** oracle: it needs `a_ref` (A
reaching B’s object) and `b_ref` (B fetching the same object). Confirmed only
when A’s response is `2xx` **and** reproduces B’s object (byte-identical, or a
superset with no victim-only lines missing). A denial or a divergent body is
rejected — this is exactly the Autorize-style differential, done deterministically.

## Cross-chain
- IDOR + JWT `sub` swap (`web-jwt-auth`); IDOR is the horizontal half of
  `web-access-control` (share the identity matrix); leaked ids from de-bundled JS
  (`recon-js-supplychain`) seed the id space.

## burpwn recipes
- `session auth` per identity → `req replay` id-swap → `compare` = the core loop.
- `fuzz run --flow <id> --position <id-offset> --payloads ids.txt` — enumerate.
- `tag add <flow> idor red` + `note add <flow> "<writeup>"` — seal the evidence batch.

## False-positive traps
- Both accounts seeing the **same public** resource is not IDOR — B’s object must
  be private to B. Confirm the resource is user-scoped.
- A 200 that returns an empty/`{}` body is not access to B’s data.
- Rotating/opaque ids that 404 on swap are not vulnerable.
