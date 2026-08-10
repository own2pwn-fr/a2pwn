---
name: web-api-business-logic
description: >
  Attack business-logic and workflow flaws in APIs. USE WHEN the target exposes a
  multi-step flow with real-world meaning — checkout, refund, transfer, quota,
  subscription tier, coupon, invitation, approval chain. Covers negative and
  fractional quantities, currency and rounding abuse, step skipping and replay,
  client-supplied prices, quota/limit bypass, and unrestricted access to sensitive
  business flows (OWASP API6).
tags: [web, business-logic, api, workflow, owasp-api6, race-condition, authorization, logic]
tools: [curl, httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Business Logic Errors/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
verification:
  kind: state_change
references:
  - "https://portswigger.net/web-security/logic-flaws"
  - "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"
license: AGPL-3.0-or-later
version: 1.0.0
---
# Business logic — the bugs no scanner has a signature for

There is no payload list for this class: the vulnerability is that the application
faithfully implements a rule that is wrong. That makes it the highest-value class an
autonomous agent can cover, because it requires reading the flow rather than
matching a pattern — and the `state_change` oracle makes it provable rather than
narrative.

## Preconditions / triggers
- Any endpoint whose parameters carry real-world semantics: `quantity`, `price`,
  `amount`, `currency`, `discount`, `coupon`, `tier`, `seats`, `credits`, `status`,
  `step`, `expires_at`.
- Any flow with more than one request: cart → checkout → pay → confirm;
  request → approve → execute; invite → accept → provision.

## Methodology

### 1. Map the flow before touching it
Walk the happy path once as a legitimate identity and capture every step. Write down
the state transitions the server believes in. You cannot skip a step you have not
observed.

### 2. Value manipulation — one dimension at a time
- **Negative and zero**: `quantity=-1`, `amount=0`, `seats=-5`. A negative line item
  that reduces an order total is a direct financial finding.
- **Fractional and rounding**: `quantity=0.0001`, `amount=0.004` — where the server
  rounds to two decimals but sums before rounding, repeated small operations extract
  value. Also try very large values for integer overflow / scientific notation
  (`1e3`, `0x10`).
- **Client-supplied price**: send `price` / `total` / `currency` even if the UI never
  does — this overlaps with the `mass-assignment` skill; use it here.
- **Currency swap**: pay in a weak currency for a price quoted in a strong one.

### 3. Step skipping and replay
- Jump straight to the final step (`POST /checkout/confirm`) without the payment
  step, using a valid order id.
- Replay the confirmation twice — is the credit applied twice? Is a single-use coupon
  reusable? (If it is only reusable under concurrency, that is the `race-condition`
  skill; use its methodology and come back with the same `state_change` proof.)
- Go BACKWARD: modify the cart after the price was locked but before confirmation.

### 4. Quota, tier and limit bypass
Cancel-and-rebook to reset a counter; use a second endpoint that touches the same
resource but enforces no limit; check whether a limit enforced in the UI exists on
the API at all. A feature gated to a paid tier that responds normally on a free
identity is an authorization finding — prove it with `two_identity`.

### 5. Authorization on the flow, not just the object
Access control is often applied to the object and forgotten on the TRANSITION: user
A may legitimately read order 42 and must not be able to `approve` it. Test each verb
and each state transition per identity, not just each URL.

## Oracle
`state_change` is the primary oracle and the reason this class is reportable at all:
- `flow_ids[0]` = a read of the state BEFORE the abusive action,
- `flow_ids[1]` = a read of the same state AFTER,
- `oracle_expect = {"must_appear": "<the impossible value>"}` — e.g. a negative
  total, a `"status":"paid"` never paid for, a credit balance that grew.

Use `two_identity` for tier/transition authorization findings, and pair with the
`race-condition` skill when the flaw only manifests under concurrency.

## Severity calibration
Logic flaws are severity-by-consequence, not by class. State the concrete impact in
one sentence — "an authenticated user can obtain an unlimited number of paid
subscriptions at zero cost" — and let CVSS follow from that, rather than defaulting
to medium.

## Pitfalls
- The response echoing your manipulated value proves nothing; the SERVER's later
  reading of its own state is the proof. Always re-read.
- Do not leave the target in a corrupted state: prefer objects you created, and
  reverse the transition when the flow allows it. Note in `remediation` when a
  test artefact could not be cleaned up.
- Financial actions against a live system need explicit authorisation — if the
  engagement did not enable active exploitation, demonstrate the acceptance of the
  impossible value and stop before the irreversible step.
