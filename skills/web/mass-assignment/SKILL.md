---
name: web-mass-assignment
description: >
  Detect and exploit mass assignment / autobinding (OWASP API6). USE WHEN a JSON or
  form endpoint updates an object and the framework binds request keys straight onto
  the model — letting you set fields the UI never exposes (role, is_admin, tenant_id,
  balance, verified, price, owner_id). Covers field discovery from GET responses,
  nested and dotted paths, HTTP parameter pollution, and privilege escalation.
tags: [web, mass-assignment, autobinding, api, owasp-api6, privilege-escalation, idor, access-control]
tools: [curl, httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Mass Assignment/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
verification:
  kind: state_change
references:
  - "https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/"
  - "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"
license: AGPL-3.0-or-later
version: 1.0.0
---
# Mass assignment — writing the fields the UI never shows you

The bug is a framework convenience: `User.update(**request.json)` binds every key
the client sent. The exploit is writing a field the client should never control. It
is trivially provable and routinely missed, because nothing in the UI hints the
field is writable.

## Preconditions / triggers
- Any `PUT`/`PATCH`/`POST` that updates an object, especially JSON APIs.
- A framework with autobinding: Rails `permit`-less params, Spring `@ModelAttribute`,
  Django ModelForm with `fields = '__all__'`, Laravel `$fillable` unset, Express +
  Mongoose `Model.findByIdAndUpdate(id, req.body)`, ASP.NET model binding.

## Methodology
1. **Discover the true field set from a READ.** `GET` the same object as an
   authenticated identity and list every key in the response — those are model
   fields, and the write endpoint frequently accepts all of them even though the
   form posts three. Also mine: OpenAPI/Swagger docs, GraphQL introspection, JS
   bundles, and error messages from a deliberately malformed body.
2. **Send one extra field at a time.** Never batch: if you set `role` and `is_admin`
   together and the object changes, you do not know which one bound, and neither
   will the report. One field per request, each in its own captured flow.
3. **Try the shape variants** the binder may accept where the flat key failed:
   - nested: `{"user": {"role": "admin"}}`, dotted: `{"user.role": "admin"}`
   - array/bracket form encoding: `user[role]=admin`
   - parameter pollution: the same key twice, in query AND body, with different values
   - case and snake/camel variants: `isAdmin`, `is_admin`, `IsAdmin`
4. **Read the object back as the OWNER identity** to confirm persistence. A 200 on
   the write proves nothing — many frameworks silently ignore unknown keys and still
   return success. The finding is the field's value CHANGED on a subsequent read.

## Highest-value fields to probe
`role`, `roles`, `is_admin`, `isAdmin`, `is_staff`, `permissions`, `scopes`,
`email_verified`, `verified`, `active`, `status`, `tenant_id`, `org_id`, `owner_id`,
`user_id`, `account_id`, `balance`, `credit`, `price`, `discount`, `quantity`,
`created_at`, `id`.

`tenant_id` / `org_id` / `owner_id` are the ones that turn mass assignment into
cross-tenant compromise — chain them into an `enables` edge toward the access-control
findings they unlock.

## Oracle
`state_change` is the right oracle, not `differential`: the proof is that server
state changed, which lives in a LATER read, not in the write's response.
- `flow_ids[0]` = the before-read (as the owner), `flow_ids[1]` = the after-read.
- `oracle_expect = {"must_appear": "admin"}` (or the exact new value).
- Include the write flow in the same workspace as supporting evidence.

Where the escalation is provable end-to-end, follow up with `two_identity`: identity
A, after setting `role=admin` on itself, now reaches an endpoint that previously
returned 403.

## Pitfalls
- **A 200 is not a finding.** Confirm with a read-back, every time.
- Do not test destructive fields (`deleted`, `status=cancelled`) on shared or
  production objects unless the engagement authorises active exploitation — prefer
  an object you created yourself.
- If the field appears to change but reverts, you likely hit an optimistic response
  and a rejecting backend job: re-read after a short delay before reporting.
