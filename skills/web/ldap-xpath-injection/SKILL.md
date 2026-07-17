---
name: web-ldap-xpath-injection
description: >
  Detect and exploit LDAP and XPath/XQuery injection. USE WHEN a login,
  user-lookup, address-book, or XML-backed search reaches an LDAP directory or an
  XPath query and responses shift under filter/predicate injection. Covers LDAP
  authentication bypass ( *)(uid=*))(|(uid=* ), LDAP filter injection and blind
  attribute exfil, XPath auth bypass ( ' or '1'='1 ), and blind boolean XPath
  extraction via substring()/count()/string-length().
tags: [web, injection, ldap, xpath, xquery, blind, auth, owasp-a03]
tools: [httpx, nuclei, ffuf]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/LDAP Injection/**/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/XPATH Injection/**/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/LDAP Injection/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: inline, inline: ["*", "*)(uid=*", "*)(uid=*))(|(uid=*", "admin)(&))", "*)(objectClass=*", ")(cn=*", "' or '1'='1", "' or 1=1 or ''='", "x' or name()='username' or 'x'='y", "'] | //user/*[contains(*,'adm')] | a['", "count(/*)=1", "string-length(//user[1]/password)>0"], license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
verification:
  kind: differential
  expect: {signal: any, min_len_delta: 16}
  signals:
    - "javax.naming"
    - "LDAPException"
    - "com.sun.jndi"
    - "XPathException"
    - "SimpleXMLElement"
    - "Invalid predicate"
references:
  - https://owasp.org/www-community/attacks/LDAP_Injection
  - https://owasp.org/www-community/attacks/XPATH_Injection
  - https://portswigger.net/kb/issues/00100500_ldap-injection
license: AGPL-3.0-or-later
version: 1.0.0
---
# LDAP & XPath Injection

Prove that attacker input alters an LDAP filter or an XPath predicate. The 0-FP
discipline: an error string or one lucky login is not proof. The oracle is a
**deterministic differential** — an always-true payload flips auth denied→accepted,
or a boolean TRUE/FALSE pair diverges in status/length. Detect broadly, confirm
deterministically.

## Sub-variants
- **LDAP auth bypass** — inject `*)(uid=*))(|(uid=*` or `*)(objectClass=*` into a
  username to make the bind filter always match; `*` as password on some filters.
- **LDAP filter injection / blind exfil** — inject `)(attr=value*` and walk the
  wildcard to disclose attribute values via presence/absence differentials.
- **XPath auth bypass** — classic `' or '1'='1` / `' or 1=1 or ''='` to satisfy
  the node predicate.
- **Blind XPath extraction** — `substring(//user[1]/password,N,1)='x'`,
  `string-length(...)`, `count(/*)` to walk the document char-by-char.
- **XQuery / XPath 2.0** — `string-to-codepoints`, `matches()` widen the surface.

## Methodology (recon → probe → confirm → exploit → chain)
1. **Recon.** `exec` capture login / directory-search / address-book flows. Guess
   the backend: enterprise SSO / "corporate directory" → LDAP; XML data files or
   `.xml` responses → XPath. `decode` encoded params.
2. **Probe.** LDAP: send `*`, `)(`, `*)(uid=*` and watch for `javax.naming` /
   `LDAPException`. XPath: send `'`, `' or '1'='1`, `']` and watch for
   `XPathException` / result-set widening.
3. **Confirm (deterministic).**
   - *Differential (primary, `verify.py` default):* pair an always-true payload
     against an always-false one and `compare`. Auth flip (`login failed` →
     session) = `signal: status_change`; a boolean predicate that returns "all
     rows" vs "none" = `length_delta`. That controllable flip is the proof.
   - *Signature (fallback):* the `signature` oracle matches parser errors —
     `javax.naming`, `com.sun.jndi`, `LDAPException`, `XPathException`,
     `SimpleXMLElement`, `Invalid predicate` — evidence the injection reached the
     query engine (weaker; pair with a differential when possible).
4. **Exploit.** LDAP: dump directory attributes via wildcard walk under the
   differential; auth-bypass to a privileged bind. XPath: extract the credential
   store char-by-char via the boolean/length oracle.
5. **Evasion.** LDAP filters escaping `*`/`(`/`)` → try `\2a` encodings, comment-
   less nested `(|(...))`; XPath quote filters → `concat()`, double-quote pivot.
   Re-run the differential after each bypass.

## Cross-chain notes
- LDAP/XPath auth bypass → authenticated session → `web-idor-bola` /
  `web-access-control` / `web-authentication`.
- Shares the boolean/blind extraction discipline with `web-sqli` and
  `web-nosql-injection` — reuse the same differential harness.
- XPath over user-supplied XML can co-occur with `web-xxe` on the same endpoint.

## False-positive traps
- One successful login with `*)(uid=*` is weak — pair it against a guaranteed-false
  filter and prove the *flip*; the account may simply exist.
- A reflected `LDAPException` / `XPathException` proves parsing broke, not that you
  controlled the result set — require a differential.
- A search that returns everything for *every* input (no TRUE/FALSE divergence) is
  a broad-match feature, not injection.

## Key payload sources
- OWASP LDAP / XPath injection guides — `references`.
- `vendor/PayloadsAllTheThings/LDAP Injection/` and `.../XPATH Injection/`
  (auth-bypass filters, wildcard exfil, blind `substring`/`count` templates).

## Verification oracle
Primary `differential` (always-true vs always-false — auth denied→accepted or
boolean length/status delta). Fallback `signature` (LDAP/XPath parser error
strings). `verify.py` selects the strongest oracle the caller wired inputs for; a
lone error string or unpaired success is rejected.
