---
name: web-deserialization
description: >
  Detect and exploit insecure deserialization. USE WHEN a cookie/param/body carries
  a serialized blob (Java rO0/AC ED 00 05, PHP O:/a:, .NET __VIEWSTATE, Python
  pickle, Ruby Marshal/YAML, node-serialize _$$ND_FUNC$$_, Jackson/fastjson type
  hints). Covers gadget-chain RCE, blind URLDNS-style OOB detection, ViewState MAC
  bypass, and phar:// triggers. Prove with an OOB callback before attempting RCE.
tags: [web, deserialization, rce, gadget-chain, owasp-a08, injection]
tools: [curl, httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Insecure Deserialization/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/deserialization/README.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: oob
  signals: ["rO0", "java.lang", "_$$ND_FUNC$$_", "O:8:"]
references:
  - "https://portswigger.net/web-security/deserialization"
  - "https://github.com/frohoff/ysoserial"
license: AGPL-3.0-or-later
version: 1.0.0
---
# Insecure deserialization — prove it OOB before you go for RCE

The safe, 0-FP first step is an **out-of-band callback** (URLDNS for Java, a
DNS/HTTP gadget elsewhere): it proves the blob is deserialized *without* firing
a destructive RCE chain. Only then weaponize.

## Preconditions / triggers
- A blob in a cookie/param/body. `decode base64` reveals magic bytes:
  `rO0`/`AC ED 00 05` = Java, `O:`/`a:` = PHP, `__VIEWSTATE` = .NET,
  pickle opcodes, `_$$ND_FUNC$$_` = node-serialize, type-hint JSON = Jackson/fastjson.

## Methodology
1. **Locate + fingerprint.** `req search` for serialized blobs across the session;
   `decode base64` to read magic bytes and pick the format/engine.
2. **Blind OOB probe (the safe oracle).** Craft a *detection-only* gadget:
   Java `URLDNS` (or `Runtime`-free chain) resolving `http://<listener>/<cid>`;
   PHP a `__wakeup`/`__destruct` gadget hitting the listener; Jackson a JNDI/URL
   gadget. Host the listener **in-sandbox** (`burpwn exec -- python -m
   a2pwn._oob_listener`) so the server’s callback lands as a `dns`/`rawtcp` flow
   in the same session, or use the external collaborator.
3. **Confirm.** A callback carrying the correlation id = deserialization proven.
4. **Weaponize (authorized only).** Swap in a real gadget chain
   (`exec ysoserial`, `phpggc`), capture the RCE-output flow.
5. **ViewState.** If `__VIEWSTATE` lacks MAC (or the machineKey leaks), forge an
   `ObjectDataProvider` payload.

## Confirmation oracle (0-FP)
`verify.py` uses the **OOB** oracle first (`collab` + `correlation_id`): a
callback proves deserialization. If no collaborator is wired, it falls back to a
**signature** match for RCE output (`uid=`/`gid=`) in the target flow. A serialized
blob that merely round-trips with no callback and no command output is **not** a
finding.

## Cross-chain
- Deser → RCE → SSRF pivot to cloud metadata; XXE inside deserialized XML
  (`web-xxe`); type-hint JSON → JNDI → RCE.

## burpwn recipes
- `decode base64 <blob>` — expose magic bytes; `req search` — find blobs everywhere.
- `req replay <id> --set-body @gadget.bin` (or `--set-header 'Cookie: ...'`) — swap
  the blob; in-sandbox listener + `req list --protocol dns|rawtcp` — capture URLDNS.

## False-positive traps
- A base64 value that is not a serialized object (just a token) → not this class.
- App-level errors on a malformed blob prove parsing, **not** gadget execution —
  require the OOB callback or command output.
