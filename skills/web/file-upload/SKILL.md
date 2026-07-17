---
name: web-file-upload
description: >
  Detect and exploit unrestricted / unsafe file upload. USE WHEN an endpoint
  accepts a file (avatar, document, import, attachment, image processor) and the
  uploaded file is stored, re-served, or processed. Covers webshell upload
  (PHP/JSP/ASPX), extension bypass (double extension, null byte, case, trailing
  dot), Content-Type spoofing, magic-byte polyglots, path traversal in the
  filename, and SVG/XML uploads that yield stored XSS or XXE.
tags: [web, file-upload, rce, webshell, xxe, xss, owasp-a04, owasp-a05]
tools: [httpx, nuclei, ffuf]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Upload Insecure Files/**/*.php", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Upload Insecure Files/**/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Upload Insecure Files/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: inline, inline: ["shell.php", "shell.php.jpg", "shell.pHp", "shell.php%00.jpg", "shell.php;.jpg", "shell.phtml", "shell.jsp", "GIF89a;<?php echo 'CID'; ?>", "../../shell.php", "..%2f..%2fshell.php", "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert('CID')\"/>", "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><svg>&x;</svg>"], license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
verification:
  kind: signature
  signals:
    - "uid="
    - "gid="
    - "A2PWN-UPLOAD-CID"
    - "root:x:0:0:"
    - "<?php"
references:
  - https://portswigger.net/web-security/file-upload
  - https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
  - https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files
license: AGPL-3.0-or-later
version: 1.0.0
---
# Unsafe File Upload

Prove that an uploaded file is stored *and* interpreted the way you intend. The
0-FP discipline: an "upload succeeded" JSON is not a finding. The proof is the file
**re-served with a unique marker echoed back**, a **webshell that executes** (a
correlation string or `uid=` in the served response), an **OOB callback** the
executed shell emits, or **file content read** via an SVG/XXE upload. Detect
broadly, confirm deterministically.

## Sub-variants
- **Direct webshell** — `.php`/`.phtml`/`.jsp`/`.aspx` executed when re-served.
- **Extension bypass** — double extension (`shell.php.jpg`), null byte
  (`shell.php%00.jpg`), trailing dot/space, case (`.pHp`), alt handlers
  (`.phtml`, `.php5`), semicolon (`shell.php;.jpg`) on IIS.
- **Content-Type / magic-byte spoof** — declare `image/jpeg`, prepend `GIF89a;`
  polyglot so validators pass while the interpreter still runs the code.
- **Path traversal in filename** — `../../shell.php` writes outside the upload dir
  (web root, cron, config).
- **SVG / XML upload** — SVG with `onload` → stored XSS; SVG/XML with a doctype →
  XXE file read (compose `web-xxe`).

## Methodology (recon → probe → confirm → exploit → chain)
1. **Recon.** `exec` capture the upload flow and any **retrieval** flow (where the
   file is later served — CDN path, `/uploads/`, an id-based download). No retrieval
   surface = far harder to prove; hunt for one.
2. **Probe.** Upload a benign file carrying a unique correlation marker
   (`A2PWN-UPLOAD-<cid>`) to learn the stored path/naming scheme. Then attempt each
   bypass class, changing one variable at a time (extension, Content-Type,
   magic bytes, filename traversal).
3. **Confirm (deterministic).**
   - *Signature (primary, `verify.py` default):* fetch the stored file and the
     `signature` oracle matches the executed/served marker — the webshell's echoed
     `<cid>`, `uid=`/`gid=` (PHP `system('id')`), `root:x:0:0:` (SVG/XXE read), or a
     raw `<?php` served verbatim (source disclosure).
   - *OOB (fallback):* a webshell that runs `curl`/`nslookup` to your correlation
     host — the `oob` oracle catches the callback, proving execution even when the
     response is blind.
   - *Marker (fallback):* the `marker` oracle full-text-searches captured history
     for the correlation string when the file surfaces at a different URL than
     expected.
4. **Exploit.** Turn a confirmed webshell into enumeration/RCE (still in-session);
   an SVG-XSS into a stored-XSS chain; an SVG-XXE into file read / SSRF.
5. **Evasion.** Server strips the exec extension → re-order double extensions,
   abuse Apache `.htaccess`/`AddType`, IIS `web.config`, or a race between upload
   and AV/rename (compose `web-race-condition`).

## Cross-chain notes
- Webshell → OS command execution → share the OOB host with `web-command-injection`.
- SVG/XML upload → `web-xxe` (file read / SSRF) or stored XSS (`web-xss`).
- Path-traversal filename → arbitrary write → config/cron overwrite; the read side
  is `web-path-traversal-lfi`.

## False-positive traps
- HTTP 200 / "upload successful" is not a finding — you must retrieve the file and
  observe execution, source disclosure, or a callback.
- A stored `.php` that is served as `text/plain` (source shown, not run) is a
  source-disclosure finding, **not** RCE — classify it honestly.
- A reflected filename in a JSON response is not proof the file executes.
- An image that is re-encoded/stripped by the server (marker gone) means the polyglot
  was neutralised — not vulnerable.

## Key payload sources
- PortSwigger file-upload labs — `references`.
- `vendor/PayloadsAllTheThings/Upload Insecure Files/` (webshells, extension and
  Content-Type bypass matrices, magic-byte polyglots, `.htaccess`/`web.config`
  tricks, SVG XSS/XXE templates).

## Verification oracle
Primary `signature` (the served/uploaded file echoes a unique marker, `uid=`,
`root:x:0:0:`, or verbatim `<?php`). Fallbacks: `oob` (executed webshell callback),
`marker` (file surfaces at another URL). `verify.py` selects the strongest oracle
the caller wired inputs for; an "upload succeeded" status alone is rejected.
