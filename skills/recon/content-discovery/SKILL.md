---
name: recon-content-discovery
description: >
  Discover hidden content: directories, files, endpoints, parameters, virtual
  hosts, and backup/config artifacts not linked from the app. USE WHEN starting an
  engagement or when a route map is incomplete — before access-control/IDOR
  testing, which needs the full endpoint inventory. Covers directory/file
  brute-forcing, recursive crawling, parameter mining, vhost discovery, and
  backup/source-leak hunting. All requests go through `burpwn exec` so findings
  land as captured, searchable flows.
tags: [recon, content-discovery, brute-force, crawl, param-mining, vhost]
tools: [ffuf, katana, subfinder, httpx, curl]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Directory Traversal/Intruder/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: inline, inline: ["robots.txt", "sitemap.xml", ".git/HEAD", ".env", ".DS_Store", "backup.zip", ".svn/wc.db", "swagger.json", "openapi.json", "graphql", ".well-known/security.txt"], license: AGPL-3.0-or-later, credit: "a2pwn"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/pentesting-web-vulnerabilities-methodology.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: signature
  signals: ["swagger", "openapi", "ref: refs/heads"]
references:
  - "https://github.com/ffuf/ffuf"
  - "https://github.com/projectdiscovery/katana"
license: AGPL-3.0-or-later
version: 1.0.0
---
# Content discovery — build the full route map

Access-control, IDOR, and business-logic testing are only as good as the
endpoint inventory. This skill produces that inventory: every directory, file,
endpoint, and parameter the app exposes but doesn’t link.

## Methodology
1. **Passive first.** `req list` after a normal browse already gives linked
   routes; de-bundled JS (`recon-js-supplychain`) reveals API paths. Start there
   — it’s free and captured.
2. **Crawl.** `exec katana -u <target> -jc -d 3` (JS-aware crawl) to expand the
   linked surface; feed results back into the session.
3. **Directory / file brute-force.** `exec ffuf -u <target>/FUZZ -w <wordlist>
   -mc 200,204,301,302,401,403 -ac` — auto-calibrate to kill soft-404s. Recurse
   into discovered dirs. Prioritise the high-signal seeds: `robots.txt`,
   `sitemap.xml`, `.git/HEAD`, `.env`, `.svn/wc.db`, `swagger.json`/`openapi.json`,
   `graphql`, `.DS_Store`, backup archives.
4. **Parameter mining.** Fuzz for unlinked query/body params that change the
   response (`ffuf` on `?FUZZ=...`, or a param wordlist) — hidden params are where
   IDOR/mass-assignment live.
5. **Virtual-host discovery.** `exec subfinder` for adjacent hosts, then
   `fuzz`/`ffuf` the `Host` header against the same IP to surface internal vhosts
   (`admin.`, `staging.`, `internal.`); compose host-header attacks.
6. **Backup / source leaks.** `.git`/`.svn` exposure → dump the repo; `.env`/
   config → secrets → `web-jwt-auth`; `swagger`/`openapi` → the complete API
   surface for `web-access-control`.

## Verification / triage
Discovery is not itself a vulnerability — a `200`/`403` is a lead, not a finding.
Confirm value by what the content *enables*: an exposed `.git` you can dump, a
`swagger.json` that reveals privileged routes, a backup with credentials. The
`verify.py`-free skills feed those artifacts into the exploit skills, whose
oracles do the confirming. Always double-check `403`s with the 403-bypass
techniques in `web-access-control`.

## Cross-chain
- Route map → `web-access-control` / `web-idor-bola`; leaked config → `web-jwt-auth`;
  vhosts → host-header attacks; `swagger`/`openapi` → full BFLA matrix.

## burpwn recipes
- `exec -- ffuf -u <t>/FUZZ -w words.txt -ac -mc all -fc 404` — captured brute.
- `exec -- katana -u <t> -jc` — JS-aware crawl.
- `req list` / `req search '<path>'` — the growing inventory is one queryable set;
  `tag add`/`note add` to mark high-value discoveries.

## False-positive traps
- Soft-404s (200 for everything) — use `-ac`/`-fc`/`-fs` calibration.
- A wildcard vhost answering every `Host` — verify content actually differs.
- A `403` that is a generic WAF block, not a real protected resource.
