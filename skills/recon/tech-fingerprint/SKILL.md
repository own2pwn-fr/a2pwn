---
name: recon-tech-fingerprint
description: >
  Fingerprint the target's technology stack: server/proxy/CDN, web framework and
  language, application/CMS, JS libraries, WAF, and TLS/HTTP-protocol support. USE
  AT THE START of every engagement — the stack dictates which vulnerability classes
  and payloads apply (e.g. Jinja vs Freemarker SSTI, PHP vs Java deserialization,
  h2/h3 desync surface). Drives every subsequent skill's payload selection.
tags: [recon, fingerprint, tech-stack, waf, cdn, framework, protocol]
tools: [httpx, nmap, curl]
payloads:
  - {kind: inline, inline: ["Server", "X-Powered-By", "X-AspNet-Version", "Set-Cookie", "X-Generator", "Via", "CF-Ray", "X-Served-By"], license: AGPL-3.0-or-later, credit: "a2pwn"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/pentesting-web-vulnerabilities-methodology.md", license: CC-BY-SA-4.0, credit: "HackTricks - Carlos Polop"}
verification:
  kind: signature
  signals: ["Server:", "X-Powered-By:", "Set-Cookie:", "alt-svc:"]
references:
  - "https://github.com/projectdiscovery/httpx"
  - "https://nmap.org/book/man-service-probes.html"
license: AGPL-3.0-or-later
version: 1.0.0
---
# Tech fingerprint — decide which payloads are even relevant

Fingerprinting is the routing step: it tells the orchestrator *which* classes and
*which* payload dialects apply, so you don’t fuzz Jinja gadgets at a Freemarker
app or Java deser at a PHP one. Cheap, first, and it shapes everything after.

## Methodology
1. **HTTP surface.** `exec httpx -u <target> -title -tech-detect -server
   -status-code -web-server` (Wappalyzer-style) → server, framework, CMS, JS libs.
   Read the raw headers too: `Server`, `X-Powered-By`, `X-AspNet-Version`,
   `X-Generator`, `Via`, `CF-Ray`/`X-Served-By` (CDN), and cookie names
   (`JSESSIONID`=Java, `PHPSESSID`=PHP, `.AspNetCore`=.NET, `laravel_session`,
   `connect.sid`=Node/Express, `csrftoken`+`sessionid`=Django).
2. **Language / framework tells.** Error-page shapes, default routes
   (`/actuator`, `/_next/`, `/wp-json`, `/api/v1`), template delimiters that error,
   and 404 fingerprints. Confirm with a harmless differential (`{{7*7}}` vs
   `${7*7}` only when SSTI is in scope — see the SSTI class).
3. **Protocol support.** `req list --protocol h2` shows HTTP/2; `alt-svc`/h3
   advertisement flags QUIC (desync surface, classes h2/h3). Note TLS version /
   ALPN from the capture (`req show` flow metadata) and whether the target is
   `tls-passthru` (MITM-blocked → not testable this session).
4. **WAF / CDN.** Cloudflare/Akamai/AWS fingerprints (headers, challenge pages,
   `CF-Ray`). A WAF dictates payload encoding/evasion for later classes.
5. **Version → advisory hint.** A precise `Server`/framework version feeds a CVE
   lookup (do it outside the sandbox), which the exploit skills then *prove* — a
   banner version is a lead, never a finding on its own.

## Verification / triage
No exploit here — this skill produces the routing metadata. Its “confirmation” is
downstream: it tells `web-deserialization` whether to fingerprint Java vs PHP,
`web-jwt-auth` which cookie is the session, `web-prototype-pollution` whether the
stack is Node, and the desync classes whether h2/h3 is even on. Banner-only
version claims must be proven by the relevant exploit skill’s oracle.

## Cross-chain
- Stack → payload dialect for **every** injection class; cookie tells → session
  handling for `web-jwt-auth`/`web-access-control`; protocol support → desync
  classes; CDN/cache headers → cache-poisoning/deception.

## burpwn recipes
- `exec -- httpx -u <t> -tech-detect -server -title` — captured fingerprint.
- `exec -- nmap -sV -p 80,443 <host>` — service/version at the transport layer.
- `req show <id>` — read TLS/ALPN/protocol metadata; `req list --protocol h2` —
  HTTP/2 presence; watch for `tls-passthru` (target MITM-blocked).

## False-positive traps
- Spoofed/removed `Server` headers — corroborate with cookie/route tells.
- A CDN banner masks the origin stack — fingerprint the app behind it.
- Version banners are frequently stale or faked; never report a CVE off a banner
  without the exploit skill proving it live.
