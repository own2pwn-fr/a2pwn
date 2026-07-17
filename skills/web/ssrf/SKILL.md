---
name: web-ssrf
description: >
  Detect and exploit Server-Side Request Forgery. USE WHEN a parameter consumes a
  URL (webhooks, ?url=, ?img=, SSO callbacks, PDF/SVG renderers, image proxies,
  URL previews) or the server fetches attacker-influenced hosts. Covers in-band,
  blind (OOB), cloud-metadata (AWS IMDSv1/IMDSv2 token handshake, GCP, Azure,
  Alibaba, K8s/EKS), DNS-rebinding, gopher:// (Redis/FastCGI/SMTP), protocol
  smuggling (file/dict/ftp), and redirect-based SSRF.
tags: [web, ssrf, oob, cloud, metadata, blind, owasp-a10]
tools: [httpx, nuclei]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Server Side Request Forgery/Files/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Server Side Request Forgery/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: upstream_doc, path: "vendor/hacktricks/pentesting-web/ssrf-server-side-request-forgery/README.md", license: CC-BY-SA-4.0, credit: "HackTricks — Carlos Polop"}
verification:
  kind: oob
  expect: {protocols: [dns, http, rawtcp], timeout_secs: 30}
  signals:
    - "SecretAccessKey"
    - "AccessKeyId"
    - "ASIA"
    - "Metadata-Flavor"
    - "ami-id"
    - "instance-id"
    - "iam/security-credentials"
    - "computeMetadata"
references:
  - https://portswigger.net/web-security/ssrf
  - https://portswigger.net/web-security/ssrf/blind
  - https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/index.html
license: AGPL-3.0-or-later
version: 1.0.0
---

# SSRF — Server-Side Request Forgery

Make the server issue requests of the attacker's choosing. **The OOB oracle is
load-bearing:** burpwn captures the *client tooling's* egress, not the target's
outbound callback, so blind SSRF is proven by a collaborator callback (external
Interactsh-style listener, or an in-sandbox `exec` listener whose callback lands
as a `dns`/`rawtcp` flow — `req list --protocol dns|rawtcp`).

## Sub-variants
- **Basic / in-band** — response contains the fetched content.
- **Blind** — no reflection; confirmed only by an OOB callback.
- **Cloud metadata** — AWS IMDSv1 (`http://169.254.169.254/latest/meta-data/`),
  **IMDSv2** (PUT `/latest/api/token` + `X-aws-ec2-metadata-token`), GCP
  (`metadata.google.internal`, `Metadata-Flavor: Google`), Azure IMDS
  (`Metadata: true`), Alibaba, K8s/EKS node-role, AWS Bedrock MMDS.
- **DNS-rebinding** — TOCTOU on an allowlist (public → `169.254.169.254`).
- **gopher://** — raw-byte smuggling to Redis/FastCGI/SMTP/memcached → RCE.
- **Protocol smuggling** — `file://`, `dict://`, `ftp://`, CRLF-in-URL.
- **Indirect** — SSRF via PDF/SVG render, webhook, URL preview, image proxy.

## Methodology (recon → probe → confirm → exploit → chain)

1. **Recon.** Enumerate URL-consuming params across captured flows (webhooks,
   `?url=`, `?img=`, SSO callbacks, XML/SVG). `req search` for outbound fetch
   markers.
2. **Probe.** Point the param at your OOB `correlation_id` URL
   (`collab.payload_url(cid)`) and trigger the sink under `exec`.
3. **Confirm (deterministic, primary).** The `oob` oracle polls the collaborator
   for a `dns`/`http`/`rawtcp` callback carrying the correlation id. One hit =
   blind SSRF proven. For in-band + metadata, the `signature` oracle matches
   credential markers (`SecretAccessKey`, `ASIA…`, `Metadata-Flavor`) in the
   response; the `marker` oracle finds echoed content across history.
4. **Exploit / pivot internal.** `169.254.169.254`, `metadata.google.internal`,
   `127.0.0.1:PORT`, `[::]`, decimal/hex/octal IP encodings; `fuzz` the
   encoding-bypass wordlist ranked by anomaly.
5. **IMDSv2 handshake.** `req replay --method PUT --set-header
   'X-aws-ec2-metadata-token-ttl-seconds: 21600'` to mint the token, then reuse
   it via `X-aws-ec2-metadata-token`. If the SSRF primitive can't set method/
   headers, chain header-injection/smuggling to inject the token header.
6. **DNS-rebinding.** Serve a domain flipping public→`169.254.169.254`; burpwn's
   `dns` capture shows *which* IP the client resolved and reveals the TOCTOU window.
7. **gopher.** URL-encode a Redis `SET`/FastCGI payload behind `gopher://`.

## Cross-chain notes
- SSRF → cloud-metadata creds → cloud account takeover.
- SSRF → internal admin panel → access-control bypass.
- SSRF reachable *via* SQLi (`LOAD_FILE`), XXE (external entity), SSTI (RCE→curl).
- Redirect-based: chain `web-*` open-redirect so the server follows 302→internal.

## False-positive traps
- A 200 from the parameter is **not** SSRF. Require the OOB callback OR verbatim
  metadata content in the response — never a status/behaviour guess.
- `tls-passthru` flows mean MITM was blocked; report `blocked`, not clean.

## Key payload sources
- PortSwigger SSRF academy — `references`.
- `vendor/PayloadsAllTheThings/Server Side Request Forgery/` (IP encodings,
  cloud endpoints, gopher); HackTricks SSRF + Cloud-SSRF (path-only); gopherus.

## Verification oracle
Primary `oob` (collaborator DNS/HTTP/rawtcp callback). Metadata/in-band:
`signature` (credential markers), `marker` (echoed content). `verify.py` selects
the strongest oracle the caller wired inputs for.
