---
name: recon-subdomain-takeover
description: >
  Detect and prove subdomain takeover. USE WHEN subdomain enumeration surfaces a
  host whose DNS still points at a decommissioned third-party service (S3, Azure,
  GitHub Pages, Heroku, Fastly, Shopify, Netlify, Zendesk…) and the underlying
  resource is unclaimed. Covers dangling CNAME, dangling NS, and the claim-proof
  discipline that separates a real takeover from a generic 404.
tags: [recon, subdomain, takeover, dns, cname, dangling, supply-chain, attack-surface]
tools: [dig, curl, httpx, subfinder]
verification:
  kind: signature
references:
  - "https://book.hacktricks.wiki/en/pentesting-web/domain-subdomain-takeover.html"
  - "https://github.com/EdOverflow/can-i-take-over-xyz"
  - "https://portswigger.net/web-security/dom-based/open-redirection"
license: AGPL-3.0-or-later
version: 1.0.0
---
# Subdomain takeover — the dangling-pointer class

a2pwn enumerates subdomains automatically before the first planning phase, so this
class is now reachable on every apex-domain engagement — and it is the one where
recon output *is* the vulnerability. A host that answers "NoSuchBucket" is not a
404: it is an unclaimed resource an attacker can register and then serve content
from a domain the client owns (cookie theft on parent-domain cookies, OAuth
redirect-URI abuse, phishing with a valid certificate).

## Preconditions / triggers
- A subdomain resolves (CNAME or A) but the service answers with a provider-specific
  "unclaimed resource" page.
- A CNAME points at a provider hostname whose zone no longer exists (NXDOMAIN on the
  target of the CNAME, while the CNAME record itself still exists).
- Delegated NS records pointing at a nameserver that no longer serves the zone.

## Methodology
1. **Resolve the full chain, do not stop at the first answer.**
   `dig +noall +answer <sub>` then follow every CNAME hop. Record whether the FINAL
   hop is NXDOMAIN — a dangling CNAME whose target does not resolve is the strongest
   signal, and it is invisible if you only look at the HTTP response.
2. **Fetch over HTTP and HTTPS** through the sandbox and read the BODY. Provider
   fingerprints are body strings, not statuses: `NoSuchBucket`, `There isn't a GitHub
   Pages site here`, `no such app` (Heroku), `Fastly error: unknown domain`,
   `Sorry, this shop is currently unavailable` (Shopify), `Do you want to register
   *.wordpress.com?`. Many of these return **404 with a 200-shaped body** or vice
   versa; the status alone tells you nothing.
3. **Check claimability before claiming anything.** Cross-reference the fingerprint
   against can-i-take-over-xyz: several providers (e.g. modern S3 with
   account-scoped names) return the same page but are NOT claimable. A non-claimable
   fingerprint is an informational finding at most.
4. **DO NOT actually register the resource.** Claiming a namespace on a third-party
   provider is an action against a third party, outside the engagement's scope, and
   is not reversible on their side. The proof is the dangling pointer plus the
   claimability of the provider namespace — not a hijacked host.

## Oracle
`signature` — the provider's unclaimed-resource string in the captured response
body, plus the resolution chain. Pass the exact fingerprint in `oracle_signals`
(e.g. `["NoSuchBucket"]`) so the verifier re-derives it from the captured flow
rather than from your narrative. Capture BOTH the DNS resolution exec and the HTTP
fetch in the finding's workspace: the HTTP body alone does not prove the pointer is
dangling.

## Severity calibration
- **high** when the parent domain sets cookies scoped to `.example.com`, or the
  subdomain appears in an OAuth redirect-URI allow-list / CSP / CORS allow-list —
  takeover escalates directly to session compromise. Chain it with `enables`.
- **medium** for a plain unclaimed host with no such coupling.
- **info** when the fingerprint matches but the provider is not claimable.

## Pitfalls that produce false positives
- A generic vendor 404 page is not a takeover fingerprint. Match the SPECIFIC string.
- A wildcard DNS record (`*.example.com`) makes every random subdomain "resolve" —
  test a deliberately random label first (`a2pwn-nonexistent-<rand>.example.com`);
  if it answers identically, you are looking at a wildcard, not a dangling pointer.
- An internal-only host that does not resolve publicly is not in scope for takeover.
