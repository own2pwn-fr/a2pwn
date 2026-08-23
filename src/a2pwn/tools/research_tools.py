"""Research tools: deep JS analysis and public-CVE lookup, shared by both executor paths.

`js_analyze` is the deliberate inversion of "let the model read the bundle": the bundle stays in the
artifact store and the model receives endpoints, sourcemaps, library versions, credential-shaped
literals and DOM sinks as structured data. `cve_lookup` is what makes those library versions
actionable — and is the only thing in a2pwn that talks to the network outside burpwn, narrowly, to
public vulnerability databases (see `a2pwn.research` for why that exception is safe and how it is
bounded).
"""

from __future__ import annotations

from langchain_core.tools import BaseTool, StructuredTool

from a2pwn.artifacts import ArtifactStore
from a2pwn.jsaudit import analyse, decode_jwt_claims
from a2pwn.research import ALLOWED_HOSTS, ResearchClient

JS_ANALYZE_DESC = (
    "Statically analyse a stored JavaScript artifact and get back structured intelligence instead "
    "of the bytes: every URL and API path the bundle references (including admin/internal routes "
    "nothing links to), sourceMappingURL targets (a .map file reconstructs the original sources — "
    "always fetch it through burpwn if one is listed), library name/version pairs to feed into "
    "cve_lookup, credential-shaped literals, and the DOM sinks worth manual review. Every hit is a "
    "LEAD, not a finding: prove it with traffic and an oracle like anything else. Pass the "
    "artifact id you got from fetching the .js file through burpwn."
)

CVE_LOOKUP_DESC = (
    "Look up known vulnerabilities for a package version in the public OSV database (CVE/GHSA ids, "
    "summaries, CVSS). Use it on every library version js_analyze or a fingerprint turns up. This "
    "is the ONE tool that reaches the internet outside the burpwn sandbox, and only to public "
    "vulnerability databases — it can never touch the target. A known-vulnerable version is a LEAD: "
    "you still have to demonstrate the vulnerable code path is reachable and exploitable here."
)

RESEARCH_FETCH_DESC = (
    "GET a page from an allow-listed vulnerability-intelligence source (" + ", ".join(sorted(ALLOWED_HOSTS)) + ") "
    "— an advisory write-up, a deps.dev record. Refused for anything else, and refused outright for "
    "engagement targets, which must go through burpwn so their traffic is captured."
)

JWT_DECODE_DESC = (
    "Decode a JWT's payload claims without validating its signature. Use it to read alg/kid/iss/exp "
    "and any role or tenant claim before deciding how to attack the token."
)

JS_ANALYZE_SCHEMA: dict = {"artifact_id": str}
CVE_LOOKUP_SCHEMA: dict = {"ecosystem": str, "package": str, "version": str}
RESEARCH_FETCH_SCHEMA: dict = {"url": str}
JWT_DECODE_SCHEMA: dict = {"token": str}


async def run_js_analyze(store: ArtifactStore, artifact_id: str) -> dict:
    artifact = store.get(artifact_id) if store else None
    if artifact is None:
        return {"error": f"no such artifact {artifact_id}"}
    if artifact.dropped_reason:
        return {"error": f"{artifact_id} was dropped as not relevant: {artifact.dropped_reason}"}
    text = artifact.content()
    if not text:
        return {"error": f"{artifact_id} has no readable content"}
    return {"artifact": artifact_id, **analyse(text)}


def research_tools(store: ArtifactStore, client: ResearchClient) -> list[BaseTool]:
    async def js_analyze(artifact_id: str) -> dict:
        return await run_js_analyze(store, artifact_id)

    async def cve_lookup(package: str, ecosystem: str = "npm", version: str = "") -> dict:
        return await client.osv_query(ecosystem, package, version)

    async def research_fetch(url: str) -> dict:
        return await client.fetch(url)

    async def jwt_decode(token: str) -> dict:
        return {"claims": decode_jwt_claims(token)}

    specs = (
        (js_analyze, "js_analyze", JS_ANALYZE_DESC),
        (cve_lookup, "cve_lookup", CVE_LOOKUP_DESC),
        (research_fetch, "research_fetch", RESEARCH_FETCH_DESC),
        (jwt_decode, "jwt_decode", JWT_DECODE_DESC),
    )
    out: list[BaseTool] = []
    for fn, name, desc in specs:
        fn.__doc__ = desc
        out.append(StructuredTool.from_function(coroutine=fn, name=name))
    return out
