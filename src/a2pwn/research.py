"""External intelligence lookups — CVE/advisory research, deliberately outside the sandbox.

a2pwn's load-bearing invariant is that **burpwn is the only egress to the target**. This module is
the one place that talks to the network without it, and the distinction it rests on is that these
hosts are not the target: they are public vulnerability databases. Routing an OSV query through the
engagement's MITM sandbox would prove nothing, and — worse — the scope guard correctly refuses it,
which is exactly why CVE research was impossible before this existed. The `js-supplychain` skill has
been telling the model to "query OSV.dev / deps.dev / GitHub Advisory" for as long as it has
shipped, with no mechanism that could do it.

Two controls keep that exception narrow:

* a **fixed allow-list** of intel hosts, so this cannot become a general-purpose fetch that reaches
  the target off-sandbox, and
* an explicit refusal when the requested host is inside the engagement scope, so a redirected or
  hallucinated URL cannot turn an intel lookup into uncaptured target traffic.

Operational note the operator is shown before the authorization gate: package names and version
strings discovered on the client's estate leave the machine when this is used. `--no-research`
turns it off.
"""

from __future__ import annotations

import json
import logging
from typing import Any

_log = logging.getLogger("a2pwn")

# Public vulnerability intelligence only. Deliberately not extensible at runtime: a config-driven
# allow-list would let an engagement file re-open the off-sandbox egress this module narrowly opens.
ALLOWED_HOSTS: frozenset[str] = frozenset(
    {
        "api.osv.dev",
        "osv.dev",
        "api.deps.dev",
        "deps.dev",
        "api.github.com",
        "services.nvd.nist.gov",
        "cve.circl.lu",
        "endoflife.date",
    }
)

_TIMEOUT = 20.0
_MAX_BODY = 200_000
# OSV ecosystem names are case-sensitive; map the spellings a model is likely to produce.
_ECOSYSTEMS = {
    "npm": "npm",
    "node": "npm",
    "javascript": "npm",
    "js": "npm",
    "pypi": "PyPI",
    "python": "PyPI",
    "pip": "PyPI",
    "maven": "Maven",
    "java": "Maven",
    "go": "Go",
    "golang": "Go",
    "packagist": "Packagist",
    "composer": "Packagist",
    "php": "Packagist",
    "rubygems": "RubyGems",
    "ruby": "RubyGems",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "dotnet": "NuGet",
    "crates.io": "crates.io",
    "cargo": "crates.io",
    "rust": "crates.io",
}


class ResearchDisabled(RuntimeError):
    """Raised when a lookup is attempted on a run started with --no-research."""


def normalise_ecosystem(name: str) -> str:
    return _ECOSYSTEMS.get((name or "").strip().lower(), (name or "").strip() or "npm")


def host_allowed(host: str) -> bool:
    return (host or "").strip().lower() in ALLOWED_HOSTS


class ResearchClient:
    """Thin HTTP client for the intel allow-list.

    ``in_scope_hosts`` is the engagement's own surface. A request to any of them is refused even if
    the host somehow appears on the allow-list, because the whole point of the burpwn invariant is
    that target traffic is captured, and a lookup issued from this process is not.
    """

    def __init__(self, enabled: bool = True, in_scope_hosts: list[str] | None = None) -> None:
        self.enabled = enabled
        self._in_scope = {h.strip().lower() for h in (in_scope_hosts or []) if h}

    def _check(self, host: str) -> str | None:
        if not self.enabled:
            return "research is disabled for this engagement (--no-research)"
        host = (host or "").strip().lower()
        if host in self._in_scope:
            return (
                f"REFUSED: {host} is an engagement target. Target traffic must go through burpwn so "
                "it is captured; this channel is for public vulnerability databases only."
            )
        if not host_allowed(host):
            return (
                f"REFUSED: {host} is not a permitted intelligence source. Allowed: "
                f"{', '.join(sorted(ALLOWED_HOSTS))}."
            )
        return None

    async def _request(self, method: str, url: str, payload: dict | None = None) -> dict:
        from urllib.parse import urlsplit

        host = urlsplit(url).hostname or ""
        refusal = self._check(host)
        if refusal:
            return {"refused": True, "error": refusal}
        try:
            import httpx
        except ImportError:  # pragma: no cover - httpx ships with the collaborator dependency set
            return {"error": "httpx is not installed; CVE research unavailable"}
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False) as http:
                resp = await http.request(
                    method, url, json=payload, headers={"User-Agent": "a2pwn-research"}
                )
        except Exception as exc:  # noqa: BLE001 - an intel outage must never abort an engagement
            _log.warning("research request to %s failed: %s", host, exc)
            return {"error": f"research request failed: {exc}"}
        body = resp.text[:_MAX_BODY]
        try:
            return {"status": resp.status_code, "json": json.loads(body)}
        except ValueError:
            return {"status": resp.status_code, "text": body}

    async def osv_query(self, ecosystem: str, package: str, version: str = "") -> dict:
        """Known vulnerabilities for one package version, from OSV (free, no key, authoritative)."""
        pkg: dict[str, Any] = {"name": package, "ecosystem": normalise_ecosystem(ecosystem)}
        payload: dict[str, Any] = {"package": pkg}
        if version:
            payload["version"] = version
        out = await self._request("POST", "https://api.osv.dev/v1/query", payload)
        if "json" not in out:
            return out
        return {"package": package, "version": version, "vulns": _summarise_osv(out["json"])}

    async def fetch(self, url: str) -> dict:
        """GET an allow-listed intelligence URL (an advisory page, a deps.dev record)."""
        return await self._request("GET", url)


def _summarise_osv(payload: Any) -> list[dict]:
    """Compress an OSV response to what actually drives a decision.

    A raw OSV record carries every affected range for every ecosystem and can run to tens of
    kilobytes per vulnerability; handing that to the model would evict the engagement context to say
    what four fields already say.
    """
    vulns = payload.get("vulns") if isinstance(payload, dict) else None
    out: list[dict] = []
    for v in vulns or []:
        if not isinstance(v, dict):
            continue
        severity = ""
        for entry in v.get("severity") or []:
            if isinstance(entry, dict) and entry.get("score"):
                severity = str(entry["score"])
                break
        aliases = [a for a in (v.get("aliases") or []) if isinstance(a, str)]
        out.append(
            {
                "id": v.get("id"),
                "aliases": aliases[:6],
                "summary": str(v.get("summary") or "")[:300],
                "severity": severity,
                "published": v.get("published"),
            }
        )
    return out
