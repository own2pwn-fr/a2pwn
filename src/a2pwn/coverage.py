"""Attack-surface inventory and the coverage matrix — exhaustiveness as a data structure.

Until this module existed, "did we test everything?" was answered entirely by prose. The executor
prompt told the model to "walk the co-located class checklist", the continuation judge was told to
"bias toward THOROUGHNESS", and nothing anywhere recorded which endpoint had been probed for which
vulnerability class. The master carried tasks, findings and a budget; a *negative* result — endpoint
reached, parameter fuzzed, nothing found — left no trace at all, so an endpoint that was probed and
came back clean was indistinguishable from one that was never touched. A run could therefore stop,
report zero findings, and be structurally unable to say whether that meant "secure" or "unvisited".

Two structures fix that:

* :class:`Asset` — one addressable unit of attack surface (host, endpoint, parameter, JS bundle,
  WebSocket channel). Assets are harvested **deterministically from captured burpwn flows**, not
  from the model's narration, because the traffic is ground truth and the narration is not.
* :class:`Probe` — one (asset, vuln_class) cell with a verdict. The cross product of applicable
  classes over discovered assets IS the coverage matrix, and the untested cells are a work-list the
  planner can be handed instead of being asked to remember what it has not done yet.

The matrix is monotone in the same sense the findings reducer is: a cell only ever moves toward more
knowledge (`untested → probed → proven`), never back, so a later dispatch cannot erase what an
earlier one established.
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, Field

if TYPE_CHECKING:  # `models` imports Probe from here, so the reverse edge must stay lazy.
    from a2pwn.models import TaskSpec

AssetKind = Literal["host", "endpoint", "param", "js", "websocket", "graphql"]
Verdict = Literal["untested", "probed", "not_applicable", "blocked", "proven"]

# Verdict precedence, low to high. A merge keeps the more informative side; nothing demotes.
_RANK: dict[str, int] = {
    "untested": 0,
    "not_applicable": 1,
    "blocked": 2,
    "probed": 3,
    "proven": 4,
}

# --------------------------------------------------------------------------- #
# applicability: which classes are worth spending a dispatch on, per asset kind #
# --------------------------------------------------------------------------- #
# Keyed to the shipped skill names (minus the `web-`/`recon-` prefix) so the matrix and the
# methodology corpus cannot drift apart. A class is listed at the COARSEST level it makes sense at:
# `cors` is a property of an origin, so it is a host cell and is tested once — listing it per
# parameter would generate hundreds of redundant dispatches and drown the genuinely untested cells.
HOST_CLASSES: tuple[str, ...] = (
    "tech-fingerprint",
    "content-discovery",
    "subdomain-takeover",
    "js-supplychain",
    "authentication",
    "jwt-auth",
    "oauth-oidc",
    "cors",
    "host-header",
    "hop-by-hop",
    "request-smuggling",
    "http2-desync",
    "http3-quic",
    "cache-poisoning",
    "cache-deception",
)

ENDPOINT_CLASSES: tuple[str, ...] = (
    "access-control",
    "idor-bola",
    "csrf",
    "race-condition",
    "mass-assignment",
    "api-business-logic",
    "file-upload",
)

# The injection-and-friends family: anything that takes attacker-controlled input at a sink.
PARAM_CLASSES: tuple[str, ...] = (
    "sqli",
    "nosql-injection",
    "ldap-xpath-injection",
    "command-injection",
    "ssti",
    "xss",
    "path-traversal-lfi",
    "ssrf",
    "open-redirect",
    "xxe",
    "deserialization",
    "prototype-pollution",
)

_KIND_CLASSES: dict[str, tuple[str, ...]] = {
    "host": HOST_CLASSES,
    "endpoint": ENDPOINT_CLASSES,
    "param": PARAM_CLASSES,
    "js": ("js-supplychain",),
    "websocket": ("websocket",),
    "graphql": ("graphql",),
}


def applicable_classes(asset: Asset) -> tuple[str, ...]:
    """Vulnerability classes worth testing against this asset."""
    return _KIND_CLASSES.get(asset.kind, ())


# --------------------------------------------------------------------------- #
# assets                                                                        #
# --------------------------------------------------------------------------- #
class Asset(BaseModel):
    """One addressable unit of attack surface."""

    kind: AssetKind
    host: str
    path: str = ""
    method: str = ""
    param: str | None = None
    # Where an attacker-controlled parameter lives, which decides which sinks it can reach.
    location: Literal["query", "body", "json", "header", "cookie", "path"] | None = None
    note: str = ""
    # A CONCRETE, requestable URL for this asset. `path` is normalised (`/order/42` -> `/order/{id}`)
    # so the matrix does not explode into one asset per row id, but that placeholder is not a URL:
    # dispatching `https://h/order/{id}` sends the sub-agent (and the scope guard) an address that
    # cannot be requested. Keep one real sighting alongside the normalised key. The scheme matters
    # for the same reason — an http-only or odd-port target is not reachable at https://.
    example_url: str = ""
    # How the asset came to be known — a flow id, "config", "propose_targets"…
    source: str = ""

    @property
    def key(self) -> str:
        return asset_key(self.kind, self.host, self.path, self.method, self.param)

    def label(self) -> str:
        """Human-shaped identity, used in generated task text and the report."""
        if self.kind == "host":
            return self.host
        if self.kind == "param":
            return f"{self.method or 'GET'} {self.host}{self.path} [{self.location or 'query'}:{self.param}]"
        return f"{self.method or 'GET'} {self.host}{self.path}".strip()


def asset_key(kind: str, host: str, path: str = "", method: str = "", param: str | None = None) -> str:
    """Canonical identity of an asset. Case-insensitive on host and method, exact on path."""
    return "|".join([kind, host.strip().lower(), _norm_path(path), (method or "").upper(), param or ""])


class Probe(BaseModel):
    """One cell of the coverage matrix: what we know about (asset, vuln_class)."""

    asset_key: str
    vuln_class: str
    verdict: Verdict = "untested"
    dispatch_id: str = ""
    # A captured flow that backs the claim. A `probed` verdict with no flow is a claim the model
    # made about its own work; with one, it is a claim the capture can be held against.
    evidence_flow: int | None = None
    note: str = ""

    @property
    def key(self) -> str:
        return f"{self.asset_key}#{self.vuln_class}"


class SurfaceMap(BaseModel):
    """The engagement's attack surface and everything known about testing it."""

    assets: dict[str, Asset] = Field(default_factory=dict)
    probes: dict[str, Probe] = Field(default_factory=dict)
    # Highest burpwn flow id already folded in, so harvesting is incremental rather than a full
    # re-scan of the capture every phase.
    harvest_cursor: int = 0

    def add_asset(self, asset: Asset) -> None:
        existing = self.assets.get(asset.key)
        if existing is None:
            self.assets[asset.key] = asset
            return
        # Keep the richer description: a later sighting may carry a note or a location the first
        # one lacked, and losing that would cost applicable classes.
        merged = existing.model_copy(
            update={
                "note": existing.note or asset.note,
                "location": existing.location or asset.location,
                "source": existing.source or asset.source,
                "example_url": existing.example_url or asset.example_url,
            }
        )
        self.assets[asset.key] = merged

    def record(self, probe: Probe) -> None:
        prior = self.probes.get(probe.key)
        if prior is None or _RANK[probe.verdict] >= _RANK[prior.verdict]:
            self.probes[probe.key] = probe

    def verdict_of(self, asset_key_: str, vuln_class: str) -> Verdict:
        probe = self.probes.get(f"{asset_key_}#{vuln_class}")
        return probe.verdict if probe else "untested"

    def untested(self) -> list[tuple[Asset, str]]:
        """Every (asset, class) cell nothing has claimed yet — the work-list, in discovery order."""
        out: list[tuple[Asset, str]] = []
        for asset in self.assets.values():
            for vuln_class in applicable_classes(asset):
                if self.verdict_of(asset.key, vuln_class) == "untested":
                    out.append((asset, vuln_class))
        return out

    def stats(self) -> dict:
        total = sum(len(applicable_classes(a)) for a in self.assets.values())
        tally: dict[str, int] = {}
        for asset in self.assets.values():
            for vuln_class in applicable_classes(asset):
                tally[self.verdict_of(asset.key, vuln_class)] = (
                    tally.get(self.verdict_of(asset.key, vuln_class), 0) + 1
                )
        by_kind: dict[str, int] = {}
        for asset in self.assets.values():
            by_kind[asset.kind] = by_kind.get(asset.kind, 0) + 1
        return {
            "assets": len(self.assets),
            "assets_by_kind": by_kind,
            "cells": total,
            "by_verdict": tally,
            "untested": tally.get("untested", 0),
            "covered_pct": round(100.0 * (total - tally.get("untested", 0)) / total, 1) if total else 0.0,
        }


def merge_surface(left: SurfaceMap | None, right: SurfaceMap | None) -> SurfaceMap:
    """LangGraph reducer for the ``surface`` channel.

    Must tolerate a parallel `Send` fan-out: several dispatches return partial maps for the same
    phase and every one of them has to land. Monotone by construction — `add_asset`/`record` only
    ever move a cell up the verdict ranking, so a sibling that probed nothing cannot erase a
    sibling that proved something.
    """
    if left is None:
        return (right or SurfaceMap()).model_copy(deep=True)
    if right is None:
        return left.model_copy(deep=True)
    out = left.model_copy(deep=True)
    # Deep-copy the incoming rows too: inserting `right`'s own pydantic objects by reference would
    # leave the merged channel value aliasing an operand's mutable state — the same shape as the
    # budget-caps bug that this channel's monotone design exists to avoid.
    for asset in right.assets.values():
        out.add_asset(asset.model_copy(deep=True))
    for probe in right.probes.values():
        out.record(probe.model_copy(deep=True))
    out.harvest_cursor = max(out.harvest_cursor, right.harvest_cursor)
    return out


# --------------------------------------------------------------------------- #
# harvesting surface from captured traffic                                      #
# --------------------------------------------------------------------------- #
_JS_RE = re.compile(r"\.m?js(\?|$)", re.I)
# Segment-anchored: `/graphql-docs` and `/lang/gql-tutorial` are ordinary endpoints, and filing
# them as GraphQL would strip them of their seven endpoint-level classes.
_GRAPHQL_RE = re.compile(r"/(graphql|gql)(/|$)", re.I)
_BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_NOISE_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "_", "cb"}


def _norm_path(path: str) -> str:
    """Strip the query string and collapse obvious id segments so `/order/1` and `/order/2` are
    one endpoint rather than two thousand."""
    raw = urlsplit(path or "").path or "/"
    parts = []
    for seg in raw.split("/"):
        if seg and (seg.isdigit() or _looks_like_id(seg)):
            parts.append("{id}")
        else:
            parts.append(seg)
    return "/".join(parts) or "/"


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HEXID_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)


def _looks_like_id(seg: str) -> bool:
    return bool(_UUID_RE.match(seg) or _HEXID_RE.match(seg))


def assets_from_flow(flow: dict) -> list[Asset]:
    """Derive every asset a single captured flow reveals.

    Deterministic and source-of-truth: this reads the traffic burpwn actually captured, so it
    cannot over-report (an endpoint nobody reached) or under-report because the model forgot to
    mention something it visited.
    """
    host = str(flow.get("authority") or flow.get("sni") or flow.get("host") or "").strip()
    if not host:
        return []
    raw_path = str(flow.get("path") or "/")
    method = str(flow.get("method") or "GET").upper()
    protocol = str(flow.get("protocol") or "")
    scheme = str(flow.get("scheme") or ("http" if protocol == "h1" and ":80" in host else "https"))
    fid = flow.get("id")
    source = f"flow:{fid}" if fid is not None else "flow"
    path = _norm_path(raw_path)
    url = f"{scheme}://{host}{raw_path}"

    out: list[Asset] = [
        Asset(kind="host", host=host, example_url=f"{scheme}://{host}", source=source)
    ]

    if protocol == "ws":
        out.append(Asset(kind="websocket", host=host, path=path, example_url=url, source=source))
        return out
    if protocol in {"dns", "rawtcp", "tls-passthru"}:
        return out

    if _JS_RE.search(raw_path):
        out.append(Asset(kind="js", host=host, path=path, example_url=url, source=source))
        return out

    kind: AssetKind = "graphql" if _GRAPHQL_RE.search(path) else "endpoint"
    out.append(
        Asset(kind=kind, host=host, path=path, method=method, example_url=url, source=source)
    )

    query = urlsplit(raw_path).query
    for name, _ in parse_qsl(query, keep_blank_values=True):
        if name in _NOISE_PARAMS:
            continue
        out.append(
            Asset(
                kind="param",
                host=host,
                path=path,
                method=method,
                param=name,
                location="query",
                example_url=url,
                source=source,
            )
        )
    return out


_MAX_BODY_PARAMS = 40
_MAX_JSON_DEPTH = 4


def _json_param_names(value, prefix: str = "", depth: int = 0) -> list[str]:
    """Flatten a JSON body into dotted parameter names (`user.address.city`, `items[].sku`)."""
    if depth > _MAX_JSON_DEPTH:
        return []
    out: list[str] = []
    if isinstance(value, dict):
        for key, sub in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            out.append(name)
            out.extend(_json_param_names(sub, name, depth + 1))
    elif isinstance(value, list) and value:
        out.extend(_json_param_names(value[0], f"{prefix}[]" if prefix else "[]", depth + 1))
    return out


def params_from_detail(detail: dict) -> list[Asset]:
    """Parameter assets carried in a request BODY, from a ``req_show`` payload.

    Query strings are visible in the flow listing; body and JSON parameters are not, and they are
    where a modern API keeps every one of its injection sinks. Without this an API-shaped target
    produced host and endpoint cells and *zero* parameter cells, and the matrix would cheerfully
    report full coverage of a surface whose actual input sinks had never been enumerated.
    """
    req = detail.get("request") or {}
    body = req.get("body")
    if not body or not isinstance(body, str):
        return []
    host = str(req.get("authority") or "").strip()
    if not host:
        return []
    raw_path = str(req.get("path") or "/")
    method = str(req.get("method") or "POST").upper()
    scheme = str(detail.get("scheme") or "https")
    path = _norm_path(raw_path)
    url = f"{scheme}://{host}{raw_path}"
    fid = detail.get("id")
    source = f"flow:{fid}" if fid is not None else "flow"
    headers = str(req.get("headers") or "").lower()

    names: list[str] = []
    location: str = "body"
    stripped = body.lstrip()
    if "application/json" in headers or stripped[:1] in "{[":
        try:
            names = _json_param_names(json.loads(body))
            location = "json"
        except (ValueError, TypeError):
            names = []
    if not names:
        names = [n for n, _ in parse_qsl(body, keep_blank_values=True)]
        location = "body"

    out: list[Asset] = []
    for name in names[:_MAX_BODY_PARAMS]:
        if not name or name in _NOISE_PARAMS:
            continue
        out.append(
            Asset(
                kind="param",
                host=host,
                path=path,
                method=method,
                param=name,
                location=location,  # type: ignore[arg-type]
                example_url=url,
                source=source,
            )
        )
    return out


def needs_body_harvest(flow: dict) -> bool:
    """Is this flow worth one extra ``req_show`` to enumerate its body parameters?"""
    return str(flow.get("method") or "").upper() in _BODY_METHODS


def harvest(surface: SurfaceMap, flows: list[dict]) -> SurfaceMap:
    """Fold a batch of captured flows into the surface map, advancing the incremental cursor.

    The cursor advances ONCE, after the whole batch. Advancing it inside the loop made the result
    depend on the input order: a proxy history returned newest-first would harvest the first flow,
    push the cursor past every remaining id, and silently drop the rest — one endpoint per phase,
    with a matrix that looks plausible and is mostly empty.
    """
    out = surface.model_copy(deep=True)
    seen_max = out.harvest_cursor
    for flow in flows:
        try:
            fid = int(flow.get("id") or 0)
        except (TypeError, ValueError):
            fid = 0
        seen_max = max(seen_max, fid)
        if fid and fid <= out.harvest_cursor:
            continue
        for asset in assets_from_flow(flow):
            out.add_asset(asset)
    out.harvest_cursor = seen_max
    return out


# --------------------------------------------------------------------------- #
# turning untested cells into dispatchable work                                 #
# --------------------------------------------------------------------------- #
_CLASSES_PER_TASK = 4


def expand_coverage_tasks(surface: SurfaceMap, limit: int = 6) -> list[TaskSpec]:
    """Generate concrete tasks for untested cells — deterministic planning, no model involved.

    This is the mechanism that makes exhaustiveness structural. The LLM planner is a *prioritiser*:
    it decides what is worth doing next given what has been learned. It is a poor *enumerator*,
    because enumerating requires remembering every endpoint it has seen and every class it has not
    yet tried, across a history truncated to the last eight records. The matrix remembers instead.

    Cells are grouped per asset (up to `_CLASSES_PER_TASK` classes per dispatch) so a hundred
    untested cells become a manageable batch of tasks rather than a hundred dispatches, and hosts
    are emitted before endpoints before parameters so recon-shaped work lands first.
    """
    if limit <= 0:
        return []
    order = {"host": 0, "js": 1, "graphql": 2, "endpoint": 3, "websocket": 4, "param": 5}
    grouped: dict[str, list[str]] = {}
    assets: dict[str, Asset] = {}
    for asset, vuln_class in surface.untested():
        grouped.setdefault(asset.key, []).append(vuln_class)
        assets[asset.key] = asset

    ranked = sorted(assets.values(), key=lambda a: (order.get(a.kind, 9), a.host, a.path, a.param or ""))
    tasks: list[TaskSpec] = []
    for asset in ranked:
        classes = grouped.get(asset.key, [])
        for i in range(0, len(classes), _CLASSES_PER_TASK):
            if len(tasks) >= limit:
                return tasks
            chunk = classes[i : i + _CLASSES_PER_TASK]
            tasks.append(_task_for(asset, chunk))
    return tasks


def _task_for(asset: Asset, classes: list[str]) -> TaskSpec:
    from a2pwn.models import TaskSpec

    joined = ", ".join(classes)
    # The concrete sighting, never the normalised key: `https://h/order/{id}` is not an address.
    target = asset.example_url or (
        f"https://{asset.host}{asset.path}" if asset.kind != "host" else f"https://{asset.host}"
    )
    if asset.kind == "param":
        task = (
            f"Probe the {asset.location or 'query'} parameter `{asset.param}` of "
            f"{asset.method or 'GET'} {target} for: {joined}. "
            "Actually inject and observe — a class counts as tested only when a payload was sent and "
            "its response judged. Call `record_probe` for every class you clear."
        )
        intent: Literal["recon", "exploit", "chain", "verify"] = "exploit"
    elif asset.kind == "host":
        task = (
            f"Assess {asset.host} for: {joined}. Report what you prove, and call `record_probe` for "
            "each class you test and find clean so the coverage matrix records it."
        )
        intent = "recon" if set(classes) & {"tech-fingerprint", "content-discovery"} else "exploit"
    else:
        task = (
            f"Test {asset.method or 'GET'} {target} for: {joined}. "
            "Call `record_probe` for every class you clear so it is not re-dispatched."
        )
        intent = "exploit"
    return TaskSpec(
        task=task,
        intent=intent,
        target=target,
        hints=[f"coverage-cell={asset.key}", f"classes={joined}"],
        # Coverage sweeps are read-mostly probes; serialising them all against one target would
        # collapse the fan-out to a single dispatch per phase for no safety gain.
        mutates=asset.kind == "param",
    )


def coverage_digest(surface: SurfaceMap, max_lines: int = 25) -> str:
    """A compact, model-readable statement of what is left — fed to the planner and the judge.

    Deliberately terse: the planner's context is already carrying history and findings, and a
    thousand-line matrix dump would push both out of the window it can actually use.
    """
    st = surface.stats()
    lines = [
        f"assets={st['assets']} ({', '.join(f'{k}:{v}' for k, v in sorted(st['assets_by_kind'].items()))})",
        f"matrix cells={st['cells']} covered={st['covered_pct']}% untested={st['untested']}",
    ]
    # Grouped by KEY, not by label: labels collide across kinds (a websocket asset and a GET
    # endpoint on the same path both render as `GET host/path`), and merging two assets' remaining
    # classes onto one line would corrupt the model's only view of the matrix.
    grouped: dict[str, tuple[str, list[str]]] = {}
    for asset, vuln_class in surface.untested():
        _, classes = grouped.setdefault(asset.key, (asset.label(), []))
        classes.append(vuln_class)
    if grouped:
        lines.append("UNTESTED (asset -> classes):")
        for label, classes in list(grouped.values())[:max_lines]:
            lines.append(f"  {label} -> {', '.join(classes)}")
        if len(grouped) > max_lines:
            lines.append(f"  … and {len(grouped) - max_lines} more asset(s)")
    else:
        lines.append("UNTESTED: none — every applicable class has a verdict on every known asset.")
    return "\n".join(lines)
