"""Final report assembly.

Only ``independently_verified`` findings are promoted into the report — the
adversarial-verify gate and the independent-reproduction dispatch must both have
passed. For every distinct evidence workspace a HAR document is exported via the
CLI (``burpwn export har``), the cross-chain map is derived from ``Finding.enables``,
and a clean human-readable markdown document is rendered.
"""

from __future__ import annotations

import logging
import os

from pydantic import BaseModel, Field

from a2pwn.burpwn import BurpwnClient
from a2pwn.models import Finding

_log = logging.getLogger("a2pwn")

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


class Report(BaseModel):
    """The promoted, evidence-backed engagement result."""

    engagement: str
    findings: list[Finding] = Field(default_factory=list)  # ONLY independently_verified promoted
    cross_chains: list[list[str]] = Field(default_factory=list)  # finding.key chains via enables
    stats: dict = Field(default_factory=dict)
    har_paths: list[str] = Field(default_factory=list)


def _promote(findings: list[Finding]) -> list[Finding]:
    """Keep only independently verified findings, most-severe first (stable)."""

    promoted = [f for f in findings if f.independently_verified]
    return sorted(
        promoted,
        key=lambda f: (-_SEVERITY_ORDER.get(f.severity, 0), f.vuln_class, f.target, f.param or ""),
    )


def _distinct_workspaces(findings: list[Finding]) -> list[str]:
    """First-seen-ordered distinct evidence workspaces across promoted findings."""

    seen: list[str] = []
    for f in findings:
        ws = f.flow_batch.workspace
        if ws and ws not in seen:
            seen.append(ws)
    return seen


def _extend_paths(node: str, edges: dict[str, list[str]], path: list[str], chains: list[list[str]]) -> None:
    """Depth-first enumerate every maximal enable-chain, cycle-safe."""

    nexts = [n for n in edges.get(node, []) if n not in path]
    if not nexts:
        if len(path) >= 2:
            chains.append(list(path))
        return
    for n in nexts:
        _extend_paths(n, edges, [*path, n], chains)


def _build_cross_chains(findings: list[Finding]) -> list[list[str]]:
    """Derive maximal ``enables`` chains restricted to promoted finding keys."""

    keys = {f.key for f in findings}
    edges: dict[str, list[str]] = {}
    targets: set[str] = set()
    for f in findings:
        outs = sorted({e for e in f.enables if e in keys and e != f.key})
        if outs:
            edges[f.key] = outs
            targets.update(outs)
    roots = sorted(k for k in edges if k not in targets)
    if not roots and edges:  # pure cycle: seed from every edge origin
        roots = sorted(edges)
    chains: list[list[str]] = []
    for root in roots:
        _extend_paths(root, edges, [root], chains)
    return chains


def _compute_stats(findings: list[Finding], chains: list[list[str]], workspaces: list[str]) -> dict:
    by_severity: dict[str, int] = {}
    by_vuln_class: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_vuln_class[f.vuln_class] = by_vuln_class.get(f.vuln_class, 0) + 1
    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "by_vuln_class": by_vuln_class,
        "cross_chains": len(chains),
        "evidence_workspaces": len(workspaces),
    }


async def build_report(state, client: BurpwnClient, out_dir: str) -> Report:
    """Promote independently-verified findings, export per-workspace HARs, map chains.

    ``state`` is the terminal :class:`MasterState` mapping; ``client`` drives the
    burpwn CLI (its ``cli_export_har`` is a static helper reached through the
    instance so the export can be recorded/faked in tests). Evidence is already
    NUL-stripped at distill time.
    """

    engagement = state["engagement"]
    findings = _promote(list(state.get("findings", [])))
    workspaces = _distinct_workspaces(findings)
    chains = _build_cross_chains(findings)

    os.makedirs(out_dir, exist_ok=True)
    har_paths: list[str] = []
    for ws in workspaces:
        out = os.path.join(out_dir, f"{ws}.har")
        try:
            client.cli_export_har(engagement.session, out)
        except Exception as exc:  # noqa: BLE001 - one failed export must not lose the whole report
            _log.warning("HAR export failed for workspace %s (skipping): %s", ws, exc)
            continue
        har_paths.append(out)

    stats = _compute_stats(findings, chains, workspaces)
    return Report(
        engagement=engagement.name,
        findings=findings,
        cross_chains=chains,
        stats=stats,
        har_paths=har_paths,
    )


def _finding_section(f: Finding) -> list[str]:
    fb = f.flow_batch
    title = f"{f.vuln_class}" + (f" ({f.sub_variant})" if f.sub_variant else "")
    lines = [
        f"### [{f.severity.upper()}] {title}",
        "",
        f"- **Key:** `{f.key}`",
        f"- **Target:** {f.target}",
        f"- **Parameter:** {f.param or '*'}",
        f"- **Oracle:** {f.oracle_kind}",
        "- **Status:** independently verified",
    ]
    if f.enables:
        lines.append("- **Enables:** " + ", ".join(f"`{k}`" for k in f.enables))
    lines += [
        "",
        "**Evidence:**",
        "",
        "```",
        f.evidence,
        "```",
        "",
        "**Flow batch (captured proof):**",
        "",
        f"- Workspace: `{fb.workspace}`"
        + (f" (id {fb.workspace_id})" if fb.workspace_id is not None else ""),
        f"- Tag: `{fb.tag}` ({fb.color})",
        f"- Flow ids: {fb.flow_ids or '—'}",
        f"- Key flow: {fb.key_flow if fb.key_flow is not None else '—'}",
        f"- HAR: `{fb.workspace}.har`",
    ]
    if fb.note:
        lines.append(f"- Note: {fb.note}")
    if f.references:
        lines.append("- References: " + ", ".join(f.references))
    lines.append("")
    return lines


def render_markdown(r: Report) -> str:
    """Render a clean human report: findings + evidence + flow batches + chain map."""

    stats = r.stats or {}
    lines: list[str] = [
        f"# a2pwn report — {r.engagement}",
        "",
        "## Summary",
        "",
        f"- Verified findings: **{stats.get('total_findings', len(r.findings))}**",
        f"- Cross-chains: **{stats.get('cross_chains', len(r.cross_chains))}**",
        f"- Evidence workspaces: **{stats.get('evidence_workspaces', len(r.har_paths))}**",
    ]
    by_sev = stats.get("by_severity") or {}
    if by_sev:
        ordered = sorted(by_sev.items(), key=lambda kv: -_SEVERITY_ORDER.get(kv[0], 0))
        lines.append("- Severity: " + ", ".join(f"{sev} {n}" for sev, n in ordered))
    lines.append("")

    lines += ["## Findings", ""]
    if r.findings:
        for f in r.findings:
            lines += _finding_section(f)
    else:
        lines += ["_No independently verified findings._", ""]

    lines += ["## Cross-chain map", ""]
    if r.cross_chains:
        for chain in r.cross_chains:
            lines.append("- " + " → ".join(f"`{k}`" for k in chain))
    else:
        lines.append("_No cross-chains derived._")
    lines.append("")

    lines += ["## Evidence artifacts (HAR)", ""]
    if r.har_paths:
        for p in r.har_paths:
            lines.append(f"- `{p}`")
    else:
        lines.append("_No HAR artifacts exported._")
    lines.append("")

    return "\n".join(lines)
