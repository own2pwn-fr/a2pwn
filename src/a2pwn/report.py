"""Final report assembly.

Only ``independently_verified`` findings are promoted into the report — the
adversarial-verify gate and the independent-reproduction dispatch must both have
passed. For every distinct evidence workspace a HAR document is exported via the
CLI (``burpwn export har``), the cross-chain map is derived from ``Finding.enables``,
and a clean human-readable markdown document is rendered.
"""

from __future__ import annotations

import html
import json
import logging
import os
import re

from pydantic import BaseModel, Field

from a2pwn.burpwn import BurpwnClient
from a2pwn.models import Finding

_log = logging.getLogger("a2pwn")


def _safe_name(token: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", token) or "ws"


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
    # Oracle-CONFIRMED but not independently reproduced (race/one-shot/TOCTOU): a separate, weaker
    # tier so the interesting-but-flaky bugs are surfaced instead of silently dropped. Never merged
    # into ``findings`` — the verified tier stays strict.
    confirmed_findings: list[Finding] = Field(default_factory=list)
    cross_chains: list[list[str]] = Field(default_factory=list)  # finding.key chains via enables
    stats: dict = Field(default_factory=dict)
    har_paths: list[str] = Field(default_factory=list)
    # Written artifact paths keyed by format ("md"/"json"/"sarif"/"html").
    report_paths: dict = Field(default_factory=dict)
    # --- engagement metadata (all optional; defaults keep old constructors valid) ---
    objective: str = ""
    targets: list[str] = Field(default_factory=list)
    models: dict = Field(default_factory=dict)  # e.g. {"executor": ..., "verifier": ...}
    dispatches_spent: int = 0
    started_at: str = ""
    duration_secs: float = 0.0


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-_SEVERITY_ORDER.get(f.severity, 0), f.vuln_class, f.target, f.param or ""),
    )


def _promote(findings: list[Finding]) -> list[Finding]:
    """Keep only independently verified findings, most-severe first (stable)."""

    return _sort_findings([f for f in findings if f.independently_verified])


def _confirmed_only(findings: list[Finding]) -> list[Finding]:
    """Oracle-confirmed findings that were NOT independently reproduced, most-severe first.

    These are the race/one-shot/TOCTOU bugs the independent-verify dispatch could not replay from a
    clean slate; dropping them entirely is a false negative on exactly the interesting findings, so
    they are reported in a distinct, clearly-labelled high-confidence tier."""

    return _sort_findings([f for f in findings if f.confirmed and not f.independently_verified])


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


def _compute_stats(
    findings: list[Finding],
    confirmed_only: list[Finding],
    chains: list[list[str]],
    workspaces: list[str],
) -> dict:
    by_severity: dict[str, int] = {}
    by_vuln_class: dict[str, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_vuln_class[f.vuln_class] = by_vuln_class.get(f.vuln_class, 0) + 1
    return {
        "total_findings": len(findings),
        "confirmed_only": len(confirmed_only),
        "by_severity": by_severity,
        "by_vuln_class": by_vuln_class,
        "cross_chains": len(chains),
        "evidence_workspaces": len(workspaces),
    }


async def build_report(
    state,
    client: BurpwnClient,
    out_dir: str,
    *,
    models: dict | None = None,
    started_at: str = "",
    duration_secs: float = 0.0,
    formats: list[str] | set[str] | None = None,
) -> Report:
    """Promote independently-verified findings, export per-workspace HARs, map chains, and write the
    report in every requested format (md + json always; sarif/html gated on ``formats``).

    ``state`` is the terminal :class:`MasterState` mapping; ``client`` drives the
    burpwn CLI (its ``cli_export_har`` is a static helper reached through the
    instance so the export can be recorded/faked in tests). Evidence is already
    NUL-stripped at distill time. ``models``/``started_at``/``duration_secs`` are engagement
    metadata a caller (``run_engagement``) threads in; all optional so existing callers/tests hold.
    """

    engagement = state["engagement"]
    all_findings = list(state.get("findings", []))
    findings = _promote(all_findings)
    confirmed_only = _confirmed_only(all_findings)
    # HAR evidence export stays scoped to the strict verified tier (the confirmed-only tier is
    # surfaced in the report body, but its per-workspace HAR is not force-exported).
    workspaces = _distinct_workspaces(findings)
    chains = _build_cross_chains(findings)

    os.makedirs(out_dir, exist_ok=True)
    har_paths: list[str] = []
    # Per-finding evidence HAR, scoped to its workspace ID where known; plus a whole-session HAR as
    # the always-present fallback (some findings lack a resolved workspace_id).
    ws_ids: dict[str, int | None] = {}
    for f in findings:
        ws_ids.setdefault(f.flow_batch.workspace, f.flow_batch.workspace_id)
    exports: list[tuple[str, int | None]] = [("evidence-all", None)]
    exports += [(ws, wid) for ws, wid in ws_ids.items() if wid is not None]
    for name, wid in exports:
        out = os.path.join(out_dir, f"{_safe_name(name)}.har")
        try:
            client.cli_export_har(engagement.session, out, wid)
        except Exception as exc:  # noqa: BLE001 - one failed export must not lose the whole report
            _log.warning("HAR export failed for %s (skipping): %s", name, exc)
            continue
        if os.path.exists(out):
            har_paths.append(out)

    stats = _compute_stats(findings, confirmed_only, chains, workspaces)
    report = Report(
        engagement=engagement.name,
        findings=findings,
        confirmed_findings=confirmed_only,
        cross_chains=chains,
        stats=stats,
        har_paths=har_paths,
        objective=str(state.get("objective", "") or ""),
        targets=list(getattr(engagement, "targets", []) or []),
        models=dict(models or {}),
        dispatches_spent=int(state.get("spent", 0) or 0),
        started_at=started_at,
        duration_secs=duration_secs,
    )
    report.report_paths = _write_reports(report, out_dir, formats)
    return report


def _write_reports(report: Report, out_dir: str, formats: list[str] | set[str] | None) -> dict:
    """Write the report in the requested formats. ``md`` and ``json`` are always written; ``sarif``
    and ``html`` are gated on ``formats`` (default: all four). Returns the written paths by format."""

    want = {str(f).strip().lower() for f in (formats or []) if str(f).strip()}
    if not want:
        want = {"md", "json", "sarif", "html"}
    renderers: list[tuple[str, str, str]] = [
        ("md", "report.md", render_markdown(report)),
        ("json", "report.json", report.model_dump_json(indent=2)),
    ]
    if "sarif" in want:
        renderers.append(("sarif", "report.sarif", render_sarif(report)))
    if "html" in want:
        renderers.append(("html", "report.html", render_html(report)))
    paths: dict[str, str] = {}
    for key, fname, body in renderers:
        path = os.path.join(out_dir, fname)
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(body)
        except Exception as exc:  # noqa: BLE001 - one failed writer must not lose the others
            _log.warning("writing %s failed (skipping): %s", fname, exc)
            continue
        paths[key] = path
    return paths


def _finding_section(f: Finding, status_label: str = "independently verified") -> list[str]:
    fb = f.flow_batch
    title = f"{f.vuln_class}" + (f" ({f.sub_variant})" if f.sub_variant else "")
    lines = [
        f"### [{f.severity.upper()}] {title}",
        "",
        f"- **Key:** `{f.key}`",
        f"- **Target:** {f.target}",
        f"- **Parameter:** {f.param or '*'}",
        f"- **Oracle:** {f.oracle_kind}",
        f"- **Status:** {status_label}",
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


_CONFIRMED_TIER_BLURB = (
    "Confirmed (oracle-proven) but not independently reproduced — treat as high-confidence, "
    "manually re-verify. These are typically race-condition / one-shot-token / TOCTOU findings the "
    "independent-verify dispatch could not replay from a clean slate."
)


def _metadata_lines(r: Report) -> list[str]:
    lines: list[str] = []
    if r.objective:
        lines.append(f"- Objective: {r.objective}")
    if r.targets:
        lines.append("- Targets: " + ", ".join(r.targets))
    if r.models:
        lines.append("- Models: " + ", ".join(f"{k}={v}" for k, v in r.models.items()))
    if r.dispatches_spent:
        lines.append(f"- Dispatches spent: {r.dispatches_spent}")
    if r.started_at:
        lines.append(f"- Started: {r.started_at}")
    if r.duration_secs:
        lines.append(f"- Duration: {r.duration_secs:.1f}s")
    return lines


def render_markdown(r: Report) -> str:
    """Render a clean human report: metadata + findings + evidence + flow batches + chain map."""

    stats = r.stats or {}
    lines: list[str] = [
        f"# a2pwn report — {r.engagement}",
        "",
        "## Summary",
        "",
        f"- Verified findings: **{stats.get('total_findings', len(r.findings))}**",
        f"- Confirmed (not reproduced): **{stats.get('confirmed_only', len(r.confirmed_findings))}**",
        f"- Cross-chains: **{stats.get('cross_chains', len(r.cross_chains))}**",
        f"- Evidence workspaces: **{stats.get('evidence_workspaces', len(r.har_paths))}**",
    ]
    by_sev = stats.get("by_severity") or {}
    if by_sev:
        ordered = sorted(by_sev.items(), key=lambda kv: -_SEVERITY_ORDER.get(kv[0], 0))
        lines.append("- Severity: " + ", ".join(f"{sev} {n}" for sev, n in ordered))
    lines += _metadata_lines(r)
    lines.append("")

    lines += ["## Findings", ""]
    if r.findings:
        for f in r.findings:
            lines += _finding_section(f)
    else:
        lines += ["_No independently verified findings._", ""]

    lines += ["## Confirmed (not independently reproduced)", "", f"_{_CONFIRMED_TIER_BLURB}_", ""]
    if r.confirmed_findings:
        for f in r.confirmed_findings:
            lines += _finding_section(f, status_label="confirmed (not independently reproduced)")
    else:
        lines += ["_None._", ""]

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


# --------------------------------------------------------------------------- #
# SARIF 2.1.0                                                                  #
# --------------------------------------------------------------------------- #
_SARIF_LEVEL: dict[str, str] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _sarif_result(f: Finding, tier: str) -> dict:
    return {
        "ruleId": f.vuln_class,
        "level": _SARIF_LEVEL.get(f.severity, "note"),
        "message": {"text": f.evidence or f.key},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f.target}}},
        ],
        "properties": {
            "proofTier": tier,
            "severity": f.severity,
            "param": f.param or "*",
            "key": f.key,
            "oracle": f.oracle_kind,
            "subVariant": f.sub_variant or "",
            "enables": list(f.enables),
        },
    }


def render_sarif(r: Report) -> str:
    """Minimal, valid SARIF 2.1.0: one run, driver 'a2pwn', a result per finding across BOTH tiers
    (the confirmed-only tier tagged ``proofTier=confirmed_not_reproduced``)."""

    results = [_sarif_result(f, "verified") for f in r.findings]
    results += [_sarif_result(f, "confirmed_not_reproduced") for f in r.confirmed_findings]
    rule_ids: list[str] = []
    for f in (*r.findings, *r.confirmed_findings):
        if f.vuln_class not in rule_ids:
            rule_ids.append(f.vuln_class)
    rules = [{"id": rid, "name": rid} for rid in rule_ids]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "a2pwn",
                        "informationUri": "https://github.com/own2pwn-fr/a2pwn",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


# --------------------------------------------------------------------------- #
# Self-contained HTML                                                          #
# --------------------------------------------------------------------------- #
_SEVERITY_CHIP: dict[str, str] = {
    "critical": "#7c1d1d",
    "high": "#b45309",
    "medium": "#a16207",
    "low": "#1d4ed8",
    "info": "#374151",
}

_HTML_CSS = """
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0d0d0d;color:#f1efeb;}
.wrap{max-width:1000px;margin:0 auto;padding:24px;}
h1{font-size:1.6rem;margin:0 0 4px;} h2{margin-top:2rem;border-bottom:1px solid #333;padding-bottom:4px;}
.meta{color:#b9b6ae;font-size:.9rem;line-height:1.7;}
.meta b{color:#f1efeb;}
table{border-collapse:collapse;width:100%;margin-top:12px;font-size:.9rem;}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a2a2a;vertical-align:top;}
th{color:#b9b6ae;font-weight:600;}
tr:hover td{background:#161616;}
.chip{display:inline-block;padding:2px 8px;border-radius:999px;color:#fff;font-size:.75rem;font-weight:700;text-transform:uppercase;}
.note{color:#b9b6ae;font-style:italic;margin:6px 0 0;}
code{background:#1a1a1a;padding:1px 5px;border-radius:4px;font-size:.8rem;color:#d7d3ca;}
.ev{white-space:pre-wrap;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.78rem;color:#cfccc4;max-width:420px;overflow-wrap:anywhere;}
""".strip()


def _chip(sev: str) -> str:
    color = _SEVERITY_CHIP.get(sev, "#374151")
    return f'<span class="chip" style="background:{color}">{html.escape(sev)}</span>'


def _html_rows(findings: list[Finding]) -> str:
    rows: list[str] = []
    for f in findings:
        variant = f" ({html.escape(f.sub_variant)})" if f.sub_variant else ""
        rows.append(
            "<tr>"
            f"<td>{_chip(f.severity)}</td>"
            f"<td>{html.escape(f.vuln_class)}{variant}</td>"
            f"<td><code>{html.escape(f.target)}</code></td>"
            f"<td>{html.escape(f.param or '*')}</td>"
            f"<td>{html.escape(f.oracle_kind)}</td>"
            f'<td class="ev">{html.escape(f.evidence)}</td>'
            "</tr>"
        )
    if not rows:
        return '<tr><td colspan="6" class="note">None.</td></tr>'
    return "".join(rows)


def render_html(r: Report) -> str:
    """Self-contained (inline CSS, no external assets) HTML summary with escaped user/finding text."""

    stats = r.stats or {}
    meta_bits: list[str] = []
    if r.objective:
        meta_bits.append(f"<b>Objective</b> {html.escape(r.objective)}")
    if r.targets:
        meta_bits.append("<b>Targets</b> " + html.escape(", ".join(r.targets)))
    if r.models:
        meta_bits.append("<b>Models</b> " + html.escape(", ".join(f"{k}={v}" for k, v in r.models.items())))
    meta_bits.append(f"<b>Verified</b> {stats.get('total_findings', len(r.findings))}")
    meta_bits.append(
        f"<b>Confirmed (not reproduced)</b> {stats.get('confirmed_only', len(r.confirmed_findings))}"
    )
    if r.dispatches_spent:
        meta_bits.append(f"<b>Dispatches</b> {r.dispatches_spent}")
    if r.started_at:
        meta_bits.append("<b>Started</b> " + html.escape(r.started_at))
    if r.duration_secs:
        meta_bits.append(f"<b>Duration</b> {r.duration_secs:.1f}s")
    head = (
        "<tr><th>Severity</th><th>Vuln class</th><th>Target</th>"
        "<th>Param</th><th>Oracle</th><th>Evidence</th></tr>"
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>a2pwn report — {html.escape(r.engagement)}</title>"
        f'<style>{_HTML_CSS}</style></head><body><div class="wrap">'
        f"<h1>a2pwn report — {html.escape(r.engagement)}</h1>"
        f'<p class="meta">{" &nbsp;·&nbsp; ".join(meta_bits)}</p>'
        "<h2>Verified findings</h2>"
        f"<table><thead>{head}</thead><tbody>{_html_rows(r.findings)}</tbody></table>"
        "<h2>Confirmed, not independently reproduced</h2>"
        f'<p class="note">{html.escape(_CONFIRMED_TIER_BLURB)}</p>'
        f"<table><thead>{head}</thead><tbody>{_html_rows(r.confirmed_findings)}</tbody></table>"
        "</div></body></html>"
    )
