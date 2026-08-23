"""The coverage-declaration tool for the ReAct executor.

The oracle kernel records what was PROVEN. Nothing recorded what was *tried and found clean*, so a
parameter that had been fuzzed for SQLi with a negative result looked exactly like a parameter no
dispatch had ever touched — which is why the continuation judge could only guess at what remained,
and why the report could never say what it had covered.

``record_probe`` is how a sub-agent writes a negative result down. Its artifact (a list of
:class:`~a2pwn.coverage.Probe`) is harvested by ``subgraph._harvest`` into ``CleanResult.probes``
and folded into the master's coverage matrix, exactly like ``propose_targets`` feeds ``next_hops``.
"""

from __future__ import annotations

from langchain_core.tools import BaseTool, StructuredTool

from a2pwn.coverage import Probe, asset_key

_VERDICTS = {"probed", "not_applicable", "blocked"}

RECORD_PROBE_DESC = (
    "Record that you TESTED an asset for a vulnerability class and what came of it. Call this for "
    "every class you clear — a class you probed and found clean is worthless to the engagement "
    "unless it is written down, because otherwise the coverage matrix re-dispatches it and the "
    "report cannot state what was covered. Use verdict='probed' when you sent payloads and judged "
    "the responses, 'not_applicable' when the class cannot apply here (say why in note), 'blocked' "
    "when a WAF/auth wall stopped you from testing it. Do NOT use this to claim a vulnerability — "
    "that is report_finding. asset_kind is one of host/endpoint/param/js/websocket/graphql."
)

PROBE_SCHEMA: dict = {
    "asset_kind": str,
    "host": str,
    "path": str,
    "method": str,
    "param": str,
    "vuln_class": str,
    "verdict": str,
    "evidence_flow": int,
    "note": str,
}


def build_probe(args: dict, dispatch_id: str = "") -> Probe | None:
    """Shared normaliser — both executor paths must produce identical Probe rows."""
    host = str(args.get("host") or "").strip().lower()
    vuln_class = str(args.get("vuln_class") or "").strip()
    if not host or not vuln_class:
        return None
    kind = str(args.get("asset_kind") or "endpoint").strip().lower()
    verdict = str(args.get("verdict") or "probed").strip().lower()
    if verdict not in _VERDICTS:
        # `proven` is deliberately not settable here: only the deterministic oracle promotes a cell
        # to proven, so the model cannot talk its way into a covered matrix.
        verdict = "probed"
    flow = args.get("evidence_flow")
    try:
        flow_id = int(flow) if flow not in (None, "", 0) else None
    except (TypeError, ValueError):
        flow_id = None
    return Probe(
        asset_key=asset_key(
            kind,
            host,
            str(args.get("path") or ""),
            str(args.get("method") or ""),
            str(args.get("param") or "") or None,
        ),
        vuln_class=vuln_class,
        verdict=verdict,  # type: ignore[arg-type]
        dispatch_id=dispatch_id,
        evidence_flow=flow_id,
        note=str(args.get("note") or "")[:400],
    )


def coverage_tools(dispatch_id: str = "") -> list[BaseTool]:
    async def record_probe(
        asset_kind: str,
        host: str,
        vuln_class: str,
        verdict: str = "probed",
        path: str = "",
        method: str = "",
        param: str = "",
        evidence_flow: int | None = None,
        note: str = "",
    ) -> tuple[str, list[Probe]]:
        probe = build_probe(
            {
                "asset_kind": asset_kind,
                "host": host,
                "path": path,
                "method": method,
                "param": param,
                "vuln_class": vuln_class,
                "verdict": verdict,
                "evidence_flow": evidence_flow,
                "note": note,
            },
            dispatch_id,
        )
        if probe is None:
            return "record_probe needs at least host and vuln_class", []
        return f"recorded {probe.vuln_class} = {probe.verdict} on {probe.asset_key}", [probe]

    record_probe.__doc__ = RECORD_PROBE_DESC
    return [
        StructuredTool.from_function(
            coroutine=record_probe, name="record_probe", response_format="content_and_artifact"
        )
    ]
