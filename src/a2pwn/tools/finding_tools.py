"""The finding-emission tool for the ReAct executor.

The executor recons and exploits with the burpwn/oracle/skill tools, but it needs an
explicit way to *declare* a proven vulnerability. ``report_finding`` builds a
:class:`~a2pwn.models.Finding` tied to a captured burpwn flow batch (workspace + tag +
note), and returns it as a tool *artifact* so the sub-agent graph's ``_harvest`` picks it
up as a candidate. The adversarial verifier still has the final say — a finding without a
real captured batch, or whose oracle does not re-derive it, is rejected.
"""

from __future__ import annotations

from langchain_core.tools import BaseTool, StructuredTool

from a2pwn.burpwn import BurpwnClient, FlowBatchManager
from a2pwn.models import Finding, FlowBatchRef

_ORACLES = {"differential", "oob", "marker", "signature", "timing", "two_identity", "llm_rubric"}
_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def finding_tools(client: BurpwnClient) -> list[BaseTool]:
    fbm = FlowBatchManager(client)

    async def report_finding(
        vuln_class: str,
        severity: str,
        target: str,
        evidence: str,
        flow_ids: list[int],
        oracle_kind: str = "signature",
        param: str | None = None,
        sub_variant: str | None = None,
        workspace: str | None = None,
        tag: str | None = None,
        key_flow: int | None = None,
        exec_ids: list[str] | None = None,
        enables: list[str] | None = None,
    ):
        """Declare ONE proven candidate vulnerability, backed by captured burpwn flows.

        Call this once per distinct vulnerability you have actually demonstrated (not
        suspected). ``flow_ids`` MUST be the ``captured_request_ids`` returned by the
        burpwn_exec/fuzz/replay calls that prove it — the finding is rejected later unless
        those flows exist and its oracle re-derives the result. ``oracle_kind`` is how it can
        be deterministically re-confirmed (differential/oob/marker/timing/two_identity/
        signature). Group a finding's requests by passing the same ``workspace`` to your
        burpwn_exec calls, then name it here.
        """
        flow_ids = list(flow_ids or [])
        tag = tag or vuln_class
        oracle_kind = oracle_kind if oracle_kind in _ORACLES else "signature"
        severity = severity if severity in _SEVERITIES else "medium"
        ref = FlowBatchRef(
            workspace=workspace or f"{vuln_class}-poc",
            tag=tag,
            color="red",
            flow_ids=flow_ids,
            exec_ids=list(exec_ids or []),
            key_flow=key_flow or (flow_ids[0] if flow_ids else None),
        )
        try:  # best-effort highlight; a burpwn hiccup must not lose the finding
            if flow_ids:
                ref = await fbm.seal(
                    ref, flow_ids, tag=tag, color="red", note_body=evidence, key_flow=ref.key_flow
                )
        except Exception:  # noqa: BLE001
            pass
        finding = Finding(
            key=Finding.make_key(vuln_class, target, param),
            vuln_class=vuln_class,
            sub_variant=sub_variant,
            severity=severity,
            target=target,
            param=param,
            evidence=FlowBatchManager.strip_nul(evidence),
            oracle_kind=oracle_kind,
            flow_batch=ref,
            enables=list(enables or []),
        )
        summary = (
            f"recorded candidate {finding.key} (severity={finding.severity}, "
            f"oracle={oracle_kind}, flows={flow_ids or 'NONE — will be rejected'})"
        )
        return summary, finding

    return [
        StructuredTool.from_function(
            coroutine=report_finding, name="report_finding", response_format="content_and_artifact"
        )
    ]
