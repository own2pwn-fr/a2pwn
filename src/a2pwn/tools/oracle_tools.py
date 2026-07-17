"""LangChain tool over the deterministic verification oracles.

``run_oracle`` is the anti-FP kernel exposed to the verifier agent: it re-derives a
candidate finding through the right oracle (differential / timing / oob / marker /
signature / two_identity / llm_rubric) instead of trusting a payload that merely
"looked reflected".
"""

from __future__ import annotations

from langchain_core.tools import BaseTool, StructuredTool

from a2pwn.burpwn import BurpwnClient
from a2pwn.oracles import VerificationOracle, run_oracle


def oracle_tools(collab, client: BurpwnClient | None = None) -> list[BaseTool]:
    resolved = client or getattr(collab, "client", None) or getattr(collab, "_client", None)

    async def run_oracle_tool(
        kind: str,
        expect: dict | None = None,
        signals: list[str] | None = None,
        correlation_id: str | None = None,
        flow_a: int | None = None,
        flow_b: int | None = None,
        attack_id: int | None = None,
        flow_id: int | None = None,
        threshold_ms: int | None = None,
    ) -> dict:
        """Deterministically confirm a candidate finding via the named oracle. Returns OracleResult."""
        spec = VerificationOracle(
            kind=kind,  # type: ignore[arg-type]
            expect=expect or {},
            signals=signals or [],
            correlation_id=correlation_id,
        )
        ctx = {
            "client": resolved,
            "collaborator": collab,
            "collab": collab,
            "flow_a": flow_a,
            "flow_b": flow_b,
            "attack_id": attack_id,
            "flow_id": flow_id,
            "threshold_ms": threshold_ms,
        }
        result = await run_oracle(spec, ctx)
        return result.model_dump()

    return [StructuredTool.from_function(coroutine=run_oracle_tool, name="run_oracle")]
