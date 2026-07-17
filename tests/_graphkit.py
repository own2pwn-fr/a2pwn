"""Deterministic fakes + builders shared by the graph tests.

Not a test module (leading underscore keeps pytest from collecting it). The LLM-bearing
role builders are monkeypatched to these fakes so no model is ever contacted.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage

from a2pwn.budget import DispatchBudget
from a2pwn.config import A2pwnConfig, EngagementSpec
from a2pwn.models import (
    Finding,
    FlowBatchRef,
    MasterContextView,
    QAPair,
    TaskSpec,
)


class _Dummy:
    """Stand-in for an unused compiled agent (the verifier)."""


class FakeClarifier:
    """`.ainvoke(ctx) -> list[str]` — questions decided by an injected callable."""

    def __init__(self, questions_fn):
        self._fn = questions_fn
        self.calls: list[dict] = []

    def invoke(self, ctx: dict) -> list[str]:
        self.calls.append(ctx)
        return list(self._fn(ctx))

    async def ainvoke(self, ctx: dict, *a: Any, **k: Any) -> list[str]:
        return self.invoke(ctx)


class FakeExecutor:
    """`.ainvoke(state) -> dict` returning canned ReAct outputs, one per call."""

    def __init__(self, results: Any):
        self._results = results if isinstance(results, list) else [results]
        self._i = 0
        self.calls: list[dict] = []

    def invoke(self, state: dict) -> dict:
        self.calls.append(state)
        out = self._results[min(self._i, len(self._results) - 1)]
        self._i += 1
        return out

    async def ainvoke(self, state: dict, *a: Any, **k: Any) -> dict:
        return self.invoke(state)


class FakeFork:
    """Async `answer(question, ctx) -> QAPair`, recording the compacted ctx."""

    def __init__(self):
        self.calls: list[tuple[str, Any]] = []

    async def answer(self, question: str, ctx: Any) -> QAPair:
        self.calls.append((question, ctx))
        return QAPair(question=question, answer=f"answer::{question}")


def make_cfg(
    *,
    active: bool = True,
    max_clarify_rounds: int = 4,
    max_verify_rounds: int = 3,
    max_phases: int = 12,
    max_batch_width: int = 6,
    max_dispatches: int = 200,
    targets: list[str] | None = None,
    name: str = "eng",
) -> A2pwnConfig:
    eng = EngagementSpec(
        name=name,
        targets=targets or ["https://app.example.com"],
        session=name,
        active_exploit_allowed=active,
        authorization_acknowledged=True,
    )
    return A2pwnConfig(
        engagement=eng,
        max_clarify_rounds=max_clarify_rounds,
        max_verify_rounds=max_verify_rounds,
        max_phases=max_phases,
        max_batch_width=max_batch_width,
        max_dispatches=max_dispatches,
    )


def make_ctx(cfg: A2pwnConfig, objective: str = "find and prove exploitable web vulns") -> MasterContextView:
    return MasterContextView(
        objective=objective, engagement=cfg.engagement, history=[], known_findings=[]
    )


def make_budget(cfg: A2pwnConfig, **over: Any) -> DispatchBudget:
    base = {
        "max_dispatches": cfg.max_dispatches,
        "max_batch_width": cfg.max_batch_width,
        "max_phases": cfg.max_phases,
    }
    base.update(over)
    return DispatchBudget(**base)


def make_finding(
    *,
    target: str = "https://app.example.com/search",
    param: str | None = "q",
    vuln: str = "xss",
    flow_ids: tuple[int, ...] = (101,),
    exec_ids: tuple[str, ...] = (),
    oracle: str = "differential",
    confirmed: bool = False,
    indep: bool = False,
    enables: tuple[str, ...] = (),
) -> Finding:
    return Finding(
        key=Finding.make_key(vuln, target, param),
        vuln_class=vuln,
        severity="high",
        target=target,
        param=param,
        evidence="proof-of-concept evidence",
        confirmed=confirmed,
        independently_verified=indep,
        oracle_kind=oracle,
        flow_batch=FlowBatchRef(
            workspace=f"{vuln}-poc",
            workspace_id=2,
            tag=vuln,
            flow_ids=list(flow_ids),
            exec_ids=list(exec_ids),
            key_flow=flow_ids[0] if flow_ids else None,
        ),
        enables=list(enables),
    )


def exec_result(findings: list[Finding], batches: list[FlowBatchRef] | None = None) -> dict:
    return {
        "messages": [AIMessage(content="executed task")],
        "candidate_findings": list(findings),
        "flow_batches": list(batches or []),
    }


def make_master_state(
    cfg: A2pwnConfig,
    *,
    pending: tuple[TaskSpec, ...] = (),
    findings: tuple[Finding, ...] = (),
    verify_queue: tuple[Finding, ...] = (),
    history: tuple = (),
    round: int = 0,
    budget: DispatchBudget | None = None,
) -> dict:
    return {
        "engagement": cfg.engagement,
        "objective": "find and prove exploitable web vulns",
        "history": list(history),
        "pending": list(pending),
        "deferred": [],
        "dispatch_results": [],
        "findings": list(findings),
        "verify_queue": list(verify_queue),
        "phase": "recon",
        "round": round,
        "budget": budget or make_budget(cfg),
    }


def build_sub(monkeypatch, cfg, client, *, clarifier, executor, fork=None, collab=None):
    """Compile a sub-agent graph with the LLM builders swapped for fakes."""
    import a2pwn.graph as g

    monkeypatch.setattr(g, "build_clarifier", lambda models: clarifier)
    monkeypatch.setattr(g, "build_executor", lambda models, tools, active: executor)
    monkeypatch.setattr(g, "build_verifier", lambda models, tools: _Dummy())
    return g.build_subagent_graph(cfg, client, fork or FakeFork(), tools=[], collab=collab)


def sub_input(cfg, *, intent, spec=None, candidate=None, dispatch_id="d-0") -> dict:
    return {
        "intent": intent,
        "spec": spec,
        "candidate": candidate,
        "master_ctx": make_ctx(cfg),
        "clarifications": [],
        "refined_prompt": "",
        "messages": [],
        "candidate_findings": [],
        "flow_batches": [],
        "critique": None,
        "verify_round": 0,
        "clarify_round": 0,
    }
