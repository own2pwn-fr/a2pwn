"""End-to-end MASTER-graph drive over the async ``astream`` bridge — the runtime path that had
ZERO coverage and where the live loop bugs lived.

These tests build the real master graph (child subgraph wired via ``run_subagent``) over the
deterministic fakes and drive it exactly the way ``runtime.run_engagement`` does: a
``graph.astream(..., subgraphs=True)`` pass, ``aget_state``, resume, repeat — all on ONE event
loop touching the long-lived (fake) ``BurpwnClient``. We assert the run reaches ``report``, that
the clean-history invariant holds in curated state (no transcript channel ever materialises), and
that a single failing dispatch is isolated instead of aborting its batch siblings.
"""

from __future__ import annotations

from langgraph.types import Command

import a2pwn.graph as g
from _graphkit import (
    FakeClarifier,
    FakeExecutor,
    arm_differential,
    build_sub,
    exec_result,
    make_cfg,
    make_finding,
    make_master_state,
    stub_judge,
)
from a2pwn.budget import STOP
from a2pwn.models import DispatchRecord, TaskSpec
from a2pwn.runtime import _has_dynamic_interrupt

_NO_QUESTIONS = FakeClarifier(lambda ctx: [])


def _propose_once(tasks: list[TaskSpec]):
    """Async ``propose_tasks`` stand-in: yields the seed tasks on the first plan, then ``[]`` so the
    engagement terminates instead of re-proposing the same work every phase."""
    state = {"n": 0}

    async def _fn(planner, master_state):
        state["n"] += 1
        return list(tasks) if state["n"] == 1 else []

    return _fn


async def _drive(graph, initial, config):
    """Replicate ``runtime.run_engagement``'s astream + resume loop across the async bridge.

    Returns ``(final_values, iterations)`` where ``iterations`` counts how many separate
    ``astream`` passes were needed (an interrupting graph needs more than one — the exact
    multi-call sequence the ``asyncio.run``-per-call loop bug corrupted).
    """
    stream_input = initial
    iterations = 0
    for _ in range(64):  # safety cap; a healthy run terminates well within this
        iterations += 1
        async for _chunk in graph.astream(
            stream_input, config, stream_mode=["updates", "messages"], subgraphs=True
        ):
            pass
        snap = await graph.aget_state(config)
        if not snap.next:
            break
        stream_input = Command(resume=True) if _has_dynamic_interrupt(snap) else None
    final = (await graph.aget_state(config)).values
    return final, iterations


def _build_master(monkeypatch, fake_client, tmp_saver, *, active, executor, tasks):
    cfg = make_cfg(active=active)
    arm_differential(fake_client)  # fail-closed adjudicator needs a positive oracle verdict
    sub = build_sub(monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=executor)
    monkeypatch.setattr(g, "propose_tasks", _propose_once(tasks))  # async: master plan awaits it
    stub_judge(monkeypatch)  # continuation judge -> complete, so the natural stop finalises
    graph = g.build_master_graph(cfg, sub, fake_client, tmp_saver)
    return cfg, graph


class _RoutingExecutor:
    """Async ReAct-executor fake that RAISES for the poisoned task and returns a real finding for
    every other prompt — so a batch with one poisoned sibling exercises dispatch isolation."""

    def __init__(self, poison_marker: str, good_result: dict):
        self.poison = poison_marker
        self.good = good_result
        self.prompts: list[str] = []

    async def ainvoke(self, state: dict, *a, **k):
        text = getattr(state["messages"][-1], "content", "") if state.get("messages") else ""
        self.prompts.append(text)
        if self.poison in text:
            raise RuntimeError("executor blew up on the poisoned task")
        return self.good


async def test_astream_run_reaches_report_and_promotes_finding(monkeypatch, fake_client, tmp_saver):
    STOP.clear()
    executor = FakeExecutor(exec_result([make_finding(flow_ids=(101, 102), exec_ids=("e-ok",))]))
    task = TaskSpec(task="probe search", target="https://app.example.com/search")
    cfg, graph = _build_master(
        monkeypatch, fake_client, tmp_saver, active=True, executor=executor, tasks=[task]
    )
    initial = make_master_state(cfg)  # empty pending -> propose_tasks supplies the seed task
    config = {"configurable": {"thread_id": "async-report"}}

    final, _iterations = await _drive(graph, initial, config)

    # The whole task -> independent-verify chain ran on the async bridge and reached the terminal
    # report node, promoting exactly one finding.
    assert final["phase"] == "report"
    assert len(final["findings"]) == 1
    assert final["findings"][0].independently_verified is True
    # clean-history invariant: NO transcript channel ever materialised in curated master state.
    assert "messages" not in final
    assert "clarifications" not in final
    assert final["history"], "expected at least one curated dispatch record"
    assert all(isinstance(r, DispatchRecord) for r in final["history"])


async def test_astream_interrupt_resume_bridges_multiple_calls(monkeypatch, fake_client, tmp_saver):
    STOP.clear()
    executor = FakeExecutor(exec_result([make_finding(flow_ids=(101, 102), exec_ids=("e-ok",))]))
    task = TaskSpec(task="probe search", target="https://app.example.com/search")
    # active=False keeps interrupt_before=['run_subagent'], forcing the runner to bounce back into
    # astream once per dispatch phase (task phase + verify phase) — a genuine two-call sequence on
    # ONE event loop against the long-lived client, the precise shape of the live loop bug.
    cfg, graph = _build_master(
        monkeypatch, fake_client, tmp_saver, active=False, executor=executor, tasks=[task]
    )
    initial = make_master_state(cfg)
    config = {"configurable": {"thread_id": "async-interrupt"}}

    final, iterations = await _drive(graph, initial, config)

    assert iterations >= 2  # more than one astream pass really crossed the async bridge
    assert final["phase"] == "report"
    assert len(final["findings"]) == 1
    assert final["findings"][0].independently_verified is True


async def test_executor_error_is_isolated_and_run_reaches_report(monkeypatch, fake_client, tmp_saver):
    STOP.clear()
    good = exec_result(
        [make_finding(target="https://app.example.com/good", param="q", flow_ids=(201, 202), exec_ids=("e-ok",))]
    )
    executor = _RoutingExecutor("POISON", good)
    good_task = TaskSpec(task="probe GOOD endpoint", target="https://app.example.com/good")
    bad_task = TaskSpec(task="probe POISON endpoint", target="https://app.example.com/bad")
    cfg, graph = _build_master(
        monkeypatch, fake_client, tmp_saver, active=True, executor=executor, tasks=[good_task, bad_task]
    )
    initial = make_master_state(cfg)
    config = {"configurable": {"thread_id": "async-isolation"}}

    final, _iterations = await _drive(graph, initial, config)

    # The poisoned sibling raised mid-dispatch but degraded to a recorded BLOCKED result; it did
    # NOT abort the batch, so the good sibling still completed the task -> verify chain and the run
    # reached report.
    assert final["phase"] == "report"
    statuses = [r.result.status for r in final["history"]]
    assert "blocked" in statuses  # the failing dispatch was recorded, not propagated
    assert len(final["findings"]) == 1
    promoted = final["findings"][0]
    assert promoted.independently_verified is True
    assert promoted.target == "https://app.example.com/good"


async def test_astream_stop_signal_routes_straight_to_report(monkeypatch, fake_client, tmp_saver):
    # A process-wide TaskStop set before the run must route the master graph straight to report
    # (no dispatch), proving the STOP kill switch reaches the graph over the async bridge.
    executor = FakeExecutor(exec_result([make_finding(flow_ids=(101, 102), exec_ids=("e-ok",))]))
    task = TaskSpec(task="probe search", target="https://app.example.com/search")
    cfg, graph = _build_master(
        monkeypatch, fake_client, tmp_saver, active=True, executor=executor, tasks=[task]
    )
    initial = make_master_state(cfg)
    config = {"configurable": {"thread_id": "async-stop"}}
    STOP.set()
    try:
        final, _iterations = await _drive(graph, initial, config)
    finally:
        STOP.clear()

    assert final["phase"] == "report"
    assert final["findings"] == []  # nothing was dispatched
    assert executor.calls == []  # the executor was never reached
