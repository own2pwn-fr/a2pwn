"""End-to-end: bootstrap seeds a subdomain-enumeration recon task for an apex target BEFORE the
first planning phase, and its discovered follow-up hosts become real dispatched tasks without the
planner ever needing to rediscover them — the "planner has the correct vision from the start"
property this feature exists for. Mirrors a live gap: auditing *.thinginthefuture.com needed the
operator to manually enumerate subdomains outside a2pwn entirely before this existed.
"""

from __future__ import annotations

from langgraph.types import Command

import a2pwn.graph as g
from _graphkit import (
    FakeClarifier,
    arm_differential,
    build_sub,
    exec_result,
    make_cfg,
    make_master_state,
    stub_judge,
)
from a2pwn.models import TaskSpec
from a2pwn.runtime import _has_dynamic_interrupt

_NO_QUESTIONS = FakeClarifier(lambda ctx: [])


async def _drive(graph, initial, config):
    """Same async-bridge drive loop as test_async_engagement.py's ``_drive`` (kept local: these
    tests don't share a harness module with that file)."""
    stream_input = initial
    for _ in range(64):
        async for _chunk in graph.astream(
            stream_input, config, stream_mode=["updates", "messages"], subgraphs=True
        ):
            pass
        snap = await graph.aget_state(config)
        if not snap.next:
            break
        stream_input = Command(resume=True) if _has_dynamic_interrupt(snap) else None
    return (await graph.aget_state(config)).values


class _ReconRoutingExecutor:
    """Returns discovered hosts for the seeded recon dispatch (prompt mentions subfinder), and a
    plain no-op result for anything else (the discovered host's own follow-up dispatch) so the
    queue drains and the engagement terminates."""

    def __init__(self, discovered: list[TaskSpec]):
        self.discovered = discovered
        self.prompts: list[str] = []

    async def ainvoke(self, state: dict, *a, **k):
        text = getattr(state["messages"][-1], "content", "") if state.get("messages") else ""
        self.prompts.append(text)
        if "subfinder" in text:
            return exec_result([], discovered_hosts=self.discovered)
        return exec_result([])


async def test_recon_seed_dispatches_before_any_planner_call(monkeypatch, fake_client, tmp_saver):
    """Round 0 must be the deterministic recon dispatch, never a planner-proposed task — the
    planner should not even be consulted until the seeded recon work is exhausted."""
    cfg = make_cfg(targets=["https://example.com"])  # apex-shaped -> seed_recon_tasks fires
    arm_differential(fake_client)
    executor = _ReconRoutingExecutor(discovered=[])
    sub = build_sub(monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=executor)

    planner_calls = {"n": 0}

    async def _never_called_first(planner, state):
        planner_calls["n"] += 1
        return []

    monkeypatch.setattr(g, "propose_tasks", _never_called_first)
    stub_judge(monkeypatch)
    graph = g.build_master_graph(cfg, sub, fake_client, tmp_saver)
    initial = make_master_state(cfg)  # empty pending -> bootstrap seeds the recon task
    config = {"configurable": {"thread_id": "recon-seed-order"}}

    await _drive(graph, initial, config)

    assert len(executor.prompts) == 1
    assert "subfinder" in executor.prompts[0]
    assert "example.com" in executor.prompts[0]


async def test_discovered_hosts_become_real_dispatched_tasks(monkeypatch, fake_client, tmp_saver):
    """The core property: a host propose_targets discovers during the seeded recon pass is
    actually dispatched next — not just described in a summary the planner might ignore."""
    cfg = make_cfg(targets=["https://example.com"])
    arm_differential(fake_client)
    discovered = [
        TaskSpec(task="Recon and exploit discovered.example.com.", target="https://discovered.example.com")
    ]
    executor = _ReconRoutingExecutor(discovered=discovered)
    sub = build_sub(monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=executor)

    async def _empty_planner(planner, state):
        return []

    monkeypatch.setattr(g, "propose_tasks", _empty_planner)
    stub_judge(monkeypatch)
    graph = g.build_master_graph(cfg, sub, fake_client, tmp_saver)
    initial = make_master_state(cfg)
    config = {"configurable": {"thread_id": "recon-seed-discovery"}}

    final = await _drive(graph, initial, config)

    assert len(executor.prompts) == 2  # the recon dispatch, then the discovered host's own dispatch
    assert any("discovered.example.com" in p for p in executor.prompts[1:])
    assert final["phase"] == "report"
    # the recon dispatch's outcome is legible in curated history (not silently dropped).
    summaries = [r.result.summary for r in final["history"]]
    assert any("recon proposed 1 follow-up target" in s for s in summaries)
