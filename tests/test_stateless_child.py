"""Stateless child: compiled checkpointer=False, and repeated master runs leave
zero child transcript residue in canonical state."""

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
)
from a2pwn.models import TaskSpec

_NO_QUESTIONS = FakeClarifier(lambda ctx: [])


async def _no_tasks(planner, state):
    return []


def test_child_compiled_without_checkpointer(monkeypatch, fake_client):
    cfg = make_cfg()
    sub = build_sub(
        monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=FakeExecutor(exec_result([]))
    )
    # checkpointer=False => scratch state never persists between invocations.
    assert sub.checkpointer in (False, None)


def _build_master(monkeypatch, fake_client, tmp_saver):
    cfg = make_cfg(active=True)
    arm_differential(fake_client)  # fail-closed adjudicator needs a positive oracle verdict
    sub = build_sub(
        monkeypatch,
        cfg,
        fake_client,
        clarifier=_NO_QUESTIONS,
        executor=FakeExecutor(exec_result([make_finding(flow_ids=(101, 102), exec_ids=("e-ok",))])),
    )
    monkeypatch.setattr(g, "propose_tasks", _no_tasks)  # async: master plan node awaits it
    graph = g.build_master_graph(cfg, sub, fake_client, tmp_saver)
    return cfg, graph


async def test_two_master_runs_leave_no_child_message_residue(monkeypatch, fake_client, tmp_saver):
    cfg, graph = _build_master(monkeypatch, fake_client, tmp_saver)
    task = TaskSpec(task="probe search", target="https://app.example.com/search")

    async def _run(thread_id: str) -> dict:
        state = make_master_state(cfg, pending=(task,))
        return await graph.ainvoke(state, {"configurable": {"thread_id": thread_id}})

    first = await _run("run-1")
    # No transcript channel ever materialised in canonical state.
    assert "messages" not in first
    assert "clarifications" not in first
    # The full task -> independent-verify chain ran and promoted exactly one finding.
    assert len(first["findings"]) == 1
    assert first["findings"][0].independently_verified is True

    second = await _run("run-2")
    # A fresh thread starts clean: the child left nothing behind.
    assert "messages" not in second
    assert len(second["findings"]) == 1
    assert second["findings"][0].independently_verified is True
