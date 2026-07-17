"""The continuation judge: when the master would naturally STOP, an agent decides whether the
engagement is genuinely complete or should push further — replacing the human "want me to
continue?" prompt with an autonomous ruling, bounded by ``max_continuations``."""

from __future__ import annotations

import a2pwn.graph as g
from _graphkit import (
    FakeClarifier,
    FakeExecutor,
    arm_differential,
    build_sub,
    exec_result,
    make_budget,
    make_cfg,
    make_finding,
    make_master_state,
)
from a2pwn.budget import STOP
from a2pwn.models import ContinuationVerdict, TaskSpec

_NO_QUESTIONS = FakeClarifier(lambda ctx: [])


class _SeqJudge:
    """Returns a scripted verdict per call (to model re-open-then-complete)."""

    def __init__(self, *verdicts: ContinuationVerdict):
        self._v = list(verdicts)
        self.calls = 0

    async def ainvoke(self, ctx, *a, **k):
        v = self._v[min(self.calls, len(self._v) - 1)]
        self.calls += 1
        return v


# --------------------------------------------------------------------------- #
# routing
# --------------------------------------------------------------------------- #
def test_integrate_next_routes_to_judge_on_natural_completion():
    cfg = make_cfg()
    state = make_master_state(cfg)  # no pending, no verify queue
    assert g.integrate_next(state) == "judge"


def test_integrate_next_continues_when_work_pending():
    cfg = make_cfg()
    state = make_master_state(cfg, pending=(TaskSpec(task="x"),))
    assert g.integrate_next(state) == "continue"


def test_integrate_next_hard_stops_skip_the_judge():
    cfg = make_cfg()
    # budget exhausted => done (never judge), even with no pending work
    state = make_master_state(cfg, budget=make_budget(cfg, spent=cfg.max_dispatches))
    assert g.integrate_next(state) == "done"

    STOP.set()
    try:
        assert g.integrate_next(make_master_state(cfg)) == "done"
    finally:
        STOP.clear()


def test_judge_route_reads_injected_work():
    cfg = make_cfg()
    assert g.judge_route(make_master_state(cfg, pending=(TaskSpec(task="x"),))) == "plan"
    assert g.judge_route(make_master_state(cfg)) == "report"


# --------------------------------------------------------------------------- #
# judge node
# --------------------------------------------------------------------------- #
async def test_judge_complete_finalises():
    cfg = make_cfg()
    node = g._make_judge_node(_SeqJudge(ContinuationVerdict(complete=True)), cfg)
    out = await node(make_master_state(cfg))
    assert out["pending"] == []
    assert out["phase"] == "complete"


async def test_judge_reopens_with_injected_tasks():
    cfg = make_cfg()
    verdict = ContinuationVerdict(
        complete=False,
        rationale="login form never fuzzed",
        remaining_work=[TaskSpec(task="fuzz login for SQLi", target="https://app.example.com/login")],
    )
    node = g._make_judge_node(_SeqJudge(verdict), cfg)
    out = await node(make_master_state(cfg))
    assert len(out["pending"]) == 1
    assert out["continuations"] == 1
    assert out["phase"] == "continuation"


async def test_judge_respects_continuation_cap():
    cfg = make_cfg(max_continuations=1)
    verdict = ContinuationVerdict(complete=False, remaining_work=[TaskSpec(task="more")])
    node = g._make_judge_node(_SeqJudge(verdict), cfg)
    # already at the cap => never re-open, even though the judge wants more
    out = await node(make_master_state(cfg, continuations=1))
    assert out["pending"] == []
    assert out["phase"] == "complete"


async def test_judge_failure_finalises_gracefully():
    cfg = make_cfg()

    class _Boom:
        async def ainvoke(self, ctx, *a, **k):
            raise RuntimeError("model down")

    node = g._make_judge_node(_Boom(), cfg)
    out = await node(make_master_state(cfg))
    assert out["pending"] == [] and out["phase"] == "complete"


# --------------------------------------------------------------------------- #
# end-to-end: judge re-opens once, then completes
# --------------------------------------------------------------------------- #
async def test_master_run_reopens_once_then_completes(monkeypatch, fake_client, tmp_saver):
    cfg = make_cfg(active=True, max_continuations=2)
    arm_differential(fake_client)

    # Planner proposes one task on the first plan only; afterwards the phase is driven by the judge.
    plan_calls = {"n": 0}

    async def _propose(planner, state):
        plan_calls["n"] += 1
        return [TaskSpec(task="probe", target="https://app.example.com")] if plan_calls["n"] == 1 else []

    sub = build_sub(
        monkeypatch,
        cfg,
        fake_client,
        clarifier=_NO_QUESTIONS,
        executor=FakeExecutor(exec_result([make_finding(flow_ids=(101, 102), exec_ids=("e-ok",))])),
    )
    monkeypatch.setattr(g, "propose_tasks", _propose)
    # First natural stop: judge re-opens with a follow-up; second: complete.
    judge = _SeqJudge(
        ContinuationVerdict(complete=False, remaining_work=[TaskSpec(task="follow-up", target="https://app.example.com")]),
        ContinuationVerdict(complete=True),
    )
    monkeypatch.setattr(g, "build_continuation_judge", lambda models: judge)

    graph = g.build_master_graph(cfg, sub, fake_client, tmp_saver)
    final = await graph.ainvoke(
        make_master_state(cfg, pending=(TaskSpec(task="probe", target="https://app.example.com"),)),
        {"configurable": {"thread_id": "judge-e2e"}},
    )
    assert judge.calls == 2  # re-opened once, then completed
    assert final["continuations"] == 1
    assert final["phase"] == "report"
