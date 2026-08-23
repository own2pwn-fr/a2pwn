"""`integrate` bookkeeping: no planned task is silently dropped, history records what was
REQUESTED (not just what happened), and work already carried out is not dispatched twice."""

import a2pwn.graph as g
from _graphkit import make_cfg, make_master_state
from a2pwn.models import CleanResult, DispatchRecord, TaskSpec


def _result(spec: TaskSpec | None, *, dispatch_id: str = "0-task-0", summary: str = "did a thing"):
    return CleanResult(dispatch_id=dispatch_id, status="no_finding", spec=spec, summary=summary)


async def test_undispatched_pending_tasks_survive_the_phase():
    """A phase dispatches at most max_batch_width tasks — the rest must stay queued.

    Regression: `pending` was rebuilt as `deferred + next_hops`, so every planned-but-not-reached
    task evaporated. Worst case is a verify-priority phase, which dispatches verifies ONLY and
    therefore answered none of the queued task work at all.
    """
    cfg = make_cfg()
    a = TaskSpec(task="probe /login for sqli", target="https://app.example.com/login")
    b = TaskSpec(task="probe /search for xss", target="https://app.example.com/search")
    state = make_master_state(cfg, pending=(a, b))
    state["dispatch_results"] = [_result(a)]

    out = await g._integrate_node(state)

    remaining = [t.task for t in out["pending"]]
    assert remaining == [b.task]


async def test_verify_only_phase_does_not_consume_task_queue():
    """A verify dispatch carries no spec, so it answers none of the queued tasks."""
    cfg = make_cfg()
    a = TaskSpec(task="probe /login for sqli", target="https://app.example.com/login")
    state = make_master_state(cfg, pending=(a,))
    state["dispatch_results"] = [_result(None, dispatch_id="0-verify-0")]

    out = await g._integrate_node(state)

    assert [t.task for t in out["pending"]] == [a.task]


async def test_history_records_the_requested_task_not_the_summary():
    """The continuation judge is asked what was never done; history must carry the request."""
    cfg = make_cfg()
    a = TaskSpec(task="probe /login for sqli", target="https://app.example.com/login")
    state = make_master_state(cfg, pending=(a,))
    state["dispatch_results"] = [_result(a, summary="no_finding: 0 finding(s)")]

    out = await g._integrate_node(state)

    assert out["history"][0].task == "probe /login for sqli"


async def test_already_dispatched_work_is_not_requeued():
    """`next_hops` and the judge append blindly; a repeat of finished work must be dropped."""
    cfg = make_cfg()
    done = TaskSpec(
        task="Recon and (if warranted) exploit api.example.com.", target="https://api.example.com"
    )
    prior = DispatchRecord(dispatch_id="0-task-0", kind="single", task=done.task, result=_result(done))
    state = make_master_state(cfg, history=(prior,))
    # dispatch_results accumulates across phases; _integrate_node slices off the already-recorded
    # prefix positionally, so the prior result must be present for the new one to be seen.
    state["dispatch_results"] = [
        prior.result,
        CleanResult(dispatch_id="1-task-0", status="no_finding", spec=None, next_hops=[done]),
    ]

    out = await g._integrate_node(state)

    assert out["pending"] == []


async def test_distinct_work_is_still_queued():
    """The repeat guard must not swallow genuinely new tasks."""
    cfg = make_cfg()
    done = TaskSpec(task="probe /login for sqli", target="https://app.example.com/login")
    fresh = TaskSpec(task="probe /search for xss", target="https://app.example.com/search")
    prior = DispatchRecord(dispatch_id="0-task-0", kind="single", task=done.task, result=_result(done))
    state = make_master_state(cfg, history=(prior,))
    state["dispatch_results"] = [
        prior.result,
        CleanResult(dispatch_id="1-task-0", status="no_finding", spec=None, next_hops=[fresh]),
    ]

    out = await g._integrate_node(state)

    assert [t.task for t in out["pending"]] == [fresh.task]
