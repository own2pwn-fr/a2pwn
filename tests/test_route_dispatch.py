"""route_dispatch + partition_pending: parallelism, clamping, budget/verify routing."""

from langgraph.types import Send

from _graphkit import make_budget, make_cfg, make_finding, make_master_state
from a2pwn.graph import partition_pending, route_dispatch
from a2pwn.models import SubAgentInput, TaskSpec


def _task(task, target, intent="exploit", mutates=True):
    return TaskSpec(task=task, target=target, intent=intent, mutates=mutates)


def test_partition_serializes_shared_mutable_target():
    a = _task("a", "https://t/1")
    b = _task("b", "https://t/1")  # same mutable target -> deferred
    c = _task("c", "https://t/2")  # distinct target -> parallel
    parallel, deferred = partition_pending([a, b, c])
    assert parallel == [a, c]
    assert deferred == [b]


def test_partition_treats_recon_and_readonly_as_parallel():
    a = _task("recon-a", "https://t/1", intent="recon")
    b = _task("recon-b", "https://t/1", intent="recon")  # read-only, same target OK
    c = _task("probe", "https://t/1", mutates=False)  # non-mutating, same target OK
    parallel, deferred = partition_pending([a, b, c])
    assert parallel == [a, b, c]
    assert deferred == []


def test_route_emits_one_send_per_parallel_task():
    cfg = make_cfg()
    tasks = tuple(_task(f"t{i}", f"https://t/{i}") for i in range(3))
    state = make_master_state(cfg, pending=tasks)
    out = route_dispatch(state)
    assert isinstance(out, list)
    assert all(isinstance(s, Send) and s.node == "run_subagent" for s in out)
    assert len(out) == 3
    assert all(isinstance(s.arg, SubAgentInput) and s.arg.intent == "task" for s in out)


def test_route_clamps_to_max_batch_width():
    cfg = make_cfg(max_batch_width=3)
    tasks = tuple(_task(f"t{i}", f"https://t/{i}") for i in range(8))
    state = make_master_state(cfg, pending=tasks)
    out = route_dispatch(state)
    assert len(out) == 3  # clamped to the per-phase cap


def test_route_reports_when_budget_exhausted():
    cfg = make_cfg()
    tasks = (_task("t", "https://t/1"),)
    state = make_master_state(cfg, pending=tasks, spent=5, budget=make_budget(cfg, max_dispatches=5))
    assert route_dispatch(state) == "report"


def test_route_reports_when_phase_cap_reached():
    cfg = make_cfg(max_phases=4)
    state = make_master_state(cfg, pending=(_task("t", "https://t/1"),), round=4)
    assert route_dispatch(state) == "report"


def test_route_prefers_verify_queue():
    cfg = make_cfg()
    candidate = make_finding(confirmed=True, flow_ids=(1,))
    state = make_master_state(
        cfg, pending=(_task("t", "https://t/1"),), verify_queue=(candidate,)
    )
    out = route_dispatch(state)
    assert isinstance(out, list)
    assert all(s.arg.intent == "verify" for s in out)
    assert out[0].arg.candidate.key == candidate.key


def test_route_skips_already_promoted_verify_candidates():
    cfg = make_cfg()
    verified = make_finding(confirmed=True, indep=True, flow_ids=(1,))
    # verify_queue still lists it, but findings shows it promoted -> drained, no task pending
    state = make_master_state(cfg, findings=(verified,), verify_queue=(verified,))
    assert route_dispatch(state) == "report"


def test_route_drops_persistently_unverifiable_candidate_after_cap():
    cfg = make_cfg()
    candidate = make_finding(confirmed=True, flow_ids=(1,))
    # Confirmed-but-never-independently-verified: after max_verify_attempts failed reproductions
    # it must stop being re-dispatched every phase (kept confirmed-only), not thrash the queue.
    state = make_master_state(cfg, findings=(candidate,), verify_queue=(candidate,))
    cap = state["budget"].max_verify_attempts
    state["verify_attempts"] = {candidate.key: cap}
    assert route_dispatch(state) == "report"

    # One attempt below the cap it is still owed a verify dispatch.
    state["verify_attempts"] = {candidate.key: cap - 1}
    out = route_dispatch(state)
    assert isinstance(out, list)
    assert all(s.arg.intent == "verify" for s in out)


def test_route_clamps_batch_to_remaining_hard_budget():
    cfg = make_cfg(max_batch_width=6)
    tasks = tuple(_task(f"t{i}", f"https://t/{i}") for i in range(5))
    # Only one dispatch of hard budget remains -> a phase may not dispatch past it.
    state = make_master_state(cfg, pending=tasks, spent=1, budget=make_budget(cfg, max_dispatches=2))
    out = route_dispatch(state)
    assert isinstance(out, list)
    assert len(out) == 1
