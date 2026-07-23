"""route_dispatch + partition_pending: parallelism, clamping, budget/verify routing."""

from langgraph.types import Send

from _graphkit import make_budget, make_cfg, make_finding, make_master_state
from a2pwn.config import EngagementSpec
from a2pwn.graph import partition_pending, route_dispatch, seed_recon_tasks
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
    state = make_master_state(cfg, pending=(_task("t", "https://t/1"),), verify_queue=(candidate,))
    out = route_dispatch(state)
    assert isinstance(out, list)
    assert all(s.arg.intent == "verify" for s in out)
    assert out[0].arg.candidate.key == candidate.key


def test_route_clamps_verify_fan_out_to_batch_width():
    # REGRESSION: a full verify queue must be clamped to max_batch_width like the task branch —
    # otherwise every queued finding becomes a concurrent Send (30 findings -> 30 Opus sub-agents),
    # blowing past the phase/spend caps the run is supposed to enforce.
    cfg = make_cfg(max_batch_width=3)
    candidates = tuple(make_finding(confirmed=True, param=f"p{i}", flow_ids=(1,)) for i in range(8))
    state = make_master_state(cfg, verify_queue=candidates)
    out = route_dispatch(state)
    assert isinstance(out, list)
    assert all(s.arg.intent == "verify" for s in out)
    assert len(out) == 3  # clamped, not 8


def test_route_clamps_verify_fan_out_to_remaining_budget():
    cfg = make_cfg(max_batch_width=6)
    candidates = tuple(make_finding(confirmed=True, param=f"p{i}", flow_ids=(1,)) for i in range(6))
    # Only 2 dispatches left before the hard cap -> at most 2 verify Sends this phase.
    state = make_master_state(
        cfg, verify_queue=candidates, spent=8, budget=make_budget(cfg, max_dispatches=10)
    )
    out = route_dispatch(state)
    assert len(out) == 2


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


def _eng(**kw) -> EngagementSpec:
    return EngagementSpec(name="e", targets=kw.pop("targets", ["https://example.com"]), session="e", **kw)


def test_seed_recon_tasks_one_per_apex_host():
    tasks = seed_recon_tasks(_eng(targets=["https://example.com"]))
    assert len(tasks) == 1
    assert tasks[0].target == "example.com"
    assert tasks[0].intent == "recon"
    assert "subfinder" in tasks[0].task
    assert "propose_targets" in tasks[0].task


def test_seed_recon_tasks_skips_already_specific_hosts():
    # Already a specific subdomain the operator explicitly chose — not apex-shaped.
    assert seed_recon_tasks(_eng(targets=["https://coreapi.qlf.example.com"])) == []


def test_seed_recon_tasks_dedupes_across_targets_and_in_scope():
    tasks = seed_recon_tasks(_eng(targets=["https://example.com"], in_scope=["example.com", "example.com"]))
    assert len(tasks) == 1  # in_scope takes precedence over targets and is itself deduped


def test_seed_recon_tasks_multiple_apex_targets():
    tasks = seed_recon_tasks(_eng(targets=["https://a.com", "https://b.com", "https://sub.c.com"]))
    assert {t.target for t in tasks} == {"a.com", "b.com"}


def test_seed_recon_tasks_empty_for_no_apex_hosts():
    assert seed_recon_tasks(_eng(targets=[])) == []
