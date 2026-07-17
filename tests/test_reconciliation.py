"""Independent verify reconciliation: a verify dispatch may only PROMOTE
(confirmed -> independently_verified); it can never downgrade a prior finding."""

import a2pwn.graph as g
from _graphkit import FakeClarifier, FakeExecutor, build_sub, exec_result, make_cfg, make_finding, sub_input
from a2pwn.models import SubAgentInput

_NO_QUESTIONS = FakeClarifier(lambda ctx: [])


def _wire(monkeypatch, fake_client, cfg, executor):
    sub = build_sub(monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=executor)
    g.SUBAGENT_GRAPH = sub
    return sub


def _payload(cfg, candidate):
    data = sub_input(cfg, intent="verify", candidate=candidate)
    return SubAgentInput(
        dispatch_id="0-verify-0",
        intent="verify",
        candidate=candidate,
        master_ctx=data["master_ctx"],
    )


async def test_independent_verify_promotes_to_independently_verified(monkeypatch, fake_client):
    cfg = make_cfg()
    candidate = make_finding(confirmed=True, flow_ids=(101,))
    # A fresh child reproduces the candidate with a real captured batch.
    _wire(monkeypatch, fake_client, cfg, FakeExecutor(exec_result([make_finding(flow_ids=(201,))])))

    out = await g.run_subagent(_payload(cfg, candidate))

    assert out["verify_queue"] == []  # a verify dispatch never re-enqueues verification
    assert len(out["findings"]) == 1
    promoted = out["findings"][0]
    assert promoted.key == candidate.key
    assert promoted.independently_verified is True


async def test_failed_verify_does_not_downgrade_prior_finding(monkeypatch, fake_client):
    cfg = make_cfg()
    candidate = make_finding(confirmed=True, flow_ids=(101,))
    # Reproduction fails (no captured batch) -> the child promotes nothing.
    _wire(monkeypatch, fake_client, cfg, FakeExecutor(exec_result([make_finding(flow_ids=())])))

    out = await g.run_subagent(_payload(cfg, candidate))
    assert out["findings"] == []

    # Reconciliation into master state keeps the previously confirmed finding intact.
    reconciled = g.merge_findings([candidate], out["findings"])
    assert len(reconciled) == 1
    assert reconciled[0].confirmed is True


async def test_task_dispatch_enqueues_confirmed_for_independent_verify(monkeypatch, fake_client):
    cfg = make_cfg()
    _wire(monkeypatch, fake_client, cfg, FakeExecutor(exec_result([make_finding(flow_ids=(301,))])))

    data = sub_input(cfg, intent="task")
    payload = SubAgentInput(dispatch_id="0-task-0", intent="task", spec=None, master_ctx=data["master_ctx"])
    out = await g.run_subagent(payload)

    assert len(out["findings"]) == 1
    assert out["findings"][0].confirmed is True
    # confirmed-but-not-independently-verified -> queued for a separate verify dispatch
    assert len(out["verify_queue"]) == 1
    assert out["verify_queue"][0].independently_verified is False
