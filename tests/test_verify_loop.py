"""Intra-task adversarial verify loop: empty capture is REJECTED, the executor is
re-driven with the critique, the loop is bounded by max_verify_rounds, and adjudication
is FAIL-CLOSED (a real capture whose deterministic oracle does not re-derive is rejected)."""

import logging

from _graphkit import (
    FakeClarifier,
    FakeExecutor,
    arm_differential,
    build_sub,
    exec_result,
    make_cfg,
    make_finding,
    sub_input,
)
from a2pwn.models import TaskSpec

_NO_QUESTIONS = FakeClarifier(lambda ctx: [])


async def test_empty_capture_is_rejected_then_retried_to_success(monkeypatch, fake_client):
    cfg = make_cfg(max_verify_rounds=3)
    arm_differential(fake_client)  # the oracle confirms once a real captured batch exists
    # Round 1: a "finding" with no captured flows (traffic never proven captured).
    # Round 2 (same key): a real captured batch -> capture + oracle both pass, verifier accepts.
    no_capture = make_finding(flow_ids=())
    real = make_finding(flow_ids=(201, 202), exec_ids=("e-ok",))
    executor = FakeExecutor([exec_result([no_capture]), exec_result([real])])
    sub = build_sub(monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=executor)

    out = await sub.ainvoke(
        sub_input(cfg, intent="task", spec=TaskSpec(task="probe", target="https://app.example.com"))
    )

    assert len(executor.calls) == 2  # rejected once, re-executed once
    result = out["clean_result"]
    assert result.status == "confirmed"
    assert len(result.findings) == 1
    assert result.findings[0].confirmed is True


async def test_verify_round_cap_bounds_the_loop(monkeypatch, fake_client):
    cfg = make_cfg(max_verify_rounds=2)
    # The executor never produces a captured batch: every round rejects.
    executor = FakeExecutor(exec_result([make_finding(flow_ids=())]))
    sub = build_sub(monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=executor)

    out = await sub.ainvoke(
        sub_input(cfg, intent="task", spec=TaskSpec(task="probe", target="https://app.example.com"))
    )

    # execute runs exactly max_verify_rounds times, then distill is forced.
    assert len(executor.calls) == 2
    assert out["clean_result"].status == "partial"
    assert out["clean_result"].findings == []


async def test_escaped_exec_capture_alarm_rejects(monkeypatch, fake_client):
    cfg = make_cfg(max_verify_rounds=1)
    fake_client.stats = {
        "escaped_execs": [{"exec_id": "e-escaped", "cmd": "curl https://app/"}],
    }
    # Flows look present, but the exec that produced them escaped the sandbox.
    escaped = make_finding(flow_ids=(9,), exec_ids=("e-escaped",))
    executor = FakeExecutor(exec_result([escaped]))
    sub = build_sub(monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=executor)

    out = await sub.ainvoke(
        sub_input(cfg, intent="task", spec=TaskSpec(task="probe", target="https://app.example.com"))
    )
    assert out["clean_result"].status == "partial"
    assert out["clean_result"].findings == []


async def test_fail_closed_real_capture_but_oracle_no_delta_is_rejected(monkeypatch, fake_client):
    cfg = make_cfg(max_verify_rounds=1)
    # Capture is provably real (clean exec, flows present) but the differential oracle sees NO
    # delta (default compare_return) -> fail-closed REJECT, never swallowed to a pass.
    fake_client.compare_return = {"status": {"changed": False}, "body": {"identical": True}}
    real_but_unproven = make_finding(flow_ids=(11, 12), exec_ids=("e-ok",), oracle="differential")
    executor = FakeExecutor(exec_result([real_but_unproven]))
    sub = build_sub(monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=executor)

    out = await sub.ainvoke(
        sub_input(cfg, intent="task", spec=TaskSpec(task="probe", target="https://app.example.com"))
    )
    assert out["clean_result"].status == "partial"
    assert out["clean_result"].findings == []


async def test_retry_round_crash_does_not_wipe_prior_confirmed_findings(monkeypatch, fake_client):
    """Regression: a verify-retry round's executor invocation crashing (e.g. the SDK's max-turns
    exhaustion with zero new activity) used to propagate all the way out of the checkpointer=False
    sub-agent graph, landing in run_subagent's outer except and degrading the ENTIRE dispatch to
    "blocked" — discarding every already-confirmed candidate from an earlier round in the SAME
    dispatch, not just the one still being retried. Observed live on a real engagement: a
    multi-candidate task confirmed a real HIGH finding on round 1, a sibling candidate stayed
    unprovable so verify looped, and the retry's executor call errored with zero new activity —
    silently losing the already-proven finding from the final report."""
    cfg = make_cfg(max_verify_rounds=2)
    arm_differential(fake_client)
    real = make_finding(flow_ids=(201, 202), exec_ids=("e-ok",), vuln="broken-access-control")
    unprovable = make_finding(flow_ids=(), vuln="xss", param="p")
    executor = FakeExecutor(
        [
            exec_result([real, unprovable]),  # round 1: one confirms, one doesn't -> retry
            RuntimeError("Claude Code returned an error result: Reached maximum number of turns (40)"),
        ]
    )
    sub = build_sub(monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=executor)

    out = await sub.ainvoke(
        sub_input(cfg, intent="task", spec=TaskSpec(task="probe", target="https://app.example.com"))
    )

    assert len(executor.calls) == 2  # round 1 + the crashing retry
    result = out["clean_result"]
    assert result.status != "blocked"  # the dispatch is NOT degraded wholesale by the retry crash
    assert any(f.vuln_class == "broken-access-control" and f.confirmed for f in result.findings)


async def test_adjudication_reject_reason_is_logged(monkeypatch, fake_client, caplog):
    """Regression: an adjudication REJECT reason previously only reached the (TUI-only) progress
    event bus — a --plain run had no way to tell WHY a candidate never made it into the report.
    It must also be logged at WARNING so the reason is visible without reverse-engineering it from
    source + raw burpwn state after the fact."""
    cfg = make_cfg(max_verify_rounds=1)
    unprovable = make_finding(flow_ids=(), vuln="xss")
    executor = FakeExecutor(exec_result([unprovable]))
    sub = build_sub(monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=executor)

    with caplog.at_level(logging.WARNING, logger="a2pwn"):
        await sub.ainvoke(
            sub_input(cfg, intent="task", spec=TaskSpec(task="probe", target="https://app.example.com"))
        )

    assert any("REJECTED at adjudication" in r.getMessage() for r in caplog.records)


async def test_fail_closed_unprovable_oracle_kind_is_rejected(monkeypatch, fake_client):
    cfg = make_cfg(max_verify_rounds=1)
    # llm_rubric has no deterministic oracle (the 0-FP kernel abstains -> confirmed=False), so
    # even a real capture must be REJECTED rather than confirmed on the LLM's say-so.
    rubric = make_finding(flow_ids=(21, 22), exec_ids=("e-ok",), oracle="llm_rubric")
    executor = FakeExecutor(exec_result([rubric]))
    sub = build_sub(monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=executor)

    out = await sub.ainvoke(
        sub_input(cfg, intent="task", spec=TaskSpec(task="probe", target="https://app.example.com"))
    )
    assert out["clean_result"].status == "partial"
    assert out["clean_result"].findings == []
