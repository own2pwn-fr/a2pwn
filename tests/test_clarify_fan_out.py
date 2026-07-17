"""Clarify fork = in-graph Send fan-out: one isolated answerer per question,
handed a COMPACTED context, bounded by max_clarify_rounds."""

from _graphkit import FakeClarifier, FakeExecutor, FakeFork, build_sub, exec_result, make_cfg, sub_input
from a2pwn.models import MasterContextView, TaskSpec


def _run_child(monkeypatch, fake_client, cfg, clarifier, fork):
    sub = build_sub(
        monkeypatch,
        cfg,
        fake_client,
        clarifier=clarifier,
        executor=FakeExecutor(exec_result([])),
        fork=fork,
    )
    spec = TaskSpec(task="probe login", target="https://app.example.com/login")
    return sub.invoke(sub_input(cfg, intent="task", spec=spec))


def test_one_fork_per_question_with_compacted_ctx(monkeypatch, fake_client):
    cfg = make_cfg()
    # Ask two questions the first round, none once they are answered.
    clarifier = FakeClarifier(lambda ctx: ["which param?", "which identity?"] if not ctx["clarifications"] else [])
    fork = FakeFork()
    _run_child(monkeypatch, fake_client, cfg, clarifier, fork)

    assert len(fork.calls) == 2  # one isolated answerer per open question
    asked = {q for q, _ctx in fork.calls}
    assert asked == {"which param?", "which identity?"}
    # each fork is seeded with a COMPACTED projection, never the raw MasterState
    assert all(isinstance(ctx, MasterContextView) for _q, ctx in fork.calls)


def test_clarify_round_cap_stops_the_loop(monkeypatch, fake_client):
    cfg = make_cfg(max_clarify_rounds=2)
    # A pathological clarifier that never stops asking — the cap must break the loop.
    clarifier = FakeClarifier(lambda ctx: ["still ambiguous?"])
    fork = FakeFork()
    out = _run_child(monkeypatch, fake_client, cfg, clarifier, fork)

    # rounds 1 and 2 fan out one question each, then compose_prompt is forced.
    assert len(fork.calls) == 2
    assert out["clean_result"].status in {"no_finding", "partial"}
