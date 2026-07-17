"""Clarify fork = in-graph Send fan-out: one isolated answerer per question,
handed a COMPACTED context, bounded by max_clarify_rounds."""

from _graphkit import FakeClarifier, FakeExecutor, FakeFork, build_sub, exec_result, make_cfg, sub_input
from a2pwn.models import MasterContextView, TaskSpec


async def _run_child(monkeypatch, fake_client, cfg, clarifier, fork):
    sub = build_sub(
        monkeypatch,
        cfg,
        fake_client,
        clarifier=clarifier,
        executor=FakeExecutor(exec_result([])),
        fork=fork,
    )
    spec = TaskSpec(task="probe login", target="https://app.example.com/login")
    return await sub.ainvoke(sub_input(cfg, intent="task", spec=spec))


async def test_one_fork_per_question_with_compacted_ctx(monkeypatch, fake_client):
    cfg = make_cfg()
    # Ask two questions the first round, none once they are answered.
    clarifier = FakeClarifier(lambda ctx: ["which param?", "which identity?"] if not ctx["clarifications"] else [])
    fork = FakeFork()
    await _run_child(monkeypatch, fake_client, cfg, clarifier, fork)

    assert len(fork.calls) == 2  # one isolated answerer per open question
    asked = {q for q, _ctx in fork.calls}
    assert asked == {"which param?", "which identity?"}
    # each fork is seeded with a COMPACTED projection, never the raw MasterState
    assert all(isinstance(ctx, MasterContextView) for _q, ctx in fork.calls)


async def test_clarify_round_cap_stops_the_loop(monkeypatch, fake_client):
    cfg = make_cfg(max_clarify_rounds=2)
    # A pathological clarifier that never stops asking — the cap must break the loop.
    clarifier = FakeClarifier(lambda ctx: ["still ambiguous?"])
    fork = FakeFork()
    out = await _run_child(monkeypatch, fake_client, cfg, clarifier, fork)

    # rounds 1 and 2 fan out one question each, then compose_prompt is forced.
    assert len(fork.calls) == 2
    assert out["clean_result"].status in {"no_finding", "partial"}


async def test_clarifier_failure_degrades_to_self_contained(monkeypatch, fake_client):
    """A clarifier hiccup (raised error / bad structured output) must not waste the dispatch —
    the child proceeds straight to compose_prompt/execute instead of crashing."""
    cfg = make_cfg()

    def _boom(ctx):
        raise RuntimeError("structured output failed: raw reply '[]'")

    sub = build_sub(
        monkeypatch,
        cfg,
        fake_client,
        clarifier=FakeClarifier(_boom),
        executor=FakeExecutor(exec_result([])),
        fork=FakeFork(),
    )
    spec = TaskSpec(task="probe login", target="https://app.example.com/login")
    out = await sub.ainvoke(sub_input(cfg, intent="task", spec=spec))
    # Reached distill despite the clarifier blowing up.
    assert out["clean_result"].status in {"no_finding", "partial", "blocked"}
