"""Auto-compaction pre_model_hook: keep the base prompt + a running summary + recent turns once
the transcript passes the token budget, so a long sub-agent runs to completion."""

from __future__ import annotations

from langchain_core.messages import AIMessage, SystemMessage, ToolMessage

from a2pwn.compaction import make_compaction_hook


class _FakeSummarizer:
    def __init__(self):
        self.calls = 0

    async def ainvoke(self, messages, *a, **k):
        self.calls += 1
        return AIMessage(content="COMPACTED SUMMARY: probed /api/file, flow_ids [3,6]")


def _big_transcript(n: int) -> list:
    msgs: list = [SystemMessage(content="you are the executor")]
    for i in range(n):
        msgs.append(AIMessage(content="x" * 4000, tool_calls=[{"id": f"c{i}", "name": "burpwn_exec", "args": {"i": i}, "type": "tool_call"}]))
        msgs.append(ToolMessage(content="y" * 4000, tool_call_id=f"c{i}", name="burpwn_exec"))
    return msgs


async def test_passthrough_under_budget():
    hook = make_compaction_hook(_FakeSummarizer(), max_tokens=1_000_000)
    out = await hook({"messages": _big_transcript(3)})
    assert out == {}


async def test_disabled_when_zero():
    fake = _FakeSummarizer()
    hook = make_compaction_hook(fake, max_tokens=0)
    out = await hook({"messages": _big_transcript(50)})
    assert out == {} and fake.calls == 0


async def test_compacts_over_budget():
    fake = _FakeSummarizer()
    hook = make_compaction_hook(fake, max_tokens=2000, keep_recent=4)
    msgs = _big_transcript(30)
    out = await hook({"messages": msgs})
    assert fake.calls == 1
    compacted = out["llm_input_messages"]
    # base system prompt preserved, a summary note injected, and the tail kept
    assert isinstance(compacted[0], SystemMessage)
    assert any("CONTEXT COMPACTED" in getattr(m, "content", "") for m in compacted)
    assert len(compacted) < len(msgs)
    # the recent window must not start on an orphan tool result (would be an invalid sequence)
    body = [m for m in compacted if not isinstance(m, SystemMessage)]
    # first body msg is the summary note (Human), never a bare ToolMessage
    assert not isinstance(body[0], ToolMessage)


async def test_summary_failure_degrades_gracefully():
    class _Boom:
        async def ainvoke(self, *a, **k):
            raise RuntimeError("model down")

    hook = make_compaction_hook(_Boom(), max_tokens=2000, keep_recent=4)
    out = await hook({"messages": _big_transcript(30)})
    # still returns a compacted view (recent turns), just without a real summary
    assert "llm_input_messages" in out
