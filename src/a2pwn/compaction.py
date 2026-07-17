"""Auto-compaction for the ReAct sub-agents.

A long exploitation grows the executor's transcript without bound — every ``burpwn_req_show``
can return a full captured response body — until it overflows the model's context window and the
sub-agent dies mid-task. This provides a ``pre_model_hook`` for ``create_react_agent`` that, once
the transcript passes a token budget, feeds the model a COMPACTED view — the base system prompt +
a running summary of everything done so far + the most recent turns — so the agent keeps working
to completion.

The compaction is **transient** (returned via ``llm_input_messages``): the full transcript stays
in the graph state, so the executor's finding-harvest still sees every ``report_finding`` artifact.
Only the model's per-call input is shrunk.
"""

from __future__ import annotations

import logging

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage
from langchain_core.messages.utils import count_tokens_approximately

_log = logging.getLogger("a2pwn")

_SUMMARY_SYS = (
    "You are compacting a web-pentest sub-agent's working transcript so it can keep going without "
    "losing the thread. Summarize what has been DONE so far, preserving EVERY operational detail "
    "the agent needs to continue: endpoints and params probed, payloads tried and their outcomes "
    "(status codes, reflected/errored responses), the burpwn workspaces and flow_ids captured, any "
    "findings ALREADY reported via report_finding (vuln class, target, param, flow_ids, oracle), "
    "open leads and next steps, and any creds/tokens/internal hosts discovered. Be concrete and "
    "information-dense — omit nothing load-bearing. Output prose only, no preamble."
)

# Cap the transcript fed to the summarizer so the summary call itself cannot overflow context.
_SUMMARY_INPUT_BUDGET = 120_000
_PER_MSG_CHARS = 6000


def _render(messages: list[BaseMessage]) -> str:
    roles = {"human": "User", "ai": "Assistant", "tool": "Tool", "system": "System"}
    lines: list[str] = []
    for m in messages:
        role = roles.get(getattr(m, "type", ""), getattr(m, "type", "msg"))
        content = m.content if isinstance(m.content, str) else str(m.content)
        text = content[:_PER_MSG_CHARS]
        tcs = getattr(m, "tool_calls", None)
        if tcs:
            text += "\n" + "\n".join(f"[call {t['name']}({str(t.get('args', {}))[:600]})]" for t in tcs)
        name = getattr(m, "name", None)
        lines.append(f"{role}{f' {name}' if name else ''}: {text}")
    return "\n".join(lines)


def _tail_within_budget(messages: list[BaseMessage], budget: int) -> list[BaseMessage]:
    """Keep the most recent messages that fit within ``budget`` approx tokens."""
    kept: list[BaseMessage] = []
    for m in reversed(messages):
        kept.insert(0, m)
        if count_tokens_approximately(kept) > budget:
            kept.pop(0)
            break
    return kept


def make_compaction_hook(
    model: BaseChatModel, *, max_tokens: int = 150_000, keep_recent: int = 8
):
    """A ``pre_model_hook`` that compacts the transcript once it passes ``max_tokens``.

    ``max_tokens<=0`` disables it (returns a no-op passthrough hook)."""

    async def _passthrough(state: dict) -> dict:
        return {}

    if max_tokens is None or max_tokens <= 0:
        return _passthrough

    async def _pre_model_hook(state: dict) -> dict:
        messages: list[BaseMessage] = state.get("messages", [])
        if not messages or count_tokens_approximately(messages) <= max_tokens:
            return {}  # under budget: the agent uses the full transcript unchanged

        system = [m for m in messages if isinstance(m, SystemMessage)]
        body = [m for m in messages if not isinstance(m, SystemMessage)]

        # Choose a recent window that never starts on an orphan tool result (a ToolMessage with no
        # preceding tool call would be an invalid sequence for API backends).
        cut = max(0, len(body) - keep_recent)
        while cut < len(body) and getattr(body[cut], "type", "") == "tool":
            cut += 1
        older, recent = body[:cut], body[cut:]
        if not older:
            return {}

        to_summarize = _tail_within_budget(older, _SUMMARY_INPUT_BUDGET)
        dropped_prefix = len(older) - len(to_summarize)
        try:
            reply = await model.ainvoke(
                [SystemMessage(content=_SUMMARY_SYS), HumanMessage(content=_render(to_summarize))]
            )
            summary = reply.content if isinstance(reply.content, str) else str(reply.content)
        except Exception as exc:  # noqa: BLE001 - compaction must never abort the run
            _log.warning("compaction summary failed, keeping recent turns only: %s", exc)
            summary = "(earlier transcript omitted; continue from the recent turns below)"

        prefix = f"[{dropped_prefix} earlier message(s) omitted] " if dropped_prefix else ""
        note = HumanMessage(content=f"[CONTEXT COMPACTED — progress so far]\n{prefix}{summary}")
        _log.info(
            "compaction: transcript ~%dk tok -> summary + %d recent (%d older summarised)",
            count_tokens_approximately(messages) // 1000,
            len(recent),
            len(older),
        )
        # Transient: the FULL transcript stays in state (finding-harvest intact); only the model's
        # input for THIS call is the compacted view.
        return {"llm_input_messages": [*system, note, *recent]}

    return _pre_model_hook
