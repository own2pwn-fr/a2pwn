"""Role-agent builders (clarifier / executor / verifier) plus the MasterFork.

Three role agents plus one isolated-fork answerer implement the clean-history mandate:

* clarifier — cheap model, structured ``list[str]`` of open questions (or ``[]``).
* executor — a ReAct agent that drives burpwn; active-exploit tools are gated
  DETERMINISTICALLY in the tool wrappers (a checkpointerless child cannot ``interrupt_before``).
* verifier — an independent, Opus-class ReAct agent that re-derives every candidate.
* MasterFork — answers ONE clarify question re-seeded with the *compacted* context only;
  the master planner is never re-invoked, so forks cannot blow up the parent context.
"""

from __future__ import annotations

import asyncio
from typing import Any

from langchain_core.messages import BaseMessage
from langchain_core.runnables import Runnable, RunnableLambda
from langchain_core.tools import BaseTool
from langgraph.graph.state import CompiledStateGraph
from langgraph.prebuilt import create_react_agent
from pydantic import BaseModel, Field

import a2pwn.prompts as P
from a2pwn.backends import make_model
from a2pwn.config import RoleModels
from a2pwn.models import MasterContextView, QAPair


class _ClarifyQuestions(BaseModel):
    """Structured envelope for the clarifier's open questions."""

    questions: list[str] = Field(default_factory=list)


def _clarify_messages(ctx: Any) -> list[BaseMessage]:
    if not isinstance(ctx, dict):
        ctx = {"input": ctx}
    return P.render_messages(P.CLARIFIER_SYS, ctx)


def _clarify_extract(out: Any) -> list[str]:
    if isinstance(out, _ClarifyQuestions):
        return [q for q in out.questions if q and q.strip()]
    if isinstance(out, dict):
        questions = out.get("questions", [])
        return [q for q in questions if isinstance(q, str) and q.strip()]
    return []


def build_clarifier(cfg: RoleModels) -> Runnable:
    """A runnable that maps a context dict to a ``list[str]`` of clarify questions.

    Uses the cheap clarifier model with structured output so the graph's ``clarify``
    node receives a clean list (empty => the task is self-contained).
    """
    structured = make_model(cfg.clarifier).with_structured_output(_ClarifyQuestions)
    chain = RunnableLambda(_clarify_messages) | structured | RunnableLambda(_clarify_extract)
    return chain.with_config(run_name="clarifier")


def build_executor(
    cfg: RoleModels, tools: list[BaseTool], active_exploit_tools: list[str]
) -> CompiledStateGraph:
    """ReAct executor.

    Active-exploitation gating is enforced DETERMINISTICALLY in the tool wrappers (the burpwn
    scope/active guard hard-blocks the call), NOT via ``interrupt_before`` — the sub-agent graph is
    compiled ``checkpointer=False`` so an ``interrupt_before`` here could never fire. When active
    exploitation is not authorised we additionally disclose the blocked tools in the prompt so the
    model does not waste turns attempting them.
    """
    prompt = P.EXECUTOR_SYS
    if active_exploit_tools:
        blocked = ", ".join(sorted(active_exploit_tools))
        prompt = (prompt or "") + (
            "\n\nACTIVE EXPLOITATION IS NOT AUTHORISED for this engagement. The following tools are "
            f"hard-blocked at the tool layer and MUST NOT be called: {blocked}."
        )
    return create_react_agent(
        make_model(cfg.executor),
        tools=tools,
        prompt=prompt,
        name="executor",
    )


def build_verifier(cfg: RoleModels, tools: list[BaseTool]) -> CompiledStateGraph:
    """Adversarial verifier on the Opus-class role-model (distinct from the executor)."""
    return create_react_agent(
        make_model(cfg.verifier),
        tools=tools,
        prompt=P.ADVERSARIAL_SYS,
        name="verifier",
    )


def _message_text(message: BaseMessage) -> str:
    content = message.content
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                parts.append(str(block.get("text", block.get("content", ""))))
        return "\n".join(p for p in parts if p).strip()
    return str(content).strip()


class MasterFork:
    """Isolated context fork: answers clarify questions without re-invoking the master."""

    def __init__(self, cfg: RoleModels) -> None:
        self._model = make_model(cfg.clarifier)

    async def answer(self, question: str, ctx: MasterContextView) -> QAPair:
        """Answer ONE question re-seeded with the compacted snapshot only."""
        compact = ctx.compact()
        messages = P.render_messages(
            P.MASTER_FORK_SYS, {"question": question, "context": compact}
        )
        reply = await self._model.ainvoke(messages)
        return QAPair(question=question, answer=_message_text(reply))

    async def answer_all(
        self, questions: list[str], ctx: MasterContextView
    ) -> list[QAPair]:
        """Answer every question in parallel (used outside the graph; in-graph uses Send)."""
        return await asyncio.gather(*[self.answer(q, ctx) for q in questions])


def freeze_context(state: Any) -> MasterContextView:
    """Immutable, COMPACTED snapshot of canonical master state handed to a fork."""
    view = MasterContextView(
        objective=state["objective"],
        engagement=state["engagement"],
        history=list(state.get("history", [])),
        known_findings=list(state.get("findings", [])),
    )
    return view.compact()
