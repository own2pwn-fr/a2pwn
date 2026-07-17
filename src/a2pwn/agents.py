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
from a2pwn.compaction import make_compaction_hook
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


def _executor_prompt(active_exploit_tools: list[str]) -> str:
    prompt = P.EXECUTOR_SYS
    if active_exploit_tools:
        blocked = ", ".join(sorted(active_exploit_tools))
        prompt = (prompt or "") + (
            "\n\nACTIVE EXPLOITATION IS NOT AUTHORISED for this engagement. The following tools are "
            f"hard-blocked at the tool layer and MUST NOT be called: {blocked}."
        )
    return prompt


class _SdkExecutor:
    """Executor backed by the claude-agent-sdk's NATIVE tool-calling loop (in-process MCP tools).

    Exposes the same ``ainvoke(state) -> {messages, candidate_findings, flow_batches}`` shape as a
    prebuilt ReAct agent, so the sub-agent graph node is identical for both backends. Native tool
    calls carry trusted ``tool_use``/``tool_result`` blocks — the model no longer treats the replayed
    transcript as prompt injection (the failure mode of the prompted-JSON path over the subscription).
    """

    def __init__(self, cfg: RoleModels, client, collab, skills, active_exploit_tools, max_turns=30):
        self._model = cfg.executor.model or "sonnet"
        self._prompt = _executor_prompt(active_exploit_tools)
        self._client = client
        self._collab = collab
        self._skills = skills or []
        self._blocked = list(active_exploit_tools or [])
        self._max_turns = max_turns

    async def ainvoke(self, state: dict, config: Any = None) -> dict:
        from langchain_core.messages import AIMessage

        from a2pwn.sdk_agent import run_sdk_agent

        prompt = ""
        for m in reversed(state.get("messages", [])):
            if getattr(m, "type", "") == "human":
                prompt = m.content if isinstance(m.content, str) else str(m.content)
                break
        outcome = await run_sdk_agent(
            model=self._model,
            system_prompt=self._prompt,
            task=prompt,
            client=self._client,
            collab=self._collab,
            skills=self._skills,
            max_turns=self._max_turns,
            active_exploit_blocked=self._blocked,
        )
        return {
            "messages": [AIMessage(content=outcome.summary or "executed task")],
            "candidate_findings": list(outcome.candidate_findings),
            "flow_batches": list(outcome.flow_batches),
        }


def build_executor(
    cfg: RoleModels,
    tools: list[BaseTool],
    active_exploit_tools: list[str],
    compaction_tokens: int = 150_000,
    *,
    client: Any = None,
    collab: Any = None,
    skills: list | None = None,
) -> Any:
    """Build the executor. On the ``claude-code`` subscription backend, use the native SDK
    tool-calling loop (:class:`_SdkExecutor`) — prompted-JSON tool-calling makes that model distrust
    the replayed transcript as prompt injection and refuse. On API backends (native tool-calling),
    use a prebuilt ReAct agent with an auto-compaction ``pre_model_hook``.

    Active-exploitation gating is deterministic in the tool wrappers (a checkpointerless child cannot
    ``interrupt_before``); we also disclose the blocked tools in the prompt so no turns are wasted.
    """
    if cfg.executor.provider == "claude-code" and client is not None:
        return _SdkExecutor(cfg, client, collab, skills, active_exploit_tools)
    model = make_model(cfg.executor)
    return create_react_agent(
        model,
        tools=tools,
        prompt=_executor_prompt(active_exploit_tools),
        pre_model_hook=make_compaction_hook(model, max_tokens=compaction_tokens),
        name="executor",
    )


def build_verifier(
    cfg: RoleModels, tools: list[BaseTool], compaction_tokens: int = 150_000
) -> CompiledStateGraph:
    """Adversarial verifier on the Opus-class role-model (distinct from the executor)."""
    model = make_model(cfg.verifier)
    return create_react_agent(
        model,
        tools=tools,
        prompt=P.ADVERSARIAL_SYS,
        pre_model_hook=make_compaction_hook(model, max_tokens=compaction_tokens),
        name="verifier",
    )


def _judge_messages(ctx: Any) -> list[BaseMessage]:
    if not isinstance(ctx, dict):
        ctx = {"input": ctx}
    return P.render_messages(P.CONTINUATION_JUDGE_SYS, ctx)


def build_continuation_judge(cfg: RoleModels) -> Runnable:
    """A runnable mapping a context dict to a :class:`ContinuationVerdict`.

    Invoked when the master would otherwise STOP: it decides whether the engagement is
    genuinely complete or should push further, returning concrete follow-up tasks. Runs on
    the master role-model (the orchestrator's own judgement)."""
    from a2pwn.models import ContinuationVerdict

    structured = make_model(cfg.master).with_structured_output(ContinuationVerdict)
    return (RunnableLambda(_judge_messages) | structured).with_config(run_name="continuation_judge")


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
