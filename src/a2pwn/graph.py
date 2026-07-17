"""Both LangGraph state machines, their reducers, the dispatch router, and the
fork-boundary wrapper.

The MASTER graph reasons over a *curated* append-only history and dispatches work
to a stateless SUB-AGENT subgraph. The subgraph owns its own chatty channels
(``messages`` / ``clarifications``) and is compiled ``checkpointer=False`` so its
transcript is garbage-collected the instant ``SUBAGENT_GRAPH.invoke`` returns — it
is reached ONLY through the plain function :func:`run_subagent`, never via
``add_node(compiled_subgraph)``. This is the clean-history-by-construction mandate:
there is physically no parent channel a transcript could leak into.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import operator
from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Send
from pydantic import BaseModel, Field

import a2pwn.prompts as P
from a2pwn.agents import (
    MasterFork,
    build_clarifier,
    build_executor,
    build_verifier,
    freeze_context,
)
from a2pwn.backends import make_model
from a2pwn.budget import DispatchBudget
from a2pwn.burpwn import BurpwnClient, FlowBatchManager
from a2pwn.config import A2pwnConfig
from a2pwn.models import (
    CleanResult,
    DispatchRecord,
    EngagementSpec,
    Finding,
    FlowBatchRef,
    MasterContextView,
    QAPair,
    SubAgentInput,
    TaskSpec,
    VerifierReport,
)
from a2pwn.oracles import VerificationOracle, differential, run_oracle, two_identity

# The compiled child subgraph, threaded in by ``build_master_graph``. ``run_subagent``
# references it here so the master graph never wires it as a node (clean-history guard).
SUBAGENT_GRAPH: CompiledStateGraph | None = None


# --------------------------------------------------------------------------- #
# async bridge
# --------------------------------------------------------------------------- #
def _run(coro: Any) -> Any:
    """Drive a coroutine to completion from a synchronous graph node.

    LangGraph runs plain-``def`` nodes; the burpwn client / collaborator / fork are
    async. When no loop is running we simply ``asyncio.run``; when one is (the graph
    was driven async), we hop to a worker thread with its own loop so we never nest.
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


# --------------------------------------------------------------------------- #
# reducers
# --------------------------------------------------------------------------- #
def append_curated(left: list, right: list) -> list:
    """Plain append — the canonical history grows, never merges transcripts."""
    return left + right


def merge_findings(left: list[Finding], right: list[Finding]) -> list[Finding]:
    """Dedup by ``Finding.key``; on collision keep the higher-ranked finding.

    rank = independently_verified(3) > confirmed(2) > candidate(1). This is MONOTONE:
    a reconciliation pass can only PROMOTE a finding, never downgrade or drop one that
    was already confirmed.
    """
    by_key: dict[str, Finding] = {f.key: f for f in left}
    for f in right:
        cur = by_key.get(f.key)
        if cur is None or f.rank() >= cur.rank():
            by_key[f.key] = f
    return list(by_key.values())


def _merge_budget(acc: DispatchBudget, inc: DispatchBudget) -> DispatchBudget:
    """Fold per-dispatch spend deltas onto the accumulator (parallel-Send safe).

    Each ``run_subagent`` returns a ``DispatchBudget(spent=1)`` delta; folding keeps the
    accumulator's caps and sums the spend so N concurrent dispatches count as N.
    """
    if acc is None:  # pragma: no cover - defensive; LangGraph sets the first value directly
        return inc
    return acc.model_copy(
        update={"spent": acc.spent + inc.spent, "stopped": acc.stopped or inc.stopped}
    )


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #
class MasterState(TypedDict):
    """Curated master state — NO ``messages``/``scratch``/``clarifications`` channel."""

    engagement: EngagementSpec
    objective: str
    history: Annotated[list[DispatchRecord], append_curated]
    pending: list[TaskSpec]
    deferred: list[TaskSpec]
    dispatch_results: Annotated[list[CleanResult], operator.add]
    findings: Annotated[list[Finding], merge_findings]
    verify_queue: Annotated[list[Finding], operator.add]
    phase: str
    round: int
    budget: Annotated[DispatchBudget, _merge_budget]


class SubAgentState(TypedDict):
    """Ephemeral child state — dies with ``SUBAGENT_GRAPH.invoke``."""

    intent: str
    spec: TaskSpec | None
    candidate: Finding | None
    master_ctx: MasterContextView
    clarifications: Annotated[list[QAPair], operator.add]
    refined_prompt: str
    messages: Annotated[list[BaseMessage], add_messages]
    candidate_findings: list[Finding]
    flow_batches: list[FlowBatchRef]
    critique: VerifierReport | None
    verify_round: int
    clarify_round: int
    clean_result: CleanResult


# --------------------------------------------------------------------------- #
# partitioning + master routing
# --------------------------------------------------------------------------- #
def partition_pending(pending: list[TaskSpec]) -> tuple[list[TaskSpec], list[TaskSpec]]:
    """Split pending tasks into (parallel, deferred).

    Parallel = a task that is read-only (``intent=='recon'`` / ``not mutates`` /
    ``target is None``) OR the first task to claim a given mutable target this phase.
    A second task that mutates an already-claimed target is deferred to the next phase
    (context is re-frozen per phase) so two siblings never assume contradictory state.
    """
    parallel: list[TaskSpec] = []
    deferred: list[TaskSpec] = []
    claimed: set[str] = set()
    for t in pending:
        read_only = t.intent == "recon" or not t.mutates or t.target is None
        if read_only:
            parallel.append(t)
            continue
        if t.target in claimed:
            deferred.append(t)
        else:
            claimed.add(t.target)
            parallel.append(t)
    return parallel, deferred


def _promoted_keys(state: MasterState) -> set[str]:
    return {f.key for f in state.get("findings", []) if f.independently_verified}


def _pending_verify(state: MasterState) -> list[Finding]:
    promoted = _promoted_keys(state)
    seen: set[str] = set()
    out: list[Finding] = []
    for f in state.get("verify_queue", []):
        if f.key in promoted or f.key in seen:
            continue
        seen.add(f.key)
        out.append(f)
    return out


def _select_dispatch(
    state: MasterState,
) -> tuple[str, list[SubAgentInput], list[TaskSpec]]:
    """Decide this phase's dispatch: (mode, per-invocation inputs, deferred tasks)."""
    ctx = freeze_context(state)
    to_verify = _pending_verify(state)
    if to_verify:
        inputs = [
            SubAgentInput(
                dispatch_id=f"{state['round']}-verify-{i}",
                intent="verify",
                candidate=f,
                master_ctx=ctx,
            )
            for i, f in enumerate(to_verify)
        ]
        return "verify", inputs, []

    parallel, deferred = partition_pending(state.get("pending", []))
    clamped = state["budget"].clamp_batch(parallel)
    overflow = parallel[len(clamped):]
    inputs = [
        SubAgentInput(
            dispatch_id=f"{state['round']}-task-{i}",
            intent="task",
            spec=t,
            master_ctx=ctx,
        )
        for i, t in enumerate(clamped)
    ]
    return "task", inputs, deferred + overflow


def route_dispatch(state: MasterState) -> list[Send] | str:
    """Conditional edge after ``plan``: fan out Sends, or route to ``report``.

    Guard first: an exhausted budget (spend cap or TaskStop) or hitting the phase cap
    routes straight to the report. Otherwise emit one ``Send`` per selected invocation;
    an empty selection also ends the run.
    """
    budget = state["budget"]
    if budget.exhausted or state["round"] >= budget.max_phases:
        return "report"
    _mode, inputs, _deferred = _select_dispatch(state)
    if not inputs:
        return "report"
    return [Send("run_subagent", inp) for inp in inputs]


# --------------------------------------------------------------------------- #
# fork boundary
# --------------------------------------------------------------------------- #
def run_subagent(payload: SubAgentInput) -> dict:
    """FORK BOUNDARY. Invoke the stateless child and return ONLY curated updates.

    The child's clarify Q&A, ReAct transcript, verifier critique and retries live and
    die inside this call; the parent only ever sees the distilled ``CleanResult`` plus
    the confirmed findings. A task dispatch enqueues its confirmed-but-not-yet-
    independently-verified findings for a separate independent-verify dispatch.
    """
    sub = SUBAGENT_GRAPH
    if sub is None:  # pragma: no cover - build_master_graph always sets it
        raise RuntimeError("SUBAGENT_GRAPH is not initialised; build the master graph first")
    thread_id = f"{payload.master_ctx.engagement.name}:{payload.dispatch_id}"
    out = sub.invoke(
        {
            "intent": payload.intent,
            "spec": payload.spec,
            "candidate": payload.candidate,
            "master_ctx": payload.master_ctx,
            "clarifications": [],
            "refined_prompt": "",
            "messages": [],
            "candidate_findings": [],
            "flow_batches": [],
            "critique": None,
            "verify_round": 0,
            "clarify_round": 0,
        },
        config={"configurable": {"thread_id": thread_id}},
    )
    clean = out["clean_result"].model_copy(update={"dispatch_id": payload.dispatch_id})
    confirmed = [f for f in clean.findings if f.confirmed]
    verify_q = (
        [f for f in confirmed if not f.independently_verified]
        if payload.intent == "task"
        else []
    )
    return {
        "dispatch_results": [clean],
        "findings": confirmed,
        "verify_queue": verify_q,
        "budget": DispatchBudget(spent=1),
    }


# --------------------------------------------------------------------------- #
# subagent nodes
# --------------------------------------------------------------------------- #
def _active_tools(cfg: A2pwnConfig, tools: list) -> list[str]:
    if cfg.engagement.active_exploit_allowed:
        return []
    return [
        t.name
        for t in tools
        if getattr(t, "name", "").startswith("exploit_") or "active" in getattr(t, "name", "")
    ]


def _clarify_ctx(state: SubAgentState) -> dict:
    return {
        "intent": state.get("intent"),
        "spec": state.get("spec"),
        "candidate": state.get("candidate"),
        "master_ctx": state["master_ctx"].compact(),
        "clarifications": state.get("clarifications", []),
    }


def need_clarify(state: dict) -> list[Send] | str:
    """Route the clarify loop: fan out one isolated ``answer_one`` per open question,
    or proceed to ``compose_prompt`` when self-contained or the round cap is reached.

    Expects ``questions`` (this round's open questions), ``clarify_round`` and the cap
    ``_max_clarify`` in the passed mapping; the graph edge injects them.
    """
    questions = state.get("questions", [])
    rounds = state.get("clarify_round", 0)
    cap = state.get("_max_clarify", 4)
    if questions and rounds <= cap:
        ctx = state["master_ctx"].compact()
        return [Send("answer_one", {"question": q, "ctx": ctx}) for q in questions]
    return "compose_prompt"


def verify_gate(state: dict) -> Literal["execute", "distill"]:
    """Loop back to ``execute`` on an unaccepted critique (until the verify-round cap),
    otherwise ``distill``."""
    critique = state.get("critique")
    rounds = state.get("verify_round", 0)
    cap = state.get("_max_verify", 3)
    if critique is not None and not critique.accepted and rounds < cap:
        return "execute"
    return "distill"


def _harvest(messages: list[BaseMessage]) -> tuple[list[Finding], list[FlowBatchRef]]:
    """Pull ``Finding`` / ``FlowBatchRef`` artifacts out of a ReAct transcript."""
    findings: list[Finding] = []
    batches: list[FlowBatchRef] = []
    for m in messages:
        artifact = getattr(m, "artifact", None)
        if artifact is None:
            continue
        items = artifact if isinstance(artifact, list) else [artifact]
        for it in items:
            if isinstance(it, Finding):
                findings.append(it)
                if it.flow_batch not in batches:
                    batches.append(it.flow_batch)
            elif isinstance(it, FlowBatchRef):
                batches.append(it)
    return findings, batches


def _invoke_agent(agent: Any, prompt: str) -> dict:
    result = agent.invoke({"messages": [HumanMessage(content=prompt)]})
    return result if isinstance(result, dict) else {"messages": []}


def _last_text(result: dict) -> str:
    messages = result.get("messages", []) if isinstance(result, dict) else []
    if not messages:
        return ""
    content = getattr(messages[-1], "content", "")
    return content if isinstance(content, str) else str(content)


def _verifier_notes(verifier: Any, rejected: list[Finding], not_done: list[str]) -> str:
    """Best-effort adversarial narrative from the independent verifier role-model.

    The deterministic oracle already decided accept/reject; this only enriches the
    critique text and is skipped whenever the verifier cannot be cheaply invoked."""
    invoke = getattr(verifier, "invoke", None)
    if invoke is None or (not rejected and not not_done):
        return ""
    prompt = (
        "As the independent adversarial verifier, summarise why these candidates were "
        "not proven and what the executor must still demonstrate:\n"
        + "\n".join(f"- {c.key}" for c in rejected)
        + "\n".join(f"- {g}" for g in not_done)
    )
    try:
        return _last_text(_invoke_agent(verifier, prompt))
    except Exception:
        return ""


def build_subagent_graph(
    cfg: A2pwnConfig,
    client: BurpwnClient,
    fork: MasterFork,
    tools: list,
    collab: Any,
) -> CompiledStateGraph:
    """Compile the stateless sub-agent subgraph (``checkpointer=False`` HARD)."""
    clarifier = build_clarifier(cfg.models)
    executor = build_executor(cfg.models, tools, _active_tools(cfg, tools))
    verifier = build_verifier(cfg.models, tools)
    fbm = FlowBatchManager(client)

    def _clarify(state: SubAgentState) -> dict:
        return {"clarify_round": state.get("clarify_round", 0) + 1}

    def _clarify_edge(state: SubAgentState) -> list[Send] | str:
        questions = clarifier.invoke(_clarify_ctx(state))
        aug = {
            "questions": list(questions or []),
            "clarify_round": state.get("clarify_round", 0),
            "master_ctx": state["master_ctx"],
            "_max_clarify": cfg.max_clarify_rounds,
        }
        return need_clarify(aug)

    def _answer_one(payload: dict) -> dict:
        qa = _run(fork.answer(payload["question"], payload["ctx"]))
        return {"clarifications": [qa]}

    def _compose(state: SubAgentState) -> dict:
        spec = state.get("spec")
        cand = state.get("candidate")
        if spec is not None:
            task = spec.task
        elif cand is not None:
            task = f"Independently reproduce and verify finding {cand.key} from an empty transcript."
        else:
            task = state["master_ctx"].objective
        lines = [f"TASK:\n{task}"]
        if spec is not None and spec.hints:
            lines.append("HINTS:\n" + "\n".join(f"- {h}" for h in spec.hints))
        if cand is not None:
            lines.append("CANDIDATE FINDING:\n" + cand.model_dump_json(indent=2))
        qas = state.get("clarifications", [])
        if qas:
            lines.append(
                "CLARIFICATIONS:\n"
                + "\n".join(f"Q: {p.question}\nA: {p.answer}" for p in qas)
            )
        lines.append(
            "IN-SCOPE TARGETS:\n" + ", ".join(state["master_ctx"].engagement.targets)
        )
        return {"refined_prompt": "\n\n".join(lines)}

    def _execute(state: SubAgentState) -> dict:
        prompt = state.get("refined_prompt") or state["master_ctx"].objective
        critique = state.get("critique")
        if critique is not None and not critique.accepted:
            gaps = "\n".join(f"- {g}" for g in critique.not_done)
            prompt += (
                "\n\nVERIFIER REJECTED THE PRIOR ATTEMPT. Address every gap and gather"
                f" real captured evidence:\n{critique.notes}\n{gaps}"
            )
        result = _invoke_agent(executor, prompt)
        messages = list(result.get("messages", []))
        findings = list(result.get("candidate_findings", []))
        batches = list(result.get("flow_batches", []))
        if not findings:
            findings, harvested = _harvest(messages)
            batches = batches or harvested
        merged: dict[str, Finding] = {f.key: f for f in state.get("candidate_findings", [])}
        for f in findings:
            merged[f.key] = f
        return {
            "messages": messages,
            "candidate_findings": list(merged.values()),
            "flow_batches": batches,
        }

    async def _maybe_oracle(candidate: Finding):
        fids = candidate.flow_batch.flow_ids
        if candidate.oracle_kind == "differential" and len(fids) >= 2:
            return await differential(client, fids[0], fids[1], {"signal": "any"})
        if candidate.oracle_kind == "two_identity" and len(fids) >= 2:
            return await two_identity(client, fids[0], fids[1])
        if candidate.oracle_kind in {"marker", "oob", "timing", "signature"}:
            spec = VerificationOracle(kind=candidate.oracle_kind)
            ctx = {
                "client": client,
                "collab": collab,
                "flow_id": candidate.flow_batch.key_flow,
                "correlation_id": None,
            }
            try:
                return await run_oracle(spec, ctx)
            except Exception:
                return None
        return None

    def _adjudicate(candidate: Finding) -> tuple[bool, str]:
        batch = candidate.flow_batch
        if not batch.flow_ids:
            return False, f"REJECT {candidate.key}: empty flow batch — capture alarm"
        ok, reason = _run(fbm.assert_capture(batch, batch.exec_ids))
        if not ok:
            return False, reason
        if _run(fbm.tls_passthru_blocked(batch)):
            return False, f"BLOCKED {candidate.key}: tls-passthru target — MITM blocked, not testable"
        res = _run(_maybe_oracle(candidate))
        if res is not None and not res.confirmed:
            return False, f"REJECT {candidate.key}: oracle {candidate.oracle_kind} did not re-derive ({res.evidence})"
        return True, ""

    def _verify(state: SubAgentState) -> dict:
        round_ = state.get("verify_round", 0) + 1
        candidates = state.get("candidate_findings", [])
        confirmed: list[Finding] = []
        rejected: list[Finding] = []
        not_done: list[str] = []
        capture_ok = True
        for c in candidates:
            ok, reason = _adjudicate(c)
            if ok:
                confirmed.append(c.model_copy(update={"confirmed": True}))
            else:
                rejected.append(c)
                not_done.append(reason)
                if "ALARM" in reason or "capture" in reason.lower():
                    capture_ok = False
        accepted = not rejected
        notes = f"verified {len(confirmed)}/{len(candidates)} candidate(s); round {round_}"
        if rejected:
            adversarial = _verifier_notes(verifier, rejected, not_done)
            if adversarial:
                notes = f"{notes}. {adversarial}"
        report = VerifierReport(
            accepted=accepted,
            confirmed=confirmed,
            rejected=rejected,
            not_done=not_done,
            capture_ok=capture_ok,
            notes=notes,
        )
        return {
            "critique": report,
            "verify_round": round_,
            "candidate_findings": confirmed if accepted else candidates,
        }

    def _verify_edge(state: SubAgentState) -> Literal["execute", "distill"]:
        aug = {
            "critique": state.get("critique"),
            "verify_round": state.get("verify_round", 0),
            "_max_verify": cfg.max_verify_rounds,
        }
        return verify_gate(aug)

    def _distill(state: SubAgentState) -> dict:
        intent = state["intent"]
        critique = state.get("critique")
        strip = FlowBatchManager.strip_nul

        if intent == "verify":
            cand = state.get("candidate")
            if cand is not None and critique is not None and critique.accepted:
                findings = [
                    cand.model_copy(
                        update={
                            "confirmed": True,
                            "independently_verified": True,
                            "evidence": strip(cand.evidence),
                        }
                    )
                ]
            else:
                # Reconciliation is monotone: never downgrade a prior confirmed finding.
                findings = []
        else:
            base = critique.confirmed if critique is not None else []
            findings = [f.model_copy(update={"evidence": strip(f.evidence)}) for f in base]

        blocked = bool(
            critique is not None and any("BLOCKED" in g for g in critique.not_done)
        )
        candidates = state.get("candidate_findings", [])
        if findings:
            status: Literal["confirmed", "partial", "no_finding", "blocked"] = "confirmed"
        elif blocked:
            status = "blocked"
        elif candidates or (critique is not None and critique.rejected):
            status = "partial"
        else:
            status = "no_finding"

        batches = state.get("flow_batches", []) or [f.flow_batch for f in findings]
        next_hops: list[TaskSpec] = []
        for f in findings:
            for enabled in f.enables:
                next_hops.append(
                    TaskSpec(
                        task=f"Pursue cross-chain: {f.key} enables {enabled}.",
                        intent="chain",
                        target=f.target,
                        hints=[f"origin_finding={f.key}"],
                    )
                )
        residual = list(critique.not_done) if critique is not None else []
        summary = (
            critique.notes
            if critique is not None
            else f"{status}: {len(findings)} finding(s)"
        )
        result = CleanResult(
            dispatch_id="",
            status=status,
            findings=findings,
            flow_batches=batches,
            residual_gaps=residual,
            next_hops=next_hops,
            summary=summary,
        )
        return {"clean_result": result}

    builder = StateGraph(SubAgentState)
    builder.add_node("clarify", _clarify)
    builder.add_node("answer_one", _answer_one)
    builder.add_node("compose_prompt", _compose)
    builder.add_node("execute", _execute)
    builder.add_node("verify", _verify)
    builder.add_node("distill", _distill)

    builder.add_edge(START, "clarify")
    builder.add_conditional_edges("clarify", _clarify_edge, ["answer_one", "compose_prompt"])
    builder.add_edge("answer_one", "clarify")
    builder.add_edge("compose_prompt", "execute")
    builder.add_edge("execute", "verify")
    builder.add_conditional_edges("verify", _verify_edge, ["execute", "distill"])
    builder.add_edge("distill", END)

    return builder.compile(checkpointer=False)


# --------------------------------------------------------------------------- #
# master nodes
# --------------------------------------------------------------------------- #
class _PlanOut(BaseModel):
    """Structured planner output — the fresh TaskSpecs for this phase."""

    tasks: list[TaskSpec] = Field(default_factory=list)


def propose_tasks(planner: Any, state: MasterState) -> list[TaskSpec]:
    """Ask the master planner for fresh TaskSpecs. Degrades to ``[]`` on any error so a
    missing/offline model ends the run cleanly instead of hanging."""
    try:
        ctx = {
            "objective": state["objective"],
            "engagement": state["engagement"],
            "history": state["history"][-8:],
            "findings": state.get("findings", []),
        }
        messages = P.render_messages(P.MASTER_PLAN_SYS, ctx)
        out = _run(planner.with_structured_output(_PlanOut).ainvoke(messages))
        return list(out.tasks)
    except Exception:
        return []


def _make_bootstrap(cfg: A2pwnConfig):
    def _bootstrap_node(state: MasterState) -> dict:
        updates: dict = {"phase": "recon", "round": 0}
        if not state.get("budget"):
            updates["budget"] = DispatchBudget(
                max_dispatches=cfg.max_dispatches,
                max_batch_width=cfg.max_batch_width,
                max_phases=cfg.max_phases,
            )
        return updates

    return _bootstrap_node


def _make_plan_node(planner: Any):
    def _plan_node(state: MasterState) -> dict:
        pending = list(state.get("pending") or [])
        if not pending and not _pending_verify(state):
            pending = propose_tasks(planner, state)
        parallel, deferred = partition_pending(pending)
        clamped = state["budget"].clamp_batch(parallel)
        overflow = parallel[len(clamped):]
        return {"pending": pending, "deferred": deferred + overflow, "phase": "dispatch"}

    return _plan_node


def _integrate_node(state: MasterState) -> dict:
    processed = len(state.get("history", []))
    new_results = state.get("dispatch_results", [])[processed:]
    records: list[DispatchRecord] = []
    for r in new_results:
        if "verify" in r.dispatch_id:
            kind: Literal["single", "batch", "verify_workflow"] = "verify_workflow"
        elif len(new_results) > 1:
            kind = "batch"
        else:
            kind = "single"
        records.append(
            DispatchRecord(
                dispatch_id=r.dispatch_id,
                kind=kind,
                task=r.summary or r.dispatch_id,
                result=r,
            )
        )
    next_hops = [h for r in new_results for h in r.next_hops]
    pending_next = list(state.get("deferred", [])) + next_hops
    return {
        "history": records,
        "pending": pending_next,
        "deferred": [],
        "round": state["round"] + 1,
        "phase": "integrate",
    }


def integrate_next(state: MasterState) -> Literal["continue", "done"]:
    """Loop for another phase while there is work and budget; otherwise report."""
    budget = state["budget"]
    if budget.exhausted or state["round"] >= budget.max_phases:
        return "done"
    if state.get("pending") or _pending_verify(state):
        return "continue"
    return "done"


def _report_node(state: MasterState) -> dict:
    """Terminal marker; ``runtime.build_report`` promotes the verified findings and
    exports the per-workspace HAR from the final state."""
    return {"phase": "report"}


def build_master_graph(
    cfg: A2pwnConfig,
    subgraph: CompiledStateGraph,
    client: BurpwnClient,
    checkpointer: BaseCheckpointSaver,
) -> CompiledStateGraph:
    """Compile the master graph, threading the child subgraph via ``run_subagent``.

    The child is reached ONLY through the plain ``run_subagent`` node — it is never
    ``add_node``-ed as a compiled subgraph, so no transcript channel is ever shared.
    ``interrupt_before=['run_subagent']`` unless the engagement pre-authorises active
    exploitation, so a human approves each dispatch.
    """
    global SUBAGENT_GRAPH
    SUBAGENT_GRAPH = subgraph

    planner = make_model(cfg.models.master)

    builder = StateGraph(MasterState)
    builder.add_node("bootstrap", _make_bootstrap(cfg))
    builder.add_node("plan", _make_plan_node(planner))
    builder.add_node("run_subagent", run_subagent)
    builder.add_node("integrate", _integrate_node)
    builder.add_node("report", _report_node)

    builder.add_edge(START, "bootstrap")
    builder.add_edge("bootstrap", "plan")
    builder.add_conditional_edges("plan", route_dispatch, ["run_subagent", "report"])
    builder.add_edge("run_subagent", "integrate")
    builder.add_conditional_edges(
        "integrate", integrate_next, {"continue": "plan", "done": "report"}
    )
    builder.add_edge("report", END)

    interrupt_before = [] if cfg.engagement.active_exploit_allowed else ["run_subagent"]
    return builder.compile(checkpointer=checkpointer, interrupt_before=interrupt_before)
