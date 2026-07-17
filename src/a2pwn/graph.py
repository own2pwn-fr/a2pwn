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

import logging
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
from a2pwn import progress
from a2pwn.agents import (
    MasterFork,
    build_clarifier,
    build_continuation_judge,
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
from a2pwn.oracles import VerificationOracle, run_oracle

# The compiled child subgraph, threaded in by ``build_master_graph``. ``run_subagent``
# references it here so the master graph never wires it as a node (clean-history guard).
SUBAGENT_GRAPH: CompiledStateGraph | None = None

_log = logging.getLogger("a2pwn")


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


def _merge_attempts(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    """Sum independent-verify attempt counts per finding key (parallel-Send safe)."""
    out: dict[str, int] = dict(left or {})
    for key, n in (right or {}).items():
        out[key] = out.get(key, 0) + n
    return out


def _spent(state: MasterState) -> int:
    """Total dispatch spend so far (the ``spent`` channel accumulates per-dispatch +1 deltas)."""
    return int(state.get("spent", 0) or 0)


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
    # finding.key -> count of independent-verify dispatches spent on it (capped drain).
    verify_attempts: Annotated[dict[str, int], _merge_attempts]
    phase: str
    round: int
    # How many times the continuation judge re-opened the engagement after a natural "done" (capped).
    continuations: int
    # CAPS live here (overwrite channel — seeded once, never carrying accumulated spend), while the
    # accumulating dispatch spend lives in ``spent`` (an ``operator.add`` int). Keeping them apart
    # stops the parallel-Send reducer from ever overwriting the caps with a delta's default caps.
    budget: DispatchBudget
    spent: Annotated[int, operator.add]


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
    """Confirmed findings still owed an independent-verify dispatch.

    Drops (a) findings already promoted to independently-verified, (b) duplicates, and
    (c) findings whose independent-verify attempts hit ``budget.max_verify_attempts`` — a
    persistently-unverifiable candidate stops being re-dispatched every phase and is kept
    confirmed-only, instead of thrashing the queue until the phase/budget cap.
    """
    promoted = _promoted_keys(state)
    attempts = state.get("verify_attempts", {}) or {}
    budget = state.get("budget")
    cap = budget.max_verify_attempts if budget is not None else 2
    seen: set[str] = set()
    out: list[Finding] = []
    for f in state.get("verify_queue", []):
        if f.key in promoted or f.key in seen or attempts.get(f.key, 0) >= cap:
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
        # Clamp the verify fan-out to the batch width AND the remaining hard budget, exactly like
        # the task branch below. Without this a full verify queue emits one Send per finding (30
        # findings -> 30 concurrent Opus sub-agents + burpwn traffic) regardless of max_batch_width,
        # blowing past the phase/spend caps the run is supposed to enforce. The overflow stays in
        # verify_queue and is picked up next phase (verify is prioritised, so it drains first).
        clamped = state["budget"].clamp(to_verify, _spent(state))
        inputs = [
            SubAgentInput(
                dispatch_id=f"{state['round']}-verify-{i}",
                intent="verify",
                candidate=f,
                master_ctx=ctx,
            )
            for i, f in enumerate(clamped)
        ]
        return "verify", inputs, []

    parallel, deferred = partition_pending(state.get("pending", []))
    clamped = state["budget"].clamp(parallel, _spent(state))
    overflow = parallel[len(clamped) :]
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

    Guard first: a TaskStop (``STOP`` event set by SIGINT), an exhausted budget (spend cap
    or ``stopped`` flag) or hitting the phase cap routes straight to the report. Otherwise
    emit one ``Send`` per selected invocation; an empty selection also ends the run.
    """
    budget = state["budget"]
    if budget.is_exhausted(_spent(state)) or state["round"] >= budget.max_phases:
        return "report"
    _mode, inputs, _deferred = _select_dispatch(state)
    if not inputs:
        return "report"
    return [Send("run_subagent", inp) for inp in inputs]


# --------------------------------------------------------------------------- #
# fork boundary
# --------------------------------------------------------------------------- #
async def run_subagent(payload: SubAgentInput) -> dict:
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
    # A verify dispatch counts as one independent-verify attempt for its candidate key even when
    # it fails/errors, so a persistently-unverifiable finding drains from the queue (capped).
    attempt_key = (
        payload.candidate.key if payload.intent == "verify" and payload.candidate is not None else None
    )
    attempts = {attempt_key: 1} if attempt_key else {}
    _label = payload.spec.task if payload.spec else (payload.candidate.key if payload.candidate else "verify")
    progress.emit("dispatch_start", id=payload.dispatch_id, intent=payload.intent, task=_label)
    _tok = progress.set_dispatch(payload.dispatch_id)
    try:
        out = await sub.ainvoke(
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
    except Exception as exc:  # noqa: BLE001 - isolate a failing child: degrade, never abort the batch
        _log.warning(
            "sub-agent dispatch %s failed, degrading to a blocked result: %s",
            payload.dispatch_id,
            exc,
            exc_info=True,
        )
        progress.reset_dispatch(_tok)
        progress.emit("dispatch_end", id=payload.dispatch_id, status="blocked", n_findings=0)
        clean = CleanResult(
            dispatch_id=payload.dispatch_id,
            status="blocked",
            summary=f"dispatch error: {exc}",
        )
        return {
            "dispatch_results": [clean],
            "findings": [],
            "verify_queue": [],
            "verify_attempts": attempts,
            "spent": 1,
        }
    progress.reset_dispatch(_tok)
    clean = out["clean_result"].model_copy(update={"dispatch_id": payload.dispatch_id})
    confirmed = [f for f in clean.findings if f.confirmed]
    progress.emit("dispatch_end", id=payload.dispatch_id, status=clean.status, n_findings=len(confirmed))
    verify_q = [f for f in confirmed if not f.independently_verified] if payload.intent == "task" else []
    return {
        "dispatch_results": [clean],
        "findings": confirmed,
        "verify_queue": verify_q,
        "verify_attempts": attempts,
        "spent": 1,
    }


# --------------------------------------------------------------------------- #
# subagent nodes
# --------------------------------------------------------------------------- #
# Tools that generate real, potentially-destructive network traffic. The deterministic block lives
# in the tool wrappers (BURPWN scope/active guard); this set drives the executor prompt disclosure
# and any tagging, and is keyed on an ``is_active``/``destructive`` marker with a name fallback for
# the concrete tool names (the old ``exploit_*`` prefix matched nothing).
_ACTIVE_TOOL_NAMES = frozenset(
    {"burpwn_exec", "burpwn_fuzz", "burpwn_req_replay", "burpwn_intercept_forward"}
)


def _is_active_tool(t: Any) -> bool:
    if getattr(t, "is_active", False) or getattr(t, "destructive", False):
        return True
    meta = getattr(t, "metadata", None)
    if isinstance(meta, dict) and (meta.get("active") or meta.get("destructive")):
        return True
    return getattr(t, "name", "") in _ACTIVE_TOOL_NAMES


def _active_tools(cfg: A2pwnConfig, tools: list) -> list[str]:
    """Names of active-exploitation tools to gate when the engagement did not pre-authorise them."""
    if cfg.engagement.active_exploit_allowed:
        return []
    return [t.name for t in tools if _is_active_tool(t)]


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


async def _invoke_agent(agent: Any, prompt: str) -> dict:
    # Async invocation: the ReAct executor's tools (burpwn/oracle/skill) are async-only,
    # so the whole sub-agent graph must run async or ToolNode raises on sync invocation.
    result = await agent.ainvoke({"messages": [HumanMessage(content=prompt)]})
    return result if isinstance(result, dict) else {"messages": []}


def _last_text(result: dict) -> str:
    messages = result.get("messages", []) if isinstance(result, dict) else []
    if not messages:
        return ""
    content = getattr(messages[-1], "content", "")
    return content if isinstance(content, str) else str(content)


async def _verifier_notes(verifier: Any, rejected: list[Finding], not_done: list[str]) -> str:
    """Best-effort adversarial narrative from the independent verifier role-model.

    The deterministic oracle already decided accept/reject; this only enriches the
    critique text and is skipped whenever the verifier cannot be cheaply invoked."""
    if getattr(verifier, "ainvoke", None) is None or (not rejected and not not_done):
        return ""
    prompt = (
        "As the independent adversarial verifier, summarise why these candidates were "
        "not proven and what the executor must still demonstrate:\n"
        + "\n".join(f"- {c.key}" for c in rejected)
        + "\n".join(f"- {g}" for g in not_done)
    )
    try:
        return _last_text(await _invoke_agent(verifier, prompt))
    except Exception:  # noqa: BLE001 - narrative enrichment is best-effort
        return ""


def build_subagent_graph(
    cfg: A2pwnConfig,
    client: BurpwnClient,
    fork: MasterFork,
    tools: list,
    collab: Any,
    skills: list | None = None,
) -> CompiledStateGraph:
    """Compile the stateless sub-agent subgraph (``checkpointer=False`` HARD)."""
    clarifier = build_clarifier(cfg.models)
    executor = build_executor(
        cfg.models,
        tools,
        _active_tools(cfg, tools),
        cfg.compaction_token_threshold,
        client=client,
        collab=collab,
        skills=skills,
    )
    verifier = build_verifier(cfg.models, tools, cfg.compaction_token_threshold)
    fbm = FlowBatchManager(client)

    def _clarify(state: SubAgentState) -> dict:
        return {"clarify_round": state.get("clarify_round", 0) + 1}

    async def _clarify_edge(state: SubAgentState) -> list[Send] | str:
        # Short-circuit: once the round cap is exhausted the clarifier's answer is discarded
        # anyway, so skip the wasted LLM call and compose the prompt directly.
        if state.get("clarify_round", 0) > cfg.max_clarify_rounds:
            return "compose_prompt"
        # A clarifier hiccup (a bare "[]" the structured parser rejects, a transient SDK error)
        # must NOT waste the whole dispatch — degrade to "no questions" and go straight to
        # exploitation. Clarification is an optional refinement, never a gate.
        try:
            questions = await clarifier.ainvoke(_clarify_ctx(state))
        except Exception as exc:  # noqa: BLE001 - optional refinement; proceed on any failure
            _log.info("clarifier failed, proceeding self-contained: %s", exc)
            return "compose_prompt"
        aug = {
            "questions": list(questions or []),
            "clarify_round": state.get("clarify_round", 0),
            "master_ctx": state["master_ctx"],
            "_max_clarify": cfg.max_clarify_rounds,
        }
        return need_clarify(aug)

    async def _answer_one(payload: dict) -> dict:
        qa = await fork.answer(payload["question"], payload["ctx"])
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
            lines.append("CLARIFICATIONS:\n" + "\n".join(f"Q: {p.question}\nA: {p.answer}" for p in qas))
        lines.append("IN-SCOPE TARGETS:\n" + ", ".join(state["master_ctx"].engagement.targets))
        return {"refined_prompt": "\n\n".join(lines)}

    async def _execute(state: SubAgentState) -> dict:
        prompt = state.get("refined_prompt") or state["master_ctx"].objective
        critique = state.get("critique")
        if critique is not None and not critique.accepted:
            gaps = "\n".join(f"- {g}" for g in critique.not_done)
            prompt += (
                "\n\nVERIFIER REJECTED THE PRIOR ATTEMPT. Address every gap and gather"
                f" real captured evidence:\n{critique.notes}\n{gaps}"
            )
        progress.emit("activity", stage="exploit", text="executing")
        result = await _invoke_agent(executor, prompt)
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

    def _oracle_inputs(candidate: Finding) -> tuple[VerificationOracle, dict]:
        """Build the finding's real oracle spec + live ctx for the deterministic adjudicator."""
        fids = candidate.flow_batch.flow_ids
        key_flow = candidate.flow_batch.key_flow
        expect = dict(candidate.oracle_expect or {})
        spec = VerificationOracle(
            kind=candidate.oracle_kind,
            signals=list(candidate.oracle_signals),
            correlation_id=candidate.correlation_id,
            expect=expect,
        )
        ctx = {
            "client": client,
            "collaborator": collab,
            "collab": collab,
            "flow_id": key_flow if key_flow is not None else (fids[0] if fids else None),
            "flow_a": fids[0] if len(fids) >= 1 else None,
            "flow_b": fids[1] if len(fids) >= 2 else None,
            "a_ref": fids[0] if len(fids) >= 1 else None,
            "b_ref": fids[1] if len(fids) >= 2 else None,
            # third evidence flow = the negative control (anon/unauthorised) for two_identity,
            # or an explicit before/after pair for the state_change semantic oracle.
            "c_ref": fids[2] if len(fids) >= 3 else None,
            "before_ref": fids[0] if len(fids) >= 1 else None,
            "after_ref": fids[1] if len(fids) >= 2 else None,
            "attack_id": expect.get("attack_id"),
            "threshold_ms": expect.get("threshold_ms", 5000),
            "correlation_id": candidate.correlation_id,
        }
        return spec, ctx

    async def _adjudicate(candidate: Finding) -> tuple[bool, str]:
        """FAIL-CLOSED adjudication. Confirm ONLY when the capture is provably real AND the
        finding's own deterministic oracle re-derives it. A missing/unmapped kind, an oracle
        error, or a ``None`` verdict all REJECT with a reason — never swallowed to a pass."""
        batch = candidate.flow_batch
        if not batch.flow_ids:
            return False, f"REJECT {candidate.key}: empty flow batch — capture alarm"
        ok, reason = await fbm.assert_capture(batch, batch.exec_ids)
        if not ok:
            return False, reason
        if await fbm.tls_passthru_blocked(batch):
            return False, f"BLOCKED {candidate.key}: tls-passthru target — MITM blocked, not testable"
        spec, ctx = _oracle_inputs(candidate)
        try:
            res = await run_oracle(spec, ctx)
        except Exception as exc:  # noqa: BLE001 - fail-closed: any oracle error REJECTS
            return False, f"REJECT {candidate.key}: oracle {candidate.oracle_kind} errored ({exc})"
        if res is None:  # defensive; run_oracle's contract is to never return None
            return False, f"REJECT {candidate.key}: oracle {candidate.oracle_kind} returned no verdict"
        if not res.confirmed:
            return (
                False,
                f"REJECT {candidate.key}: oracle {candidate.oracle_kind} did not re-derive ({res.evidence})",
            )
        return True, ""

    async def _verify(state: SubAgentState) -> dict:
        round_ = state.get("verify_round", 0) + 1
        candidates = state.get("candidate_findings", [])
        confirmed: list[Finding] = []
        rejected: list[Finding] = []
        not_done: list[str] = []
        capture_ok = True
        if candidates:
            progress.emit("activity", stage="verify", text=f"adjudicating {len(candidates)} candidate(s)")
        for c in candidates:
            ok, reason = await _adjudicate(c)
            if ok:
                confirmed.append(c.model_copy(update={"confirmed": True}))
                progress.emit(
                    "finding",
                    status="confirmed",
                    vuln_class=c.vuln_class,
                    severity=c.severity,
                    target=c.target,
                )
            else:
                rejected.append(c)
                not_done.append(reason)
                progress.emit(
                    "finding",
                    status="rejected",
                    vuln_class=c.vuln_class,
                    severity=c.severity,
                    target=c.target,
                )
                if "ALARM" in reason or "capture" in reason.lower():
                    capture_ok = False
        accepted = not rejected
        notes = f"verified {len(confirmed)}/{len(candidates)} candidate(s); round {round_}"
        if rejected:
            adversarial = await _verifier_notes(verifier, rejected, not_done)
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

        blocked = bool(critique is not None and any("BLOCKED" in g for g in critique.not_done))
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
        summary = critique.notes if critique is not None else f"{status}: {len(findings)} finding(s)"
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


async def propose_tasks(planner: Any, state: MasterState) -> list[TaskSpec]:
    """Ask the master planner for fresh TaskSpecs. Degrades to ``[]`` on any error so a
    missing/offline model ends the run cleanly instead of hanging.

    Async so the whole engagement runs on the single ``astream``-owned loop — no
    ``asyncio.run``-per-call touching the long-lived client from a worker thread."""
    try:
        ctx = {
            "objective": state["objective"],
            "engagement": state["engagement"],
            "history": state["history"][-8:],
            "findings": state.get("findings", []),
        }
        messages = P.render_messages(P.MASTER_PLAN_SYS, ctx)
        out = await planner.with_structured_output(_PlanOut).ainvoke(messages)
        tasks = list(out.tasks)
        if not tasks:
            _log.warning("planner returned no tasks (empty structured output)")
        return tasks
    except Exception as exc:
        _log.warning("planner failed, ending run cleanly: %s", exc, exc_info=True)
        return []


def _make_bootstrap(cfg: A2pwnConfig):
    def _bootstrap_node(state: MasterState) -> dict:
        # Seed verify_attempts/spent so their reducer channels initialise even when the runner's
        # stream input omits them. Set the budget CAPS authoritatively from cfg here — the caps live
        # in this overwrite channel and are never derived from a dispatch delta, so max_dispatches /
        # max_phases are actually enforced (a per-dispatch delta only bumps the separate ``spent``).
        return {
            "phase": "recon",
            "round": 0,
            "verify_attempts": {},
            "continuations": 0,
            "spent": 0,
            "budget": DispatchBudget(
                max_dispatches=cfg.max_dispatches,
                max_batch_width=cfg.max_batch_width,
                max_phases=cfg.max_phases,
                max_verify_attempts=cfg.max_verify_rounds,
            ),
        }

    return _bootstrap_node


def _make_plan_node(planner: Any):
    async def _plan_node(state: MasterState) -> dict:
        b = state["budget"]
        progress.emit(
            "phase", phase="plan", round=state.get("round", 0), spent=_spent(state), max=b.max_dispatches
        )
        pending = list(state.get("pending") or [])
        if not pending and not _pending_verify(state):
            pending = await propose_tasks(planner, state)
        parallel, deferred = partition_pending(pending)
        clamped = state["budget"].clamp(parallel, _spent(state))
        overflow = parallel[len(clamped) :]
        return {"pending": pending, "deferred": deferred + overflow, "phase": "dispatch"}

    return _plan_node


async def _integrate_node(state: MasterState) -> dict:
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


def integrate_next(state: MasterState) -> Literal["continue", "judge", "done"]:
    """Loop for another phase while there is work and budget; otherwise consult the
    continuation judge before stopping.

    A TaskStop (``STOP`` set by SIGINT) or an exhausted/phase-capped budget ends the run
    immediately (``done``, a hard stop — the judge never overrides those). When there is
    still queued work, ``continue``. When the planner produced NO more work (the natural
    "here is what I did; want me to continue?" moment), route to ``judge`` to decide
    autonomously whether the engagement is genuinely complete."""
    budget = state["budget"]
    if budget.is_exhausted(_spent(state)) or state["round"] >= budget.max_phases:
        return "done"
    if state.get("pending") or _pending_verify(state):
        return "continue"
    return "judge"


def _make_judge_node(judge: Any, cfg: A2pwnConfig):
    """Continuation judge: invoked when the master would naturally STOP. Decides whether the
    engagement is complete or should push further, and (if so, and under the cap/budget) injects
    concrete follow-up tasks so the run continues instead of ending prematurely."""

    async def _judge_node(state: MasterState) -> dict:
        used = state.get("continuations", 0)
        # Respect the hard cap and budget: never re-open past the limit or when spent.
        if used >= cfg.max_continuations or state["budget"].is_exhausted(_spent(state)):
            _log.info("continuation judge skipped (cap/budget/stop); finalising")
            return {"pending": [], "phase": "complete"}
        ctx = {
            "objective": state["objective"],
            "engagement": state["engagement"],
            "in_scope": state["engagement"].in_scope or state["engagement"].targets,
            "history": state.get("history", []),
            "findings": state.get("findings", []),
        }
        try:
            verdict = await judge.ainvoke(ctx)
        except Exception as exc:  # noqa: BLE001 - a judge failure must not hang the run
            _log.warning("continuation judge failed, finalising: %s", exc)
            return {"pending": [], "phase": "complete"}
        remaining = list(getattr(verdict, "remaining_work", []) or [])
        if getattr(verdict, "complete", True) or not remaining:
            _log.info("continuation judge: engagement complete — %s", getattr(verdict, "rationale", ""))
            return {"pending": [], "phase": "complete"}
        _log.info(
            "continuation judge: NOT complete (round %d/%d) — re-opening with %d task(s): %s",
            used + 1,
            cfg.max_continuations,
            len(remaining),
            getattr(verdict, "rationale", ""),
        )
        return {"pending": remaining, "continuations": used + 1, "phase": "continuation"}

    return _judge_node


def judge_route(state: MasterState) -> Literal["plan", "report"]:
    """Continue planning if the judge injected follow-up work; otherwise report."""
    return "plan" if state.get("pending") else "report"


async def _report_node(state: MasterState) -> dict:
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
    judge = build_continuation_judge(cfg.models)

    builder = StateGraph(MasterState)
    builder.add_node("bootstrap", _make_bootstrap(cfg))
    builder.add_node("plan", _make_plan_node(planner))
    builder.add_node("run_subagent", run_subagent)
    builder.add_node("integrate", _integrate_node)
    builder.add_node("judge", _make_judge_node(judge, cfg))
    builder.add_node("report", _report_node)

    builder.add_edge(START, "bootstrap")
    builder.add_edge("bootstrap", "plan")
    builder.add_conditional_edges("plan", route_dispatch, ["run_subagent", "report"])
    builder.add_edge("run_subagent", "integrate")
    builder.add_conditional_edges(
        "integrate", integrate_next, {"continue": "plan", "judge": "judge", "done": "report"}
    )
    builder.add_conditional_edges("judge", judge_route, {"plan": "plan", "report": "report"})
    builder.add_edge("report", END)

    interrupt_before = [] if cfg.engagement.active_exploit_allowed else ["run_subagent"]
    return builder.compile(checkpointer=checkpointer, interrupt_before=interrupt_before)
