"""The MASTER state machine, its reducers, the dispatch router, and the fork boundary.

The MASTER graph reasons over a *curated* append-only history and dispatches work to a stateless
SUB-AGENT subgraph, which lives in :mod:`a2pwn.subgraph` (it owns the chatty ``messages`` /
``clarifications`` channels and everything that dies with one dispatch). The two halves used to
share this file; the split is along the fork boundary itself.

That subgraph is compiled ``checkpointer=False`` so its transcript is garbage-collected the instant
``SUBAGENT_GRAPH.ainvoke`` returns, and it is reached ONLY through the plain function
:func:`run_subagent`, never via ``add_node(compiled_subgraph)``. This is the
clean-history-by-construction mandate: there is physically no parent channel a transcript could leak
into. Do NOT wire the subgraph in as a node, and do NOT add a messages channel to
:class:`MasterState`.

For backwards compatibility (and because they read as one design), the sub-agent names are
re-exported here, so ``from a2pwn.graph import build_subagent_graph`` keeps working.
"""

from __future__ import annotations

import logging
import operator
from typing import Annotated, Any, Literal, TypedDict

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Send
from pydantic import BaseModel, Field

import a2pwn.prompts as P
from a2pwn import progress
from a2pwn.agents import build_continuation_judge, freeze_context
from a2pwn.backends import make_model
from a2pwn.budget import DispatchBudget
from a2pwn.burpwn import BurpwnClient
from a2pwn.config import A2pwnConfig
from a2pwn.models import (
    CleanResult,
    DispatchRecord,
    EngagementSpec,
    Finding,
    SubAgentInput,
    TaskSpec,
)
from a2pwn.scope import host_of, is_apex_host
from a2pwn.subgraph import SubAgentState, build_subagent_graph, need_clarify, verify_gate

__all__ = [
    "SUBAGENT_GRAPH",
    "MasterState",
    "SubAgentState",
    "build_master_graph",
    "build_subagent_graph",
    "integrate_next",
    "judge_route",
    "merge_findings",
    "need_clarify",
    "partition_pending",
    "propose_tasks",
    "route_dispatch",
    "run_subagent",
    "seed_recon_tasks",
    "verify_gate",
]

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


def _spent_usd(state: MasterState) -> float:
    """Real dollars spent so far (accumulated from each dispatch's reported model cost)."""
    return float(state.get("spent_usd", 0.0) or 0.0)


def _spent_tokens(state: MasterState) -> int:
    """Real tokens spent so far (accumulated from each dispatch's reported usage)."""
    return int(state.get("spent_tokens", 0) or 0)


def _exhausted(state: MasterState) -> bool:
    """Any hard stop: TaskStop, the dispatch cap, or a real cost/token ceiling."""
    return state["budget"].is_exhausted(_spent(state), _spent_usd(state), _spent_tokens(state))


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
    # Real spend, accumulated exactly like ``spent`` and for the same reducer-safety reason: the
    # caps live on the overwrite-channel ``budget``, the accumulating totals live here, so a
    # parallel-Send delta can never clobber a cap with its default.
    spent_usd: Annotated[float, operator.add]
    spent_tokens: Annotated[int, operator.add]


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
    if _exhausted(state) or state["round"] >= budget.max_phases:
        reason = budget.overspend_reason(_spent(state), _spent_usd(state), _spent_tokens(state))
        if reason:
            _log.info("routing to report: %s", reason)
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
                "discovered_hosts": [],
                "critique": None,
                "verify_round": 0,
                "clarify_round": 0,
                "cost_usd": 0.0,
                "tokens": 0,
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
            "spent_usd": 0.0,
            "spent_tokens": 0,
        }
    progress.reset_dispatch(_tok)
    clean = out["clean_result"].model_copy(update={"dispatch_id": payload.dispatch_id})
    confirmed = [f for f in clean.findings if f.confirmed]
    progress.emit(
        "dispatch_end",
        id=payload.dispatch_id,
        status=clean.status,
        n_findings=len(confirmed),
        cost_usd=clean.cost_usd,
        tokens=clean.tokens,
    )
    verify_q = [f for f in confirmed if not f.independently_verified] if payload.intent == "task" else []
    return {
        "dispatch_results": [clean],
        "findings": confirmed,
        "verify_queue": verify_q,
        "verify_attempts": attempts,
        "spent": 1,
        "spent_usd": float(clean.cost_usd or 0.0),
        "spent_tokens": int(clean.tokens or 0),
    }


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


def seed_recon_tasks(engagement: EngagementSpec) -> list[TaskSpec]:
    """One deterministic subdomain-enumeration recon task per apex-shaped target host, seeded
    BEFORE the planner's first LLM call.

    Without this, the master only ever sees whatever single hostname the operator typed and has to
    discover the real asset surface piecemeal, phase by phase, through its own LLM reasoning — this
    engagement's own live run against ``*.thinginthefuture.com`` needed the operator to manually
    enumerate subdomains via crt.sh/hackertarget outside a2pwn entirely. Seeding these into
    ``pending`` makes ``_plan_node`` skip its first planner call (pending is non-empty), so phase 0
    is pure deterministic recon; the executor is expected to call ``propose_targets`` for every
    genuinely live host it finds, which flows into ``next_hops`` exactly like a cross-chain
    follow-up — by the time the planner's LLM runs for the first time (phase 1), it already has
    concrete, discovered hosts queued instead of a single bare apex domain.
    """
    hosts: list[str] = []
    seen: set[str] = set()
    for token in engagement.in_scope or engagement.targets:
        host = host_of(token)
        if host and is_apex_host(host) and host not in seen:
            seen.add(host)
            hosts.append(host)
    return [
        TaskSpec(
            task=(
                f"Enumerate subdomains of {host} (subfinder), probe every candidate for "
                "liveness/tech with httpx, then call propose_targets once for each genuinely "
                "live, distinct host worth testing (skip parked/dead/CDN-only/duplicate entries). "
                "This is pure recon — do not attempt exploitation here."
            ),
            intent="recon",
            target=host,
            hints=["subdomain-enumeration", "seeded-before-first-planning-phase"],
        )
        for host in hosts
    ]


def _make_bootstrap(cfg: A2pwnConfig):
    def _bootstrap_node(state: MasterState) -> dict:
        # Seed verify_attempts/spent so their reducer channels initialise even when the runner's
        # stream input omits them. Set the budget CAPS authoritatively from cfg here — the caps live
        # in this overwrite channel and are never derived from a dispatch delta, so max_dispatches /
        # max_phases are actually enforced (a per-dispatch delta only bumps the separate ``spent``).
        # ``pending`` is a plain (overwrite) channel: only inject the recon seed when the caller
        # starts genuinely empty (the real CLI flow) — an explicitly pre-seeded pending list (tests,
        # or any programmatic caller driving the graph from a custom initial state) is left untouched
        # rather than clobbered.
        existing_pending = state.get("pending") or []
        return {
            "phase": "recon",
            "round": 0,
            "verify_attempts": {},
            "continuations": 0,
            "spent": 0,
            "spent_usd": 0.0,
            "spent_tokens": 0,
            "pending": existing_pending or seed_recon_tasks(cfg.engagement),
            "budget": DispatchBudget(
                max_dispatches=cfg.max_dispatches,
                max_batch_width=cfg.max_batch_width,
                max_phases=cfg.max_phases,
                max_verify_attempts=cfg.max_verify_rounds,
                max_usd=cfg.max_usd,
                max_tokens=cfg.max_tokens,
            ),
        }

    return _bootstrap_node


def _make_plan_node(planner: Any):
    async def _plan_node(state: MasterState) -> dict:
        b = state["budget"]
        progress.emit(
            "phase",
            phase="plan",
            round=state.get("round", 0),
            spent=_spent(state),
            max=b.max_dispatches,
            max_phases=b.max_phases,
        )
        pending = list(state.get("pending") or [])
        if not pending and not _pending_verify(state):
            pending = await propose_tasks(planner, state)
        parallel, deferred = partition_pending(pending)
        clamped = state["budget"].clamp(parallel, _spent(state))
        overflow = parallel[len(clamped) :]
        return {"pending": pending, "deferred": deferred + overflow, "phase": "dispatch"}

    return _plan_node


def task_signature(spec: TaskSpec) -> tuple[str, str, str]:
    """Identity of a unit of work, for queue bookkeeping and repeat suppression.

    Deliberately coarse — intent + target + the task text, case- and whitespace-normalised. Two
    dispatches that differ only in prose phrasing are the same work, and re-running them burns
    budget that the untested surface needs.
    """
    return (spec.intent, (spec.target or "").strip().lower(), " ".join(spec.task.lower().split()))


def _drop_answered(pending: list[TaskSpec], answered: list[TaskSpec]) -> list[TaskSpec]:
    """Remove one queue entry per returned dispatch, preserving duplicates that were not run."""
    remaining = list(pending)
    for spec in answered:
        sig = task_signature(spec)
        for i, queued in enumerate(remaining):
            if task_signature(queued) == sig:
                remaining.pop(i)
                break
    return remaining


def _drop_already_dispatched(pending: list[TaskSpec], history: list[DispatchRecord]) -> list[TaskSpec]:
    """Suppress re-queued work that a prior dispatch already carried out.

    `next_hops` (cross-chain edges, `propose_targets` discoveries) and the continuation judge all
    append straight into the queue with no memory of each other, so a host discovered twice, or a
    chain edge re-emitted every time its origin finding is re-confirmed, used to be dispatched again
    and again. Nothing in the code prevented it — the only guard was an English sentence in the
    planner prompt.
    """
    seen = {task_signature(rec.result.spec) for rec in history if rec.result.spec is not None}
    out: list[TaskSpec] = []
    for spec in pending:
        sig = task_signature(spec)
        if sig in seen:
            _log.info("dropping already-dispatched task: %s", spec.task)
            continue
        seen.add(sig)
        out.append(spec)
    return out


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
                # The REQUESTED task, not the result summary. History that only records outcomes
                # cannot answer "what did we ask for and never get", which is precisely the
                # question the continuation judge is asked to answer.
                task=(r.spec.task if r.spec else None) or r.summary or r.dispatch_id,
                result=r,
            )
        )
    next_hops = [h for r in new_results for h in r.next_hops]
    # A phase dispatches at most `max_batch_width` tasks, and a phase with anything in the verify
    # queue dispatches verifies ONLY. Rebuilding the queue as `deferred + next_hops` therefore threw
    # away every task that was planned but not reached this phase — silently, so a run looked
    # complete while whole planned tasks had simply evaporated. Carry the unanswered remainder.
    answered = [r.spec for r in new_results if r.spec is not None]
    leftover = _drop_answered(list(state.get("pending", [])), answered)
    pending_next = leftover + list(state.get("deferred", [])) + next_hops
    pending_next = _drop_already_dispatched(pending_next, state.get("history", []) + records)
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
    if _exhausted(state) or state["round"] >= budget.max_phases:
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
        if used >= cfg.max_continuations or _exhausted(state):
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
