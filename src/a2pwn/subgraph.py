"""The stateless SUB-AGENT subgraph: its state, nodes, and the fail-closed adjudicator.

Split out of :mod:`a2pwn.graph`, which had grown to carry both state machines plus every router and
node in one file. The boundary is the natural one: this module owns everything that lives and dies
inside one dispatch (clarify Q&A, the ReAct transcript, the verifier critique and its retries),
while ``graph`` owns the curated master state and the fork boundary that invokes this graph.

The compiled graph here is ``checkpointer=False`` HARD. That is the clean-history-by-construction
mandate: the child's transcript is garbage-collected the instant ``ainvoke`` returns, and the graph
is reached ONLY through the plain function ``graph.run_subagent`` — never via
``add_node(compiled_subgraph)`` — so there is physically no parent channel a transcript could leak
into. Do not wire it in as a node, and do not add a messages channel to ``MasterState``.

This file is part of a2pwn and is distributed under the GNU Affero General Public License v3.0
or later; see the repository ``LICENSE`` for the full text.
"""

from __future__ import annotations

import logging
import operator
import re
from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Send

from a2pwn import progress
from a2pwn.agents import MasterFork, build_clarifier, build_executor, build_verifier
from a2pwn.burpwn import BurpwnClient, FlowBatchManager
from a2pwn.config import A2pwnConfig
from a2pwn.coverage import Probe
from a2pwn.models import (
    CleanResult,
    Finding,
    FlowBatchRef,
    MasterContextView,
    QAPair,
    TaskSpec,
    VerifierReport,
)
from a2pwn.oracles import VerificationOracle, run_oracle
from a2pwn.toolcore import ACTIVE_TOOL_NAMES

_log = logging.getLogger("a2pwn")


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #


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
    # Recon-proposed follow-up targets (via the propose_targets tool) — mirrors candidate_findings'
    # merge-by-key accumulation, but keyed by target since a TaskSpec has no natural finding-style key.
    discovered_hosts: list[TaskSpec]
    # Coverage declarations (via record_probe) — what this dispatch TESTED, including every class
    # it cleared. Keyed by (asset, class) so a retry round restates rather than duplicates a cell.
    probes: list[Probe]
    critique: VerifierReport | None
    verify_round: int
    clarify_round: int
    # Real model spend, accumulated across every execute round of this dispatch (a verify-retry
    # round costs real money too, so summing is the only honest total).
    cost_usd: Annotated[float, operator.add]
    tokens: Annotated[int, operator.add]
    clean_result: CleanResult


# --------------------------------------------------------------------------- #
# subagent nodes
# --------------------------------------------------------------------------- #
# Tools that generate real, potentially-destructive network traffic. The deterministic block lives
# in the tool wrappers (BURPWN scope/active guard); this set drives the executor prompt disclosure
# and any tagging, and is keyed on an ``is_active``/``destructive`` marker with a name fallback for
# the concrete tool names (the old ``exploit_*`` prefix matched nothing). Sourced from the shared
# tool definition so a newly-added active tool cannot be forgotten here.
_ACTIVE_TOOL_NAMES = ACTIVE_TOOL_NAMES


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


def _harvest(
    messages: list[BaseMessage],
) -> tuple[list[Finding], list[FlowBatchRef], list[TaskSpec], list[Probe]]:
    """Pull ``Finding`` / ``FlowBatchRef`` / ``TaskSpec`` / ``Probe`` artifacts out of a ReAct
    transcript.

    ``TaskSpec`` artifacts come from ``propose_targets`` (recon-discovered follow-up hosts) and
    ``Probe`` artifacts from ``record_probe`` (coverage declarations) — the LangChain path's only
    way to surface them, since (unlike the SDK path) its tool results aren't threaded back through
    a dedicated return field.
    """
    findings: list[Finding] = []
    batches: list[FlowBatchRef] = []
    discovered: list[TaskSpec] = []
    probes: list[Probe] = []
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
            elif isinstance(it, TaskSpec):
                discovered.append(it)
            elif isinstance(it, Probe):
                probes.append(it)
    return findings, batches, discovered, probes


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


_VETO_RE = re.compile(r"^\s*VETO\s+(?P<key>\S+)\s*:\s*(?P<reason>.+)$", re.M)


async def _adversarial_veto(verifier: Any, confirmed: list[Finding]) -> dict[str, str]:
    """Let the independent role-model REJECT an oracle-confirmed candidate. It can never accept one.

    The architecture always claimed a two-layer discipline — a deterministic oracle plus an
    adversarial verifier on a distinct, stronger model — but the verifier agent was only ever asked
    to narrate *existing* rejections. It had no say in any verdict. This gives it one, in the only
    direction that is safe: a veto can produce a false negative, never a false positive, so the
    fail-closed kernel stays fail-closed and the stronger model gets to catch what a mechanical
    oracle cannot (a "differential" that differs for an unrelated reason, an oracle re-derived
    against the attacker's own echoed request, a capture that proves the wrong thing).

    Fail-OPEN on any error or unparseable reply: the oracle already confirmed, so a flaky verifier
    call must not silently delete a proven finding. Vetoes must cite a reason, which is carried into
    residual gaps and `run.jsonl` so nothing disappears without a trace.
    """
    if getattr(verifier, "ainvoke", None) is None or not confirmed:
        return {}
    listing = "\n".join(
        f"- key={c.key} oracle={c.oracle_kind} target={c.target} param={c.param or '*'} "
        f"flows={c.flow_batch.flow_ids} evidence={c.evidence[:300]}"
        for c in confirmed
    )
    prompt = (
        "These candidates PASSED the deterministic oracle. Re-examine each one in the sandbox and "
        "try to REFUTE it. You cannot approve anything — silence means it stands. Emit one line per "
        "candidate you can actually refute, in exactly this form and nothing else:\n"
        "VETO <key>: <the concrete reason the oracle fired for something other than the claimed "
        "vulnerability>\n"
        "Refute only on evidence you verified yourself. A hunch is not a veto.\n\n" + listing
    )
    try:
        text = _last_text(await _invoke_agent(verifier, prompt))
    except Exception as exc:  # noqa: BLE001 - fail OPEN: never drop a proven finding on an error
        _log.warning("adversarial veto pass failed, keeping oracle verdicts: %s", exc)
        return {}
    keys = {c.key for c in confirmed}
    vetoes = {
        m.group("key"): m.group("reason").strip()
        for m in _VETO_RE.finditer(text or "")
        if m.group("key") in keys
    }
    if vetoes:
        _log.warning("adversarial verifier vetoed %d oracle-confirmed candidate(s)", len(vetoes))
    return vetoes


def _unmet_task_classes(spec: TaskSpec | None, probes: list[Probe]) -> list[str]:
    """Which classes the dispatch was ASKED to test but never recorded a verdict for.

    Coverage-expanded tasks name their classes in a `classes=` hint, so "was the work actually done"
    is answerable without an LLM: compare the ask against what `record_probe` and the oracle
    settled. This is the peer-review step the architecture was missing — until `CleanResult.spec`
    existed, the master could not compare a request against its result at all, because history only
    ever recorded outcomes.

    Reported as residual gaps, which the planner and the report both already read, rather than
    silently re-queued: the operator should be able to see that a dispatch was asked for eight
    classes and settled three.
    """
    if spec is None:
        return []
    asked: list[str] = []
    for hint in spec.hints:
        if hint.startswith("classes="):
            asked = [c.strip() for c in hint[len("classes=") :].split(",") if c.strip()]
    if not asked:
        return []
    settled = {p.vuln_class for p in probes}
    missed = [c for c in asked if c not in settled]
    if not missed:
        return []
    return [
        f"NOT DONE: dispatch was asked to test {', '.join(asked)} but recorded no verdict for "
        f"{', '.join(missed)}"
    ]


def _reproduces(candidate: Finding | None, confirmed: list[Finding]) -> bool:
    """Did an independent-verify dispatch actually re-derive THE candidate it was sent to check?

    Requiring merely "some candidate survived adjudication" would let a fresh child that stumbled
    onto an unrelated bug promote the one it was asked about. Match on the canonical key first, then
    fall back to (vuln_class, target) so a differently-normalised param does not read as a failure.
    """
    if candidate is None:
        return bool(confirmed)
    for f in confirmed:
        if f.key == candidate.key:
            return True
        if f.vuln_class == candidate.vuln_class and f.target == candidate.target:
            return True
    return False


def build_subagent_graph(
    cfg: A2pwnConfig,
    client: BurpwnClient,
    fork: MasterFork,
    tools: list,
    collab: Any,
    skills: list | None = None,
    identities: Any = None,
    throttle: Any = None,
    artifacts: Any = None,
    directives: Any = None,
    research: Any = None,
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
        max_turns=cfg.executor_max_turns,
        engagement=cfg.engagement,
        identities=identities,
        throttle=throttle,
        fuzz_cap=cfg.fuzz_max_requests,
        artifacts=artifacts,
        directives=directives,
        research=research,
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
        verify_round = state.get("verify_round", 0)
        if verify_round == 0:
            # First attempt: let a crash propagate as before (run_subagent degrades the whole
            # dispatch to "blocked") — there is no prior-round work to protect yet.
            result = await _invoke_agent(executor, prompt)
        else:
            try:
                result = await _invoke_agent(executor, prompt)
            except Exception as exc:  # noqa: BLE001 - a RETRY round crashing (e.g. max-turns with
                # zero new activity) must NOT propagate: the sub-agent graph has checkpointer=False,
                # so an uncaught exception here is caught by run_subagent's outer try/except and
                # degrades the ENTIRE dispatch to "blocked", discarding every already-confirmed
                # candidate from EARLIER rounds of this SAME dispatch — a real data-loss bug this
                # once masked (a multi-candidate task where only some candidates confirmed would
                # retry the still-rejected ones, and a crashed retry silently dropped the
                # already-proven findings too). Treat as "no new activity this round" instead:
                # state's candidate_findings (merged below) is untouched, so anything already
                # confirmed in a prior round survives to distill.
                _log.warning(
                    "executor invocation failed on verify round %s, keeping prior candidates: %s",
                    verify_round,
                    exc,
                )
                result = {}
        messages = list(result.get("messages", []))
        findings = list(result.get("candidate_findings", []))
        batches = list(result.get("flow_batches", []))
        discovered = list(result.get("discovered_hosts", []))
        probes = list(result.get("probes", []))
        if not findings or not discovered or not probes:
            harvested_findings, harvested_batches, harvested_hosts, harvested_probes = _harvest(messages)
            if not findings:
                findings = harvested_findings
                batches = batches or harvested_batches
            if not discovered:
                discovered = harvested_hosts
            if not probes:
                probes = harvested_probes
        merged: dict[str, Finding] = {f.key: f for f in state.get("candidate_findings", [])}
        for f in findings:
            merged[f.key] = f
        # discovered_hosts has no Finding-style key; dedupe by target (last-write-wins across rounds).
        merged_hosts: dict[str, TaskSpec] = {
            t.target: t for t in state.get("discovered_hosts", []) if t.target
        }
        for t in discovered:
            if t.target:
                merged_hosts[t.target] = t
        # Coverage cells dedupe by (asset, class); a later round's verdict wins, which is right —
        # a retry round is a better-informed statement about the same cell than the round before.
        merged_probes: dict[str, Probe] = {p.key: p for p in state.get("probes", [])}
        for probe in probes:
            merged_probes[probe.key] = probe
        return {
            "messages": messages,
            "candidate_findings": list(merged.values()),
            "flow_batches": batches,
            "discovered_hosts": list(merged_hosts.values()),
            "probes": list(merged_probes.values()),
            "cost_usd": float(result.get("cost_usd") or 0.0),
            "tokens": int(result.get("tokens") or 0),
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
                    param=c.param,
                )
            else:
                rejected.append(c)
                not_done.append(reason)
                # Only the TUI saw this via progress.emit — a --plain run had no way to tell WHY a
                # well-evidenced candidate never made it into the report. Log it at WARNING so the
                # reject reason (capture alarm, tls-passthru, or the oracle simply not re-deriving)
                # is visible without needing to reverse-engineer it from source + raw burpwn state.
                _log.warning("candidate %s REJECTED at adjudication: %s", c.key, reason)
                progress.emit(
                    "finding",
                    status="rejected",
                    vuln_class=c.vuln_class,
                    severity=c.severity,
                    target=c.target,
                    param=c.param,
                    # The reason is what makes a rejection actionable after the fact; it now reaches
                    # the durable run.jsonl, not just the ephemeral TUI.
                    reason=reason,
                    oracle_kind=c.oracle_kind,
                )
                if "ALARM" in reason or "capture" in reason.lower():
                    capture_ok = False
        # The second layer: an independent, stronger role-model gets to REFUTE what the mechanical
        # oracle accepted. Reject-only by construction, so this can never manufacture a finding.
        if confirmed:
            vetoes = await _adversarial_veto(verifier, confirmed)
            if vetoes:
                survived = []
                for c in confirmed:
                    reason = vetoes.get(c.key)
                    if reason is None:
                        survived.append(c)
                        continue
                    rejected.append(c)
                    not_done.append(f"VETOED {c.key}: {reason}")
                    _log.warning("candidate %s VETOED by the adversarial verifier: %s", c.key, reason)
                    progress.emit(
                        "finding",
                        status="rejected",
                        vuln_class=c.vuln_class,
                        severity=c.severity,
                        target=c.target,
                        param=c.param,
                        reason=f"adversarial veto: {reason}",
                        oracle_kind=c.oracle_kind,
                    )
                confirmed = survived

        accepted = not rejected
        if state["intent"] == "verify":
            # An INDEPENDENT-VERIFY dispatch must produce its OWN proof. `accepted = not rejected`
            # alone made "reported nothing" indistinguishable from "reproduced it": a child that
            # gave up, refused, ran out of turns, or crashed on a retry round (swallowed above)
            # yields zero candidates, hence zero rejections, hence accepted=True — and `_distill`
            # then promoted the ORIGINAL candidate to `independently_verified`. That is a hole
            # straight through the product's 0-FP guarantee: not proving became proving.
            accepted = accepted and _reproduces(state.get("candidate"), confirmed)
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
            # A typed edge states what leverage was obtained; hand that leverage to the next hop.
            # Without it the follow-up dispatch was told "A enables B" and started from an empty
            # transcript, with no access to the credential or host that made the chain a chain.
            typed = {e.to_key: e for e in f.chain_edges}
            for enabled in dict.fromkeys([*typed, *f.enables]):
                edge = typed.get(enabled)
                hints = [f"origin_finding={f.key}"]
                if edge is not None and edge.material:
                    task = (
                        f"Pursue cross-chain: {f.key} yielded {edge.kind} that should enable "
                        f"{enabled}. USE THIS MATERIAL, do not re-derive it: {edge.material}"
                    )
                    if edge.note:
                        task += f" ({edge.note})"
                    hints += [f"chain_kind={edge.kind}", f"chain_material={edge.material}"]
                else:
                    task = f"Pursue cross-chain: {f.key} enables {enabled}."
                next_hops.append(
                    TaskSpec(task=task, intent="chain", target=f.target, hints=hints)
                )
        # Recon-discovered follow-up targets (propose_targets) feed the queue exactly like a
        # cross-chain follow-up: by the next planning phase they are concrete, ready-to-dispatch
        # tasks, not something the planner has to independently rediscover through its own reasoning.
        discovered = list(state.get("discovered_hosts", []))
        next_hops += discovered
        residual = list(critique.not_done) if critique is not None else []
        residual += _unmet_task_classes(state.get("spec"), state.get("probes", []))
        summary = critique.notes if critique is not None else f"{status}: {len(findings)} finding(s)"
        if discovered:
            host_list = ", ".join(t.target for t in discovered if t.target)
            summary = f"{summary} — recon proposed {len(discovered)} follow-up target(s): {host_list}"
        result = CleanResult(
            dispatch_id="",
            status=status,
            spec=state.get("spec"),
            findings=findings,
            flow_batches=batches,
            residual_gaps=residual,
            next_hops=next_hops,
            probes=list(state.get("probes", [])),
            summary=summary,
            cost_usd=float(state.get("cost_usd") or 0.0),
            tokens=int(state.get("tokens") or 0),
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
