"""Async bootstrap + engagement runner (streaming loop, approval-gate resume).

``bootstrap`` wires every subsystem into the two compiled graphs; ``run_engagement`` drives the
master graph with ``astream(..., subgraphs=True)`` so a live UI can attribute per-sub-agent steps
via the namespace tuple without any of it entering the curated master state, pausing on the
authorization ``interrupt_before`` gate and resuming once approved, then rendering the report.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command

from a2pwn import progress
from a2pwn.agents import MasterFork
from a2pwn.artifacts import ArtifactStore
from a2pwn.budget import STOP, DispatchBudget, install_stop_handler
from a2pwn.burpwn import BurpwnClient
from a2pwn.catalog import all_cards, as_langchain_tools, load_skill
from a2pwn.collaborator import Collaborator
from a2pwn.config import A2pwnConfig
from a2pwn.coverage import SurfaceMap
from a2pwn.directives import DirectiveBus
from a2pwn.graph import build_master_graph, build_subagent_graph
from a2pwn.identity import IdentityStore
from a2pwn.report import Report, build_report
from a2pwn.research import ResearchClient
from a2pwn.throttle import Throttle
from a2pwn.tools import burpwn_tools, finding_tools, oracle_tools, recon_tools
from a2pwn.tools.artifact_tools import artifact_tools
from a2pwn.tools.coverage_tools import coverage_tools
from a2pwn.tools.research_tools import research_tools

_log = logging.getLogger("a2pwn")


# --------------------------------------------------------------------------- #
# paths / checkpointer                                                         #
# --------------------------------------------------------------------------- #
def _state_dir() -> Path:
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "a2pwn"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _safe(token: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", token) or "run"


def run_out_dir(cfg: A2pwnConfig, thread_id: str) -> Path:
    """Deterministic per-run artifact directory (shared by ``run_engagement`` and the CLI)."""
    out = _state_dir() / "runs" / _safe(thread_id)
    out.mkdir(parents=True, exist_ok=True)
    return out


def list_runs() -> list[dict]:
    """Enumerate prior run directories under ``<state>/runs``, newest first.

    Each entry carries the ``thread_id`` (directory name), its path, mtime, and — when a
    ``report.json`` is present — the verified / confirmed-only counts, severity tally and objective.
    Display-only: the CLI ``list`` command renders these; no model or burpwn is touched."""
    base = _state_dir() / "runs"
    if not base.exists():
        return []
    runs: list[dict] = []
    for d in base.iterdir():
        if not d.is_dir():
            continue
        info: dict = {
            "thread_id": d.name,
            "path": str(d),
            "has_report": False,
            "verified": 0,
            "confirmed": 0,
            "by_severity": {},
            "objective": "",
            "mtime": d.stat().st_mtime,
        }
        rj = d / "report.json"
        if rj.exists():
            try:
                data = json.loads(rj.read_text(encoding="utf-8"))
                info["has_report"] = True
                info["verified"] = len(data.get("findings", []) or [])
                info["confirmed"] = len(data.get("confirmed_findings", []) or [])
                info["by_severity"] = (data.get("stats") or {}).get("by_severity", {}) or {}
                info["objective"] = data.get("objective", "") or ""
                info["targets"] = list(data.get("targets", []) or [])
                info["in_scope"] = list(data.get("in_scope", []) or [])
                info["exclude"] = list(data.get("exclude", []) or [])
                info["identity_names"] = list(data.get("identity_names", []) or [])
                info["mtime"] = rj.stat().st_mtime
            except Exception as exc:  # noqa: BLE001 - a corrupt report.json must not break the listing
                _log.debug("list_runs: unreadable report.json in %s: %s", d, exc)
        runs.append(info)
    runs.sort(key=lambda r: r.get("mtime") or 0.0, reverse=True)
    return runs


async def _make_checkpointer(cfg: A2pwnConfig) -> BaseCheckpointSaver:
    """Async checkpointer (``run_engagement`` drives the graph with ``astream``): AsyncSqliteSaver
    single-box default (``~/.local/share/a2pwn/runs.db``) or AsyncPostgresSaver. The underlying
    connection is kept open for the process lifetime, as the sync path did."""
    if cfg.checkpoint_uri:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        # Keep the async context manager so teardown can call __aexit__ symmetrically and release
        # the connection pool — a bare `.conn.close()` leaks pooled connections on the Postgres path.
        cm = AsyncPostgresSaver.from_conn_string(cfg.checkpoint_uri)
        saver = await cm.__aenter__()
        await saver.setup()
        saver._a2pwn_cm = cm
        return saver
    import aiosqlite
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

    db_path = _state_dir() / "runs.db"
    conn = await aiosqlite.connect(str(db_path))
    saver = AsyncSqliteSaver(conn)
    await saver.setup()
    return saver


# --------------------------------------------------------------------------- #
# skills / tools                                                               #
# --------------------------------------------------------------------------- #
def _seed_skills(cfg: A2pwnConfig) -> list:  # noqa: ARG001 - cfg kept for signature stability
    """Seed the executor with the WHOLE methodology catalog.

    This used to run `retrieve()` with a query built from the engagement name and its target hosts.
    Hostnames share no vocabulary with a methodology corpus, so the FTS match was near-empty: a real
    run against `ginandjuice.shop` seeded exactly ONE skill (`burpwn`) out of 37, and every dispatch
    went out without the SQLi / XSS / SSRF / IDOR / JWT / GraphQL / race-condition methodology it was
    supposed to carry. Relevance filtering at seed time is the wrong shape anyway — the executor does
    not know which classes apply until it has seen the target, which is exactly what a pentest is.
    """
    skills = []
    for card in all_cards():
        try:
            skills.append(load_skill(card.name))
        except Exception as exc:  # noqa: BLE001 - a broken skill card must not abort bootstrap
            _log.warning("skipping skill %s: %s", card.name, exc)
    return skills


# --------------------------------------------------------------------------- #
# preflight / scope                                                            #
# --------------------------------------------------------------------------- #
class BurpwnMissingError(RuntimeError):
    """burpwn is not installed / not on PATH — raised before any model is constructed."""


def ensure_burpwn_available() -> None:
    """Fail fast (before spending LLM calls) when the burpwn binary is not on ``PATH``.

    burpwn is a hard requirement: without it every sandbox tool call raises ``FileNotFoundError``
    lazily inside the ReAct loop, producing a slow, confusing, cost-incurring empty engagement.
    """
    if shutil.which("burpwn") is None:
        raise BurpwnMissingError(
            "burpwn is not installed or not on PATH. a2pwn drives ALL traffic through the burpwn "
            "sandbox, so it cannot run without it. Install it with `a2pwn install-burpwn` (or grab a "
            "release from https://github.com/own2pwn-fr/burpwn), then run `a2pwn doctor` to verify "
            "the host supports rootless user/network namespaces, and re-run."
        )


def _scope_hosts(cfg: A2pwnConfig) -> list[str]:
    """In-scope host list for burpwn scope enforcement: parse hosts from ``in_scope`` (falling back
    to ``targets``), de-duplicated and order-preserving."""
    from a2pwn.scope import host_of

    raw = cfg.engagement.in_scope or cfg.engagement.targets
    hosts: list[str] = []
    for token in raw:
        host = host_of(token)
        if host and host not in hosts:
            hosts.append(host)
    return hosts


# --------------------------------------------------------------------------- #
# bootstrap                                                                    #
# --------------------------------------------------------------------------- #
async def bootstrap(
    cfg: A2pwnConfig,
) -> tuple[BurpwnClient, CompiledStateGraph, BaseCheckpointSaver]:
    """Preflight burpwn, spawn the session/MCP client, and compile both graphs.

    Returns the client, the compiled master graph, and the checkpointer (the caller owns
    closing both the client and the checkpointer so their background threads don't hang exit).
    """
    ensure_burpwn_available()

    try:
        report = BurpwnClient.cli_doctor()
        if isinstance(report, dict) and report.get("ok") is False:
            _log.warning("burpwn doctor: sandbox prerequisites incomplete: %s", report)
    except Exception as exc:  # noqa: BLE001 - doctor is a warn-not-fatal preflight
        _log.warning("burpwn doctor preflight failed (continuing): %s", exc)

    try:
        BurpwnClient.cli_session_new(cfg.engagement.session)
    except Exception as exc:  # noqa: BLE001 - session may already exist
        _log.info("session new(%s): %s", cfg.engagement.session, exc)

    client = BurpwnClient(cfg.engagement.session)
    # Deterministic scope enforcement: tell burpwn itself which hosts are in scope so it can contain
    # traffic, backing the per-tool argv guards in tools/burpwn_tools.py. Best-effort: the proxy
    # daemon may not be up until the first exec, so a failure here is logged, not fatal.
    for host in _scope_hosts(cfg):
        try:
            await client.intercept_scope(host=host)
        except Exception as exc:  # noqa: BLE001 - scope narrowing is best-effort at bootstrap
            _log.debug("intercept_scope(%s) failed (continuing): %s", host, exc)
    checkpointer = await _make_checkpointer(cfg)
    collab = Collaborator(client, cfg.engagement.oob_listener)
    # Actually START the OOB callback sink, otherwise the `oob` oracle polls a listener that was
    # never launched and NO blind SSRF/XXE/deserialization/SQLi can ever be confirmed (the strongest
    # 0-FP signal would be dead code). Best-effort: a sandbox that cannot host the listener must not
    # abort the run; the external backend (oob_listener set) needs no in-sandbox listener. Stash the
    # handle on the client so run_engagement's teardown can stop() it.
    client._collaborator = collab
    if not cfg.engagement.oob_listener:
        try:
            await collab.start_in_sandbox()
        except Exception as exc:  # noqa: BLE001 - OOB is one oracle among several; degrade, don't abort
            _log.warning("OOB listener failed to start (blind-OOB oracle disabled): %s", exc)
    fork = MasterFork(cfg.models)

    # Engagement-wide policy objects, shared by every tool wrapper on BOTH executor paths so a
    # refusal, a rate limit or an identity means the same thing regardless of which executor runs.
    identities = IdentityStore(client, cfg.engagement.identities) if cfg.engagement.identities else None
    directives = DirectiveBus()
    throttle = Throttle(
        max_rps=cfg.max_rps, block_threshold=cfg.block_threshold, directives=directives
    )
    client._identities = identities  # for the report/summary to describe what was used
    client._throttle = throttle

    # One artifact store per engagement, shared by every dispatch: two sub-agents probing the same
    # host should not each pull the same three-megabyte bundle through the sandbox. Spilled next to
    # the run's other evidence so a bulky body stays inspectable after the run.
    artifacts = ArtifactStore(spill_dir=Path(run_out_dir(cfg, cfg.engagement.name)) / "artifacts")
    client._artifacts = artifacts
    # Out-of-band channel to running dispatches, shared with the throttle so a tripped circuit
    # breaker reaches every sibling immediately instead of each one rediscovering it by wasting
    # turns against a WAF wall.
    client._directives = directives
    # The ONE channel that leaves the machine without burpwn, narrowly scoped to public
    # vulnerability databases (see a2pwn.research). Off entirely under --no-research.
    research = ResearchClient(
        enabled=cfg.research_enabled,
        in_scope_hosts=[*cfg.engagement.targets, *cfg.engagement.in_scope],
    )

    skills = _seed_skills(cfg)
    tools = (
        as_langchain_tools(skills, client, collab)
        # `engagement` was missing here: the documented Python-level scope refusal in
        # burpwn_tools (CLAUDE.md: "the tool wrappers deterministically refuse traffic to
        # out-of-scope hosts") was never actually engaged in a real run on this (LangChain/API
        # backend) executor path — only burpwn's own server-side sandbox containment applied.
        + burpwn_tools(
            client,
            cfg.engagement,
            identities=identities,
            throttle=throttle,
            fuzz_cap=cfg.fuzz_max_requests,
        )
        + oracle_tools(collab, client)
        + finding_tools(client)
        + recon_tools(cfg.engagement)
        + coverage_tools()
        + artifact_tools(artifacts)
        + research_tools(artifacts, research)
    )

    subgraph = build_subagent_graph(
        cfg,
        client,
        fork,
        tools,
        collab,
        skills,
        identities=identities,
        throttle=throttle,
        artifacts=artifacts,
        directives=directives,
        research=research,
    )
    graph = build_master_graph(cfg, subgraph, client, checkpointer)
    return client, graph, checkpointer


async def _close_checkpointer(checkpointer: BaseCheckpointSaver) -> None:
    """Close the checkpointer's backing connection so its worker thread doesn't hang exit."""
    cm = getattr(checkpointer, "_a2pwn_cm", None)
    if cm is not None:  # Postgres path: exit the context manager so the pool is released.
        try:
            await cm.__aexit__(None, None, None)
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup
            _log.debug("checkpointer context exit failed: %s", exc)
        return
    conn = getattr(checkpointer, "conn", None)
    closer = getattr(conn, "close", None)
    if closer is None:
        return
    try:
        result = closer()
        if hasattr(result, "__await__"):
            await result
    except Exception as exc:  # noqa: BLE001 - best-effort cleanup
        _log.debug("checkpointer close failed: %s", exc)


# --------------------------------------------------------------------------- #
# streaming / resume helpers                                                   #
# --------------------------------------------------------------------------- #
def _unpack(chunk: Any) -> tuple[tuple, str | None, Any]:
    ns: tuple = ()
    mode: str | None = None
    data: Any = chunk
    if isinstance(chunk, tuple):
        if len(chunk) == 3:
            ns, mode, data = chunk
        elif len(chunk) == 2:
            first, second = chunk
            if isinstance(first, tuple):
                ns = first
                if isinstance(second, tuple) and len(second) == 2:
                    mode, data = second
                else:
                    data = second
            else:
                mode, data = first, second
    return ns, mode, data


def _emit_telemetry(chunk: Any) -> None:
    ns, mode, data = _unpack(chunk)
    label = ":".join(str(p) for p in ns) if ns else "master"
    if mode == "updates" and isinstance(data, dict):
        for node in data:
            _log.info("[%s] node=%s", label, node)
    elif mode == "messages":
        _log.debug("[%s] message chunk", label)


def _has_dynamic_interrupt(snap: Any) -> bool:
    for task in getattr(snap, "tasks", ()) or ():
        if getattr(task, "interrupts", None):
            return True
    values = getattr(snap, "values", None)
    return isinstance(values, dict) and "__interrupt__" in values


def _approve_interrupt(cfg: A2pwnConfig, snap: Any) -> bool:
    """Decide whether to resume past the master's per-dispatch interrupt.

    Authorization is a ONE-TIME acknowledgement taken upfront by the CLI gate; it is NOT a
    per-dispatch approval. Only interactive step-through mode (``cfg.step_through``) prompts the
    operator before each dispatch — otherwise approval is upfront-only and the run resumes
    autonomously (the honest semantics the disclaimer now documents).
    """
    if not cfg.step_through:
        return True
    prompt = f"Approve dispatch against {cfg.engagement.targets}? [y/N] "
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


# --------------------------------------------------------------------------- #
# engagement runner                                                            #
# --------------------------------------------------------------------------- #
def _model_meta(cfg: A2pwnConfig) -> dict:
    """Executor/verifier backend labels threaded into the report metadata."""
    ex, ver = cfg.models.executor, cfg.models.verifier
    return {
        "executor": f"{ex.provider}:{ex.model or 'sonnet'}",
        "verifier": f"{ver.provider}:{ver.model or 'opus'}",
    }


async def run_engagement(
    cfg: A2pwnConfig,
    objective: str,
    thread_id: str,
    *,
    tui: bool = False,
    formats: list[str] | None = None,
    seed_tasks: list | None = None,
    baseline: list | None = None,
) -> Report:
    """Drive the master graph to completion and build the evidence-grounded report.

    With ``tui=True`` a live :mod:`rich` dashboard runs concurrently, fed by the display-only
    :mod:`a2pwn.progress` event bus (which never touches graph state, so clean-history holds).
    ``formats`` selects which report artifacts are written (md+json always).

    ``seed_tasks`` pre-loads the master's ``pending`` queue (used by ``a2pwn retest`` to seed one
    reproduce-this-finding task per baseline finding, skipping the planner's first LLM call exactly
    like the recon seed does); ``baseline`` is the prior run's findings the report diffs against.
    """
    client: BurpwnClient | None = None
    checkpointer: BaseCheckpointSaver | None = None
    out_dir = run_out_dir(cfg, thread_id)
    config = {"configurable": {"thread_id": thread_id}}
    queue: asyncio.Queue | None = asyncio.Queue() if tui else None
    if queue is not None:
        progress.set_sink(queue)
    # Durable event log for EVERY run (TUI or not): dispatches, tool calls, tool failures, model
    # refusals and adjudication reject reasons. Without it a finished run can only be diagnosed by
    # re-reading raw model transcripts, which is how three silently-dropped-finding bugs stayed
    # hidden until a live engagement surfaced them.
    progress.set_file_sink(out_dir / "run.jsonl")
    model_label = f"{cfg.models.executor.provider} · {cfg.models.executor.model or 'sonnet'}"
    targets_label = ", ".join(cfg.engagement.targets)
    models_meta = _model_meta(cfg)
    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    t0 = time.monotonic()
    try:
        client, graph, checkpointer = await bootstrap(cfg)
        budget = DispatchBudget(
            max_dispatches=cfg.max_dispatches,
            max_batch_width=cfg.max_batch_width,
            max_phases=cfg.max_phases,
            max_usd=cfg.max_usd,
            max_tokens=cfg.max_tokens,
        )
        install_stop_handler(budget)

        stream_input: Any = {
            "engagement": cfg.engagement,
            "objective": objective,
            "budget": budget,
            "history": [],
            "pending": list(seed_tasks or []),
            "deferred": [],
            "dispatch_results": [],
            "findings": [],
            "verify_queue": [],
            "verify_attempts": {},
            # The coverage matrix starts empty; bootstrap seeds it from the declared scope and
            # `integrate` grows it from captured traffic.
            "surface": SurfaceMap(),
            "phase": "recon",
            "round": 0,
            "continuations": 0,
            "spent": 0,
            "spent_usd": 0.0,
            "spent_tokens": 0,
        }

        async def _drive_loop() -> None:
            si = stream_input
            while True:
                async for chunk in graph.astream(
                    si, config, stream_mode=["updates", "messages"], subgraphs=True
                ):
                    _emit_telemetry(chunk)
                snap = await graph.aget_state(config)
                if not snap.next:
                    break
                if not _approve_interrupt(cfg, snap):
                    _log.warning("dispatch declined by operator; routing to report")
                    budget.stopped = True
                    break
                si = Command(resume=True) if _has_dynamic_interrupt(snap) else None

        async def _drive() -> Report:
            # Optional wall-clock safety net: past the deadline, stop driving and still report what
            # was proven. STOP also flags the routers so a resume wouldn't re-enter the graph.
            if cfg.max_wall_secs:
                try:
                    await asyncio.wait_for(_drive_loop(), timeout=cfg.max_wall_secs)
                except TimeoutError:
                    _log.warning(
                        "engagement hit the %ss wall-clock deadline; building the report from "
                        "proven findings so far",
                        cfg.max_wall_secs,
                    )
                    STOP.set()
            else:
                await _drive_loop()
            final = (await graph.aget_state(config)).values
            throttle = getattr(client, "_throttle", None)
            return await build_report(
                final,
                client,
                str(out_dir),
                models=models_meta,
                started_at=started_at,
                duration_secs=time.monotonic() - t0,
                formats=formats,
                traffic=throttle.stats() if throttle is not None else None,
                baseline=baseline,
            )

        if queue is not None:
            from a2pwn import tui as tuimod

            progress.emit("engagement", target=targets_label, model=model_label, objective=objective)
            tui_task = asyncio.create_task(
                tuimod.run_tui(queue, target=targets_label, model=model_label, objective=objective)
            )
            try:
                report = await _drive()
                progress.emit(
                    "done",
                    report=str(out_dir / "report.md"),
                    har=list(report.har_paths),
                    n_verified=len(report.findings),
                )
            except BaseException:
                queue.put_nowait(None)  # stop the live view even on failure
                raise
            finally:
                await tui_task
        else:
            report = await _drive()
    finally:
        if queue is not None:
            progress.clear_sink()
        progress.close_file_sink()
        # Close each subsystem independently so one failing close never orphans the other's worker
        # thread. The checkpoint is already durable, so the run stays resumable by thread_id.
        if client is not None:
            collab = getattr(client, "_collaborator", None)
            if collab is not None and hasattr(collab, "stop"):
                try:
                    await collab.stop()  # tear down the in-sandbox OOB listener
                except Exception as exc:  # noqa: BLE001 - best-effort; the listener self-expires on TTL
                    _log.debug("OOB listener stop failed: %s", exc)
            try:
                await client.close()
            except Exception as exc:  # noqa: BLE001 - best-effort teardown, never mask the real error
                _log.debug("client close failed: %s", exc)
        if checkpointer is not None:
            await _close_checkpointer(checkpointer)
    return report
