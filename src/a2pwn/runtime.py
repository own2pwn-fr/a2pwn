"""Async bootstrap + engagement runner (streaming loop, approval-gate resume).

``bootstrap`` wires every subsystem into the two compiled graphs; ``run_engagement`` drives the
master graph with ``astream(..., subgraphs=True)`` so a live UI can attribute per-sub-agent steps
via the namespace tuple without any of it entering the curated master state, pausing on the
authorization ``interrupt_before`` gate and resuming once approved, then rendering the report.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command

from a2pwn import progress
from a2pwn.agents import MasterFork
from a2pwn.budget import DispatchBudget, install_stop_handler
from a2pwn.burpwn import BurpwnClient
from a2pwn.catalog import as_langchain_tools, load_skill, retrieve
from a2pwn.collaborator import Collaborator
from a2pwn.config import A2pwnConfig
from a2pwn.graph import build_master_graph, build_subagent_graph
from a2pwn.report import Report, build_report
from a2pwn.tools import burpwn_tools, finding_tools, oracle_tools

_log = logging.getLogger("a2pwn")

_SEED_SKILL_LIMIT = 64


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


async def _make_checkpointer(cfg: A2pwnConfig) -> BaseCheckpointSaver:
    """Async checkpointer (``run_engagement`` drives the graph with ``astream``): AsyncSqliteSaver
    single-box default (``~/.local/share/a2pwn/runs.db``) or AsyncPostgresSaver. The underlying
    connection is kept open for the process lifetime, as the sync path did."""
    if cfg.checkpoint_uri:
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        saver = await AsyncPostgresSaver.from_conn_string(cfg.checkpoint_uri).__aenter__()
        await saver.setup()
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
def _seed_skills(cfg: A2pwnConfig) -> list:
    eng = cfg.engagement
    query = " ".join([eng.name, *eng.targets, *eng.in_scope]).strip()
    skills = []
    for card in retrieve(query, k=_SEED_SKILL_LIMIT):
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
            "sandbox, so it cannot run without it. Install it from "
            "https://github.com/own2pwn-fr/burpwn and run `burpwn doctor` to verify the host "
            "supports rootless user/network namespaces, then re-run."
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
    fork = MasterFork(cfg.models)

    skills = _seed_skills(cfg)
    tools = (
        as_langchain_tools(skills, client, collab)
        + burpwn_tools(client)
        + oracle_tools(collab, client)
        + finding_tools(client)
    )

    subgraph = build_subagent_graph(cfg, client, fork, tools, collab, skills)
    graph = build_master_graph(cfg, subgraph, client, checkpointer)
    return client, graph, checkpointer


async def _close_checkpointer(checkpointer: BaseCheckpointSaver) -> None:
    """Close the checkpointer's backing connection so its worker thread doesn't hang exit."""
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
async def run_engagement(
    cfg: A2pwnConfig, objective: str, thread_id: str, *, tui: bool = False
) -> Report:
    """Drive the master graph to completion and build the evidence-grounded report.

    With ``tui=True`` a live :mod:`rich` dashboard runs concurrently, fed by the display-only
    :mod:`a2pwn.progress` event bus (which never touches graph state, so clean-history holds)."""
    client: BurpwnClient | None = None
    checkpointer: BaseCheckpointSaver | None = None
    out_dir = run_out_dir(cfg, thread_id)
    config = {"configurable": {"thread_id": thread_id}}
    queue: asyncio.Queue | None = asyncio.Queue() if tui else None
    if queue is not None:
        progress.set_sink(queue)
    model_label = f"{cfg.models.executor.provider} · {cfg.models.executor.model or 'sonnet'}"
    targets_label = ", ".join(cfg.engagement.targets)
    try:
        client, graph, checkpointer = await bootstrap(cfg)
        budget = DispatchBudget(
            max_dispatches=cfg.max_dispatches,
            max_batch_width=cfg.max_batch_width,
            max_phases=cfg.max_phases,
        )
        install_stop_handler(budget)

        stream_input: Any = {
            "engagement": cfg.engagement,
            "objective": objective,
            "budget": budget,
            "history": [],
            "pending": [],
            "deferred": [],
            "dispatch_results": [],
            "findings": [],
            "verify_queue": [],
            "verify_attempts": {},
            "phase": "recon",
            "round": 0,
            "continuations": 0,
        }

        async def _drive() -> Report:
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
            final = (await graph.aget_state(config)).values
            return await build_report(final, client, str(out_dir))

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
        # Close each subsystem independently so one failing close never orphans the other's worker
        # thread. The checkpoint is already durable, so the run stays resumable by thread_id.
        if client is not None:
            try:
                await client.close()
            except Exception as exc:  # noqa: BLE001 - best-effort teardown, never mask the real error
                _log.debug("client close failed: %s", exc)
        if checkpointer is not None:
            await _close_checkpointer(checkpointer)
    return report
