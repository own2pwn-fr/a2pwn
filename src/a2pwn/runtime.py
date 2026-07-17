"""Async bootstrap + engagement runner (streaming loop, approval-gate resume).

``bootstrap`` wires every subsystem into the two compiled graphs; ``run_engagement`` drives the
master graph with ``astream(..., subgraphs=True)`` so a live UI can attribute per-sub-agent steps
via the namespace tuple without any of it entering the curated master state, pausing on the
authorization ``interrupt_before`` gate and resuming once approved, then rendering the report.
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command

from a2pwn.agents import MasterFork
from a2pwn.budget import DispatchBudget, install_stop_handler
from a2pwn.burpwn import BurpwnClient
from a2pwn.catalog import as_langchain_tools, load_skill, retrieve
from a2pwn.collaborator import Collaborator
from a2pwn.config import A2pwnConfig
from a2pwn.graph import build_master_graph, build_subagent_graph
from a2pwn.report import Report, build_report
from a2pwn.tools import burpwn_tools, oracle_tools

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


def _make_checkpointer(cfg: A2pwnConfig) -> BaseCheckpointSaver:
    """SqliteSaver single-box default (``~/.local/share/a2pwn/runs.db``) or PostgresSaver."""
    if cfg.checkpoint_uri:
        from langgraph.checkpoint.postgres import PostgresSaver

        saver = PostgresSaver.from_conn_string(cfg.checkpoint_uri).__enter__()
        saver.setup()
        return saver
    db_path = _state_dir() / "runs.db"
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    saver = SqliteSaver(conn)
    saver.setup()
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
# bootstrap                                                                    #
# --------------------------------------------------------------------------- #
async def bootstrap(cfg: A2pwnConfig) -> tuple[BurpwnClient, CompiledStateGraph]:
    """Preflight burpwn, spawn the session/MCP client, and compile both graphs."""
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
    checkpointer = _make_checkpointer(cfg)
    collab = Collaborator(client, cfg.engagement.oob_listener)
    fork = MasterFork(cfg.models)

    tools = (
        as_langchain_tools(_seed_skills(cfg), client, collab)
        + burpwn_tools(client)
        + oracle_tools(collab, client)
    )

    subgraph = build_subagent_graph(cfg, client, fork, tools, collab)
    graph = build_master_graph(cfg, subgraph, client, checkpointer)
    return client, graph


def bootstrap_node(state: dict) -> dict:
    """Seed the canonical master state at graph entry (START -> bootstrap -> plan)."""
    budget = state.get("budget") or DispatchBudget()
    return {
        "engagement": state["engagement"],
        "objective": state["objective"],
        "budget": budget,
        "phase": "recon",
        "round": 0,
    }


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
    if cfg.engagement.active_exploit_allowed:
        return True
    if cfg.engagement.authorization_acknowledged or cfg.disclaimer_ack:
        return True
    prompt = f"Approve dispatch against {cfg.engagement.targets}? [y/N] "
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


# --------------------------------------------------------------------------- #
# engagement runner                                                            #
# --------------------------------------------------------------------------- #
async def run_engagement(cfg: A2pwnConfig, objective: str, thread_id: str) -> Report:
    """Drive the master graph to completion and build the evidence-grounded report."""
    client, graph = await bootstrap(cfg)
    budget = DispatchBudget(
        max_dispatches=cfg.max_dispatches,
        max_batch_width=cfg.max_batch_width,
        max_phases=cfg.max_phases,
    )
    install_stop_handler(budget)

    config = {"configurable": {"thread_id": thread_id}}
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
        "phase": "recon",
        "round": 0,
    }
    out_dir = run_out_dir(cfg, thread_id)

    try:
        while True:
            async for chunk in graph.astream(
                stream_input, config, stream_mode=["updates", "messages"], subgraphs=True
            ):
                _emit_telemetry(chunk)
            snap = await graph.aget_state(config)
            if not snap.next:
                break
            if not _approve_interrupt(cfg, snap):
                _log.warning("dispatch declined by operator; routing to report")
                budget.stopped = True
                break
            stream_input = Command(resume=True) if _has_dynamic_interrupt(snap) else None

        final = (await graph.aget_state(config)).values
        report = await build_report(final, client, str(out_dir))
    finally:
        await client.close()
    return report
