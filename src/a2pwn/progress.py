"""Ephemeral progress event bus for the live TUI.

The clean-history mandate keeps sub-agent transcripts out of the master *state*, but a live UI still
needs to show what each dispatch is doing. These events are display-only — they never touch graph
state, so the invariant holds. A dispatch identifier is carried on a :class:`contextvars.ContextVar`
that ``run_subagent`` sets before invoking the child; every emit inside that async task (sub-agent
nodes, the SDK executor's tool loop, ``report_finding``) reads it, so events are attributed to the
right dispatch without threading an id through every call.

Emitting to the TUI is a cheap no-op until a sink (an ``asyncio.Queue``) is installed, so headless /
``--plain`` runs pay nothing for the live view.

There is a SECOND, independent sink: a JSONL file installed by ``run_engagement`` for every run,
TUI or not. Its absence was a real cost — the three "well-evidenced findings silently dropped from
the report" bugs were only found by reading raw LLM transcripts by hand, because the adjudication
reject reasons and tool failures existed nowhere durable. ``run.jsonl`` next to the report makes a
finished run answerable after the fact ("what did dispatch 3-task-1 actually call, and why was that
candidate rejected?") without re-running anything.
"""

from __future__ import annotations

import contextvars
import json
import time
from typing import Any

_sink: Any = None  # asyncio.Queue | None — installed by the TUI
_file: Any = None  # a writable text file handle — installed for every run
_dispatch: contextvars.ContextVar[str] = contextvars.ContextVar("a2pwn_dispatch", default="master")


def set_sink(queue: Any) -> None:
    """Install the event queue the TUI drains (call once at run start)."""
    global _sink
    _sink = queue


def clear_sink() -> None:
    global _sink
    _sink = None


def set_file_sink(path: Any) -> None:
    """Install the durable JSONL event log at ``path`` (best-effort; never fatal to a run)."""
    global _file
    close_file_sink()
    try:
        _file = open(path, "a", encoding="utf-8", buffering=1)  # noqa: SIM115 - lifetime is the run
    except OSError:  # a read-only/full run dir must not abort the engagement
        _file = None


def close_file_sink() -> None:
    global _file
    handle, _file = _file, None
    if handle is not None:
        try:
            handle.close()
        except OSError:
            pass


def set_dispatch(dispatch_id: str):
    """Bind the current async task to a dispatch id; returns the contextvar token to reset."""
    return _dispatch.set(dispatch_id)


def reset_dispatch(token) -> None:
    try:
        _dispatch.reset(token)
    except (ValueError, LookupError):  # pragma: no cover - token from a different context
        pass


def current_dispatch() -> str:
    return _dispatch.get()


def emit(kind: str, **fields: Any) -> None:
    """Fan an event out to the live TUI queue and the durable JSONL log (never raises).

    Both sinks are optional and independent: a ``--plain`` run has no queue but still writes the
    file, and neither failure mode is allowed to disturb the engagement.
    """
    q, fh = _sink, _file
    if q is None and fh is None:
        return
    event = {"kind": kind, "dispatch": _dispatch.get(), **fields}
    if q is not None:
        try:
            q.put_nowait(event)
        except Exception:  # noqa: BLE001 - a full/closed UI queue must never disturb the engagement
            pass
    if fh is not None:
        try:
            fh.write(json.dumps({"ts": time.time(), **event}, default=str) + "\n")
        except Exception:  # noqa: BLE001 - a full disk must not abort a live engagement
            pass
