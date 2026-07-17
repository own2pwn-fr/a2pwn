"""Ephemeral progress event bus for the live TUI.

The clean-history mandate keeps sub-agent transcripts out of the master *state*, but a live UI still
needs to show what each dispatch is doing. These events are display-only — they never touch graph
state, so the invariant holds. A dispatch identifier is carried on a :class:`contextvars.ContextVar`
that ``run_subagent`` sets before invoking the child; every emit inside that async task (sub-agent
nodes, the SDK executor's tool loop, ``report_finding``) reads it, so events are attributed to the
right dispatch without threading an id through every call.

Emitting is a cheap no-op until a sink (an ``asyncio.Queue``) is installed by the TUI, so headless /
``--plain`` runs pay nothing.
"""

from __future__ import annotations

import contextvars
from typing import Any

_sink: Any = None  # asyncio.Queue | None — installed by the TUI
_dispatch: contextvars.ContextVar[str] = contextvars.ContextVar("a2pwn_dispatch", default="master")


def set_sink(queue: Any) -> None:
    """Install the event queue the TUI drains (call once at run start)."""
    global _sink
    _sink = queue


def clear_sink() -> None:
    global _sink
    _sink = None


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
    """Push a display event onto the sink if one is installed (non-blocking, never raises)."""
    q = _sink
    if q is None:
        return
    event = {"kind": kind, "dispatch": _dispatch.get(), **fields}
    try:
        q.put_nowait(event)
    except Exception:  # noqa: BLE001 - a full/closed UI queue must never disturb the engagement
        pass
