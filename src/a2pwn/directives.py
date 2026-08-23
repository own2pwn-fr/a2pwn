"""Out-of-band messages to a RUNNING dispatch.

Fan-out was fire-and-forget: `run_subagent` awaited the child and had no way to reach it again until
it returned. Nothing could tell a sub-agent that the target had started blocking, that a sibling had
already proven the very bug it was working on, or that the engagement was nearly out of budget — all
of which were known *while* it was burning turns on the wrong thing.

The delivery mechanism deliberately does not depend on the model's cooperation: directives are
appended to the next TOOL RESULT the dispatch receives. There is no "check your messages" tool the
agent might not call, and no interrupt that needs a checkpointer the stateless child does not have.
An agent that keeps working keeps reading its tool results, so it will see the message.

Everything here is process-local and synchronous; a directive is a hint, never a control signal.
The hard controls (scope refusal, the circuit breaker, budget exhaustion) stay where they are, in
the tool wrappers and the routers.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

_log = logging.getLogger("a2pwn")

_MAX_PER_DRAIN = 4
_MAX_LEN = 600


@dataclass
class DirectiveBus:
    """Per-engagement mailbox, shared by every dispatch in the fan-out."""

    _targeted: dict[str, list[str]] = field(default_factory=dict)
    _broadcast: list[str] = field(default_factory=list)
    # How much of the broadcast log each dispatch has already been shown. A dispatch that starts
    # late must not be handed the whole backlog of a long engagement, so it joins at the end.
    _cursor: dict[str, int] = field(default_factory=dict)
    _once: set[str] = field(default_factory=set)

    def post_once(self, key: str, text: str, *, to: str | None = None) -> None:
        """Post at most one directive per key, ever.

        Standing conditions (near the budget ceiling, the breaker tripped) are re-evaluated every
        phase; re-broadcasting them would fill each dispatch's tool results with the same sentence
        and train the model to skim past directives entirely.
        """
        if key in self._once:
            return
        if self.post(text, to=to):
            self._once.add(key)

    def post(self, text: str, *, to: str | None = None) -> bool:
        """Queue a directive for one dispatch, or (``to=None``) for every running one.

        Returns whether anything was actually queued, so `post_once` does not burn its key on a
        producer that computed an empty message and would then be unable to ever post it.
        """
        text = (text or "").strip()[:_MAX_LEN]
        if not text:
            return False
        if to:
            self._targeted.setdefault(to, []).append(text)
        else:
            self._broadcast.append(text)
        _log.info("directive posted (%s): %s", to or "broadcast", text)
        return True

    def join(self, dispatch_id: str) -> None:
        """Register a dispatch at the current end of the broadcast log."""
        self._cursor.setdefault(dispatch_id, len(self._broadcast))

    def drain(self, dispatch_id: str) -> list[str]:
        """Take at most ``_MAX_PER_DRAIN`` pending directives; the rest stay queued.

        The cap exists so one tool result is not buried under a wall of banners. It must not be a
        DROP: advancing the cursor past the whole log and then slicing lost every message beyond
        the fourth, permanently — including, in the worst case, the circuit-breaker broadcast
        masked by a burst of targeted messages.
        """
        if not dispatch_id:
            return []
        seen = self._cursor.get(dispatch_id)
        if seen is None:
            # A dispatch that never joined is treated as joining now rather than being handed the
            # entire engagement's backlog on its first tool call.
            seen = len(self._broadcast)
            self._cursor[dispatch_id] = seen
        out: list[str] = []
        targeted = self._targeted.get(dispatch_id) or []
        taken = targeted[:_MAX_PER_DRAIN]
        del targeted[: len(taken)]
        if not targeted:
            self._targeted.pop(dispatch_id, None)
        out.extend(taken)
        room = _MAX_PER_DRAIN - len(out)
        if room > 0 and seen < len(self._broadcast):
            chunk = self._broadcast[seen : seen + room]
            out.extend(chunk)
            self._cursor[dispatch_id] = seen + len(chunk)
        return out

    def annotate(self, dispatch_id: str, text: str) -> str:
        """Append any pending directives to a tool result's text."""
        pending = self.drain(dispatch_id)
        if not pending:
            return text
        banner = "\n".join(f"[DIRECTIVE from the engagement coordinator] {d}" for d in pending)
        return f"{text}\n\n{banner}"
