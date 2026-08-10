"""Global dispatch budget + TaskStop kill switch + hard-cap helpers (cost/termination safety)."""

import signal
import sys
import threading
from typing import Any

from pydantic import BaseModel

# Process-wide TaskStop signal. ``install_stop_handler`` sets it on SIGINT; the master graph's
# routers (``route_dispatch`` / ``integrate_next``) check ``STOP.is_set()`` so a Ctrl-C reaches the
# graph even though the DispatchBudget carried in state is a per-phase snapshot the signal handler
# cannot reach in place. Tests may ``STOP.set()`` / ``STOP.clear()`` around a routing assertion.
STOP = threading.Event()


class DispatchBudget(BaseModel):
    """Immutable-by-convention spend/cap tracker threaded through master state.

    ``charge`` returns a fresh copy so the LangGraph reducer overwrite semantics stay pure;
    ``stopped`` is the TaskStop kill switch flipped by ``install_stop_handler``.
    """

    max_dispatches: int = 200
    spent: int = 0
    max_batch_width: int = 6
    max_phases: int = 12
    # Cap on independent-verify attempts per finding key across phases; once exhausted a
    # persistently-unverifiable candidate is dropped from the verify queue (confirmed-only).
    max_verify_attempts: int = 2
    # REAL spend ceilings, alongside the dispatch COUNT cap above. A dispatch count is a poor proxy
    # for cost (one dispatch ranges from a few turns to 60 turns with a 150k-token compaction), so
    # ``max_dispatches`` alone cannot bound what a run actually costs. Both are None by default,
    # preserving the historical count-only behaviour. Accumulated spend lives in the master state's
    # separate ``spent_usd``/``spent_tokens`` reducer channels, never on this object.
    max_usd: float | None = None
    max_tokens: int | None = None
    stopped: bool = False  # TaskStop kill switch (set by CLI signal / interrupt)

    def charge(self, n: int = 1) -> "DispatchBudget":
        return self.model_copy(update={"spent": self.spent + n})

    @property
    def exhausted(self) -> bool:
        return self.stopped or STOP.is_set() or self.spent >= self.max_dispatches

    # State-aware variants: the master state carries the CAPS in this immutable ``budget`` object
    # and the accumulating spend in a separate ``spent`` channel (an ``operator.add`` int), so the
    # LangGraph fan-out reducer can never overwrite the caps with a delta's defaults. The graph
    # routers use these, passing ``state["spent"]``.
    def is_exhausted(self, spent: int, spent_usd: float = 0.0, spent_tokens: int = 0) -> bool:
        """True when ANY hard stop applies: TaskStop, the dispatch count cap, or a real spend cap.

        ``spent_usd``/``spent_tokens`` default to 0 so every existing call site keeps its exact
        prior meaning (dispatch-count-only) — the cost ceilings simply never fire when the caller
        does not track them.
        """
        if self.stopped or STOP.is_set() or spent >= self.max_dispatches:
            return True
        if self.max_usd is not None and spent_usd >= self.max_usd:
            return True
        return self.max_tokens is not None and spent_tokens >= self.max_tokens

    def overspend_reason(self, spent: int, spent_usd: float = 0.0, spent_tokens: int = 0) -> str:
        """Why the run stopped, for the operator-facing log/report ("" when it has not)."""
        if self.stopped or STOP.is_set():
            return "operator stop (Ctrl-C)"
        if spent >= self.max_dispatches:
            return f"dispatch cap reached ({spent}/{self.max_dispatches})"
        if self.max_usd is not None and spent_usd >= self.max_usd:
            return f"cost cap reached (${spent_usd:.2f}/${self.max_usd:.2f})"
        if self.max_tokens is not None and spent_tokens >= self.max_tokens:
            return f"token cap reached ({spent_tokens}/{self.max_tokens})"
        return ""

    def clamp(self, tasks: list, spent: int) -> list:
        """Cap a phase's parallel Sends to the batch width AND the remaining hard budget, so a
        phase never dispatches past ``max_dispatches``."""
        remaining = max(0, self.max_dispatches - spent)
        return tasks[: min(self.max_batch_width, remaining)]

    def clamp_batch(self, tasks: list) -> list:
        """Model-local clamp using this budget's own ``spent`` (standalone / test use)."""
        return self.clamp(tasks, self.spent)


def install_stop_handler(budget_ref: DispatchBudget) -> None:
    """Wire SIGINT so the first Ctrl-C flips ``budget_ref.stopped`` for a graceful report.

    A second Ctrl-C chains to the previous handler (hard abort). No-op when not running on the
    main thread (``signal.signal`` raises there), so it stays safe inside test harnesses.
    """
    previous = signal.getsignal(signal.SIGINT)
    state: dict[str, int] = {"count": 0}

    def _handler(signum: int, frame: Any) -> None:
        state["count"] += 1
        budget_ref.stopped = True
        STOP.set()  # process-wide signal the graph routers actually read
        if state["count"] == 1:
            # First Ctrl-C: user-visible confirmation that a graceful finalize is under way. The TUI
            # footer picks up the "stopping" event; plain runs get the stderr line.
            from a2pwn import progress

            progress.emit("stopping")
            print(
                "\n⏸ arrêt propre demandé — finalisation du rapport (Ctrl-C encore pour forcer).",
                file=sys.stderr,
                flush=True,
            )
        if state["count"] >= 2:
            if callable(previous):
                previous(signum, frame)
            else:
                raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGINT, _handler)
    except ValueError:
        # Not in the main thread; the caller keeps running without a soft-stop hook.
        pass
