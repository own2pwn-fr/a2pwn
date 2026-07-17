"""Global dispatch budget + TaskStop kill switch + hard-cap helpers (cost/termination safety)."""

import signal
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
    def is_exhausted(self, spent: int) -> bool:
        return self.stopped or STOP.is_set() or spent >= self.max_dispatches

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
