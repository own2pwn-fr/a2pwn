"""Global dispatch budget + TaskStop kill switch + hard-cap helpers (cost/termination safety)."""

import signal
from typing import Any

from pydantic import BaseModel


class DispatchBudget(BaseModel):
    """Immutable-by-convention spend/cap tracker threaded through master state.

    ``charge`` returns a fresh copy so the LangGraph reducer overwrite semantics stay pure;
    ``stopped`` is the TaskStop kill switch flipped by ``install_stop_handler``.
    """

    max_dispatches: int = 200
    spent: int = 0
    max_batch_width: int = 6
    max_phases: int = 12
    stopped: bool = False  # TaskStop kill switch (set by CLI signal / interrupt)

    def charge(self, n: int = 1) -> "DispatchBudget":
        return self.model_copy(update={"spent": self.spent + n})

    @property
    def exhausted(self) -> bool:
        return self.stopped or self.spent >= self.max_dispatches

    def clamp_batch(self, tasks: list) -> list:
        return tasks[: self.max_batch_width]


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
