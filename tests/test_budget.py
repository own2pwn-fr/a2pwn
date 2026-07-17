"""Global dispatch budget: charge, exhaustion, clamp, and the TaskStop kill switch."""

import pytest

from _graphkit import make_budget, make_cfg, make_master_state
from a2pwn.budget import STOP, DispatchBudget
from a2pwn.graph import integrate_next, route_dispatch
from a2pwn.models import TaskSpec


@pytest.fixture(autouse=True)
def _clear_stop():
    # The STOP event is process-wide; make sure no test leaks a set state to another.
    STOP.clear()
    yield
    STOP.clear()


def test_charge_is_pure_and_increments_spend():
    b = DispatchBudget(max_dispatches=10)
    charged = b.charge(3)
    assert charged.spent == 3
    assert b.spent == 0  # original untouched (reducer-safe copy)


def test_exhausted_on_spend_cap():
    assert DispatchBudget(max_dispatches=5, spent=5).exhausted is True
    assert DispatchBudget(max_dispatches=5, spent=4).exhausted is False


def test_exhausted_on_stop_flag():
    assert DispatchBudget(max_dispatches=100, spent=0, stopped=True).exhausted is True


def test_clamp_batch_caps_width():
    b = DispatchBudget(max_batch_width=2)
    assert b.clamp_batch([1, 2, 3, 4]) == [1, 2]


def test_clamp_batch_also_caps_to_remaining_budget():
    # width 6 but only 2 dispatches of hard budget remain -> clamp to 2.
    b = DispatchBudget(max_batch_width=6, max_dispatches=10, spent=8)
    assert b.clamp_batch([1, 2, 3, 4, 5]) == [1, 2]
    # fully spent -> nothing dispatches.
    assert DispatchBudget(max_batch_width=6, max_dispatches=10, spent=10).clamp_batch([1, 2]) == []


def test_stop_flag_routes_to_report():
    cfg = make_cfg()
    tasks = (TaskSpec(task="t", target="https://t/1"),)
    state = make_master_state(cfg, pending=tasks, budget=make_budget(cfg, stopped=True))
    assert route_dispatch(state) == "report"


def test_exhausted_budget_routes_to_report_even_with_work_pending():
    cfg = make_cfg()
    tasks = (TaskSpec(task="t", target="https://t/1"),)
    state = make_master_state(cfg, pending=tasks, spent=1, budget=make_budget(cfg, max_dispatches=1))
    assert route_dispatch(state) == "report"


def test_stop_event_routes_dispatch_to_report():
    # The SIGINT-set process-wide STOP event must reach the graph router even though the budget
    # snapshot in state was never mutated in place (TaskStop actually stops).
    cfg = make_cfg()
    tasks = (TaskSpec(task="t", target="https://t/1"),)
    state = make_master_state(cfg, pending=tasks)
    assert route_dispatch(state) != "report"  # baseline: work would dispatch
    STOP.set()
    assert route_dispatch(state) == "report"


def test_stop_event_ends_the_phase_loop():
    cfg = make_cfg()
    tasks = (TaskSpec(task="t", target="https://t/1"),)
    state = make_master_state(cfg, pending=tasks)
    assert integrate_next(state) == "continue"
    STOP.set()
    assert integrate_next(state) == "done"
