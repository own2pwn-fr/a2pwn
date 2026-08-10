"""Real spend ceilings (dollars / tokens), alongside the dispatch COUNT cap.

``max_dispatches`` bounds how many dispatches run, not what they cost: one dispatch ranges from a
handful of turns to 60 turns with a 150k-token compaction, so two runs at the same dispatch cap can
differ by an order of magnitude in spend. The TUI even labelled the dispatch bar "cost cap", which
it was not. These tests pin that the real ceilings stop the run and that the spend channels survive
the parallel-Send reducer.
"""

from __future__ import annotations

from _graphkit import make_cfg, make_master_state
from a2pwn.budget import STOP, DispatchBudget
from a2pwn.graph import integrate_next, route_dispatch
from a2pwn.models import CleanResult, TaskSpec


def _state(budget: DispatchBudget, **over) -> dict:
    cfg = make_cfg()
    return make_master_state(
        cfg,
        pending=(TaskSpec(task="probe /login", target="https://app.example.com/login"),),
        budget=budget,
        **over,
    )


# --------------------------------------------------------------------------- budget model
def test_cost_ceilings_default_to_disabled():
    budget = DispatchBudget(max_dispatches=10)
    assert budget.is_exhausted(spent=0, spent_usd=10_000.0, spent_tokens=10**9) is False


def test_usd_ceiling_exhausts():
    budget = DispatchBudget(max_dispatches=100, max_usd=5.0)
    assert budget.is_exhausted(spent=1, spent_usd=4.99) is False
    assert budget.is_exhausted(spent=1, spent_usd=5.0) is True


def test_token_ceiling_exhausts():
    budget = DispatchBudget(max_dispatches=100, max_tokens=1000)
    assert budget.is_exhausted(spent=1, spent_tokens=999) is False
    assert budget.is_exhausted(spent=1, spent_tokens=1000) is True


def test_dispatch_cap_still_applies_independently():
    budget = DispatchBudget(max_dispatches=2, max_usd=1000.0)
    assert budget.is_exhausted(spent=2, spent_usd=0.0) is True


def test_legacy_single_argument_call_keeps_its_exact_meaning():
    # Every pre-existing call site passes only `spent`; the cost ceilings must never fire for them.
    budget = DispatchBudget(max_dispatches=10, max_usd=1.0, max_tokens=10)
    assert budget.is_exhausted(3) is False


def test_overspend_reason_names_the_binding_cap():
    assert "cost cap" in DispatchBudget(max_dispatches=100, max_usd=5.0).overspend_reason(1, 5.0)
    assert "token cap" in DispatchBudget(max_dispatches=100, max_tokens=10).overspend_reason(1, 0.0, 10)
    assert "dispatch cap" in DispatchBudget(max_dispatches=2).overspend_reason(2)
    assert DispatchBudget(max_dispatches=100).overspend_reason(1) == ""


def test_stop_event_reason_wins():
    STOP.set()
    try:
        assert "operator stop" in DispatchBudget(max_dispatches=100).overspend_reason(1)
    finally:
        STOP.clear()


# --------------------------------------------------------------------------- routing
def test_route_dispatch_reports_when_the_cost_ceiling_is_hit():
    budget = DispatchBudget(max_dispatches=100, max_phases=12, max_usd=5.0)
    assert route_dispatch(_state(budget, spent_usd=5.5)) == "report"


def test_route_dispatch_proceeds_below_the_cost_ceiling():
    budget = DispatchBudget(max_dispatches=100, max_phases=12, max_usd=5.0)
    assert route_dispatch(_state(budget, spent_usd=1.0)) != "report"


def test_route_dispatch_reports_when_the_token_ceiling_is_hit():
    budget = DispatchBudget(max_dispatches=100, max_phases=12, max_tokens=1000)
    assert route_dispatch(_state(budget, spent_tokens=1200)) == "report"


def test_integrate_stops_on_the_cost_ceiling_without_consulting_the_judge():
    # A hard stop must never be overridden by the continuation judge.
    budget = DispatchBudget(max_dispatches=100, max_phases=12, max_usd=1.0)
    assert integrate_next(_state(budget, spent_usd=2.0)) == "done"


def test_integrate_continues_below_the_cost_ceiling():
    budget = DispatchBudget(max_dispatches=100, max_phases=12, max_usd=10.0)
    assert integrate_next(_state(budget, spent_usd=1.0)) == "continue"


# --------------------------------------------------------------------------- propagation
def test_clean_result_carries_spend_to_the_master():
    result = CleanResult(dispatch_id="d1", status="no_finding", cost_usd=0.42, tokens=1234)
    assert result.cost_usd == 0.42
    assert result.tokens == 1234


def test_clean_result_spend_defaults_to_zero():
    result = CleanResult(dispatch_id="d1", status="no_finding")
    assert result.cost_usd == 0.0
    assert result.tokens == 0


def test_sdk_usage_tokens_sums_every_bucket():
    from a2pwn.sdk_agent import _usage_tokens

    usage = {
        "input_tokens": 10,
        "output_tokens": 20,
        "cache_creation_input_tokens": 5,
        "cache_read_input_tokens": 7,
    }
    assert _usage_tokens(usage) == 42


def test_sdk_usage_tokens_is_shape_defensive():
    from a2pwn.sdk_agent import _usage_tokens

    assert _usage_tokens(None) == 0
    assert _usage_tokens({"input_tokens": "not-a-number"}) == 0
