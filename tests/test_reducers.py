"""Reducers: curated append + monotone finding merge (never downgrades)."""

from _graphkit import make_finding
from a2pwn.budget import DispatchBudget
from a2pwn.graph import _merge_budget, append_curated, merge_findings


def test_append_curated_is_plain_concat():
    assert append_curated([1, 2], [3, 4]) == [1, 2, 3, 4]
    assert append_curated([], [1]) == [1]


def test_merge_findings_adds_new_key():
    a = make_finding(param="q")
    b = make_finding(param="name", vuln="sqli")
    merged = merge_findings([a], [b])
    assert {f.key for f in merged} == {a.key, b.key}


def test_merge_findings_promotes_candidate_to_confirmed():
    candidate = make_finding(confirmed=False)
    confirmed = make_finding(confirmed=True)
    merged = merge_findings([candidate], [confirmed])
    assert len(merged) == 1
    assert merged[0].confirmed is True


def test_merge_findings_never_downgrades_confirmed():
    confirmed = make_finding(confirmed=True)
    candidate = make_finding(confirmed=False)  # same key, weaker rank
    merged = merge_findings([confirmed], [candidate])
    assert len(merged) == 1
    assert merged[0].confirmed is True


def test_merge_findings_never_downgrades_independently_verified():
    verified = make_finding(confirmed=True, indep=True)
    confirmed = make_finding(confirmed=True, indep=False)  # same key, lower rank
    merged = merge_findings([verified], [confirmed])
    assert len(merged) == 1
    assert merged[0].independently_verified is True


def test_merge_budget_sums_spend_deltas():
    acc = DispatchBudget(max_dispatches=10, spent=2)
    folded = _merge_budget(_merge_budget(acc, DispatchBudget(spent=1)), DispatchBudget(spent=1))
    assert folded.spent == 4
    assert folded.max_dispatches == 10  # caps preserved from the accumulator


def test_merge_budget_latches_stop_flag():
    acc = DispatchBudget(spent=0)
    folded = _merge_budget(acc, DispatchBudget(spent=1, stopped=True))
    assert folded.stopped is True
