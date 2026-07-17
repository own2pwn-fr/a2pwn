"""Reducers: curated append + monotone finding merge (never downgrades)."""

from _graphkit import make_finding
from a2pwn.graph import _merge_attempts, append_curated, merge_findings


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




def test_merge_attempts_sums_per_key_counts():
    # Parallel verify Sends for the same finding key accumulate; distinct keys coexist.
    left = {"k1": 1}
    merged = _merge_attempts(_merge_attempts(left, {"k1": 1}), {"k2": 1})
    assert merged == {"k1": 2, "k2": 1}
    # Identity element (empty) is a no-op and never mutates the accumulator.
    assert _merge_attempts({}, {"k1": 1}) == {"k1": 1}
    assert _merge_attempts({"k1": 1}, {}) == {"k1": 1}
