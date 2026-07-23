"""CVSS 3.1 base-score computation — never trust the model's own arithmetic, re-derive it.

Reference scores cross-checked against the FIRST.org CVSS 3.1 calculator and against the vectors
actually used in a real pentest report this engine produced (the values are well-known reference
points: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N == 9.1, a textbook "trivial full-impact RCE" vector)."""

from __future__ import annotations

from a2pwn.cvss import parse_cvss31


def test_none_and_empty_vector_return_none():
    assert parse_cvss31(None) is None
    assert parse_cvss31("") is None


def test_unparseable_vector_returns_none_not_a_guess():
    assert parse_cvss31("not a real vector") is None
    assert parse_cvss31("AV:N/AC:L") is None  # incomplete


def test_full_prefixed_vector_parses():
    r = parse_cvss31("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
    assert r is not None
    assert r.base_score == 9.1
    assert r.severity == "Critical"


def test_bare_vector_without_version_prefix_parses():
    r = parse_cvss31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")
    assert r is not None
    assert r.base_score == 9.1


def test_high_severity_vectors():
    # Missing-auth destructive DELETE: integrity-only impact.
    r = parse_cvss31("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N")
    assert r.base_score == 7.5
    assert r.severity == "High"

    # JWT signature bypass with a conservative AC:H (full impact needs a valid identity too).
    r = parse_cvss31("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N")
    assert r.base_score == 7.4
    assert r.severity == "High"


def test_medium_severity_info_disclosure_vector():
    r = parse_cvss31("AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N")
    assert r.base_score == 5.3
    assert r.severity == "Medium"


def test_low_severity_clickjacking_vector():
    r = parse_cvss31("AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N")
    assert r.base_score == 3.1
    assert r.severity == "Low"


def test_zero_impact_vector_scores_none():
    r = parse_cvss31("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert r.base_score == 0.0
    assert r.severity == "None"


def test_changed_scope_vector_parses_and_scores_higher():
    unchanged = parse_cvss31("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    changed = parse_cvss31("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
    assert unchanged is not None and changed is not None
    assert changed.base_score >= unchanged.base_score
    assert changed.severity == "Critical"


def test_vector_is_case_and_whitespace_tolerant_via_stripping():
    r = parse_cvss31("  AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N  ")
    assert r is not None
    assert r.base_score == 9.1
