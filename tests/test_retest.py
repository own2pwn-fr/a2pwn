"""The retest cycle: re-check a baseline's findings and report the delta.

The load-bearing property is the *hedge*. A baseline finding that no longer reproduces is reported
as "fixed OR unreproducible", never flatly as fixed — a moved endpoint or an expired test credential
is indistinguishable from a real fix, and signing a live bug off as remediated is the one mistake
this command must not make.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from a2pwn.cli import _load_baseline, _retest_tasks, app
from a2pwn.models import Finding, FlowBatchRef
from a2pwn.report import Report, _retest_delta, render_markdown

runner = CliRunner()


def _finding(key_class: str, *, verified: bool = True) -> Finding:
    target = f"https://app.example.com/{key_class}"
    return Finding(
        key=Finding.make_key(key_class, target, "q"),
        vuln_class=key_class,
        severity="high",
        target=target,
        param="q",
        evidence=f"{key_class} proven",
        confirmed=True,
        independently_verified=verified,
        oracle_kind="differential",
        flow_batch=FlowBatchRef(workspace=f"{key_class}-poc", tag=key_class, flow_ids=[1]),
    )


# --------------------------------------------------------------------------- delta computation
def test_no_baseline_yields_no_retest_section():
    assert _retest_delta(None, [_finding("xss")], []) == {}


def test_a_reproved_finding_is_still_vulnerable():
    xss = _finding("xss")
    delta = _retest_delta([xss], [xss], [])
    assert delta["still_vulnerable"] == [xss.key]
    assert delta["fixed_or_unreproducible"] == []


def test_a_finding_that_no_longer_reproduces_is_hedged_not_declared_fixed():
    xss = _finding("xss")
    delta = _retest_delta([xss], [], [])
    assert delta["still_vulnerable"] == []
    assert delta["fixed_or_unreproducible"] == [xss.key]


def test_the_weaker_confirmed_tier_still_counts_as_vulnerable():
    # A finding the independent-verify dispatch could not replay is NOT evidence of a fix.
    xss = _finding("xss")
    delta = _retest_delta([xss], [], [xss])
    assert delta["still_vulnerable"] == [xss.key]


def test_new_findings_since_the_baseline_are_surfaced():
    old, new = _finding("xss"), _finding("sqli")
    delta = _retest_delta([old], [old, new], [])
    assert delta["new_since_baseline"] == [new.key]


def test_baseline_count_is_reported():
    delta = _retest_delta([_finding("xss"), _finding("sqli")], [], [])
    assert delta["baseline_findings"] == 2


# --------------------------------------------------------------------------- rendering
def test_markdown_renders_the_delta_with_the_hedge_spelled_out():
    xss = _finding("xss")
    report = Report(engagement="t", retest=_retest_delta([xss], [], []))
    body = render_markdown(report)
    assert "Retest delta" in body
    assert "Fixed or no longer reproducible" in body
    assert "human sign-off" in body


def test_a_non_retest_report_has_no_retest_section():
    assert "Retest delta" not in render_markdown(Report(engagement="t"))


# --------------------------------------------------------------------------- baseline loading
def test_loads_a_report_json_by_path(tmp_path):
    xss = _finding("xss")
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps({"engagement": "prior", "findings": [json.loads(xss.model_dump_json())]}),
        encoding="utf-8",
    )
    findings, data = _load_baseline(str(path))
    assert [f.key for f in findings] == [xss.key]
    assert data["engagement"] == "prior"


def test_loads_both_tiers_from_the_baseline(tmp_path):
    verified, confirmed = _finding("xss"), _finding("race", verified=False)
    path = tmp_path / "report.json"
    path.write_text(
        json.dumps(
            {
                "findings": [json.loads(verified.model_dump_json())],
                "confirmed_findings": [json.loads(confirmed.model_dump_json())],
            }
        ),
        encoding="utf-8",
    )
    findings, _ = _load_baseline(str(path))
    assert {f.key for f in findings} == {verified.key, confirmed.key}


def test_an_unknown_baseline_is_rejected():
    with pytest.raises(Exception, match="no such baseline"):
        _load_baseline("definitely-not-a-run-or-a-path")


# --------------------------------------------------------------------------- task seeding
def test_one_seeded_task_per_baseline_finding():
    # Seeding concrete tasks (rather than hoping the planner derives them) is what stops a baseline
    # finding from being quietly skipped because the planner judged it uninteresting.
    findings = [_finding("xss"), _finding("sqli")]
    tasks = _retest_tasks(findings)
    assert len(tasks) == 2
    assert {t.target for t in tasks} == {f.target for f in findings}


def test_seeded_tasks_carry_the_baseline_key_and_oracle():
    task = _retest_tasks([_finding("xss")])[0]
    assert any(h.startswith("baseline_key=") for h in task.hints)
    assert "oracle=differential" in task.hints
    assert task.intent == "verify"


def test_seeded_task_asks_for_bypasses_of_a_shallow_fix():
    task = _retest_tasks([_finding("xss")])[0]
    assert "bypasses" in task.task


# --------------------------------------------------------------------------- CLI wiring
def test_retest_refuses_a_baseline_with_no_findings(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"engagement": "prior", "findings": []}), encoding="utf-8")
    result = runner.invoke(app, ["retest", "--baseline", str(path), "--yes"])
    assert result.exit_code == 2
    assert "no findings to retest" in result.output


def test_retest_refuses_when_the_baseline_records_no_targets(tmp_path):
    xss = _finding("xss")
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"findings": [json.loads(xss.model_dump_json())]}), encoding="utf-8")
    result = runner.invoke(app, ["retest", "--baseline", str(path), "--yes"])
    assert result.exit_code == 2
    assert "no targets" in result.output.lower()
