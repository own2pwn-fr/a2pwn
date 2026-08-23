"""CLI wiring for engagement files, exclusions and the real spend ceilings.

``run_engagement``/``ensure_burpwn_available`` are stubbed exactly as in ``test_cli_gate`` — no test
here may spawn burpwn or spend a model call. What is asserted is the *assembled config*: the run
plan is printed BEFORE the authorization gate, so it is the last line of defence against testing
something the client did not authorise, and the carve-outs it shows must be the ones actually
threaded into the engagement.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from a2pwn import cli
from a2pwn.report import Report

runner = CliRunner()


@pytest.fixture
def captured(monkeypatch, tmp_path):
    """Stub the engagement runner; yields the dict the CLI's assembled config lands in."""
    sink: dict = {}

    async def _fake_run(cfg, objective, thread_id, **kwargs):
        sink["cfg"] = cfg
        sink["objective"] = objective
        sink.update(kwargs)
        return Report(engagement=cfg.engagement.name)

    monkeypatch.setattr(cli, "run_engagement", _fake_run)
    monkeypatch.setattr(cli, "ensure_burpwn_available", lambda: None)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    return sink


def _engagement_file(tmp_path, extra: str = "") -> str:
    path = tmp_path / "engagement.yaml"
    path.write_text(
        "name: acme\n"
        "objective: audit the shop\n"
        "targets: [https://app.example.com]\n"
        "exclude: [legacy.example.com, /admin/billing]\n" + extra,
        encoding="utf-8",
    )
    return str(path)


def _text(res) -> str:
    out = res.output or ""
    try:
        out += res.stderr or ""
    except (ValueError, AttributeError):
        pass
    return out


# --------------------------------------------------------------------------- config file
def test_config_file_supplies_targets_and_objective(captured, tmp_path):
    result = runner.invoke(cli.app, ["run", "--config", _engagement_file(tmp_path), "--yes"])
    assert result.exit_code == 0, _text(result)
    assert captured["cfg"].engagement.targets == ["https://app.example.com"]
    assert captured["objective"] == "audit the shop"


def test_exclusions_reach_the_engagement(captured, tmp_path):
    runner.invoke(cli.app, ["run", "--config", _engagement_file(tmp_path), "--yes"])
    assert captured["cfg"].engagement.exclude == ["legacy.example.com", "/admin/billing"]


def test_identities_reach_the_engagement(captured, tmp_path):
    path = _engagement_file(
        tmp_path,
        "identities:\n"
        "  - {name: alice, headers: {Authorization: 'Bearer t'}}\n"
        "  - {name: anon, anonymous: true}\n",
    )
    runner.invoke(cli.app, ["run", "--config", path, "--yes"])
    identities = captured["cfg"].engagement.identities
    assert [i.name for i in identities] == ["alice", "anon"]
    assert identities[1].anonymous is True


def test_run_plan_shows_the_exclusions(captured, tmp_path):
    # The operator must SEE the carve-outs before acknowledging authorization.
    result = runner.invoke(cli.app, ["run", "--config", _engagement_file(tmp_path), "--yes"])
    assert "legacy.example.com" in _text(result)


def test_explicit_flag_overrides_the_file(captured, tmp_path):
    runner.invoke(
        cli.app, ["run", "--config", _engagement_file(tmp_path), "--objective", "only the API", "--yes"]
    )
    assert captured["objective"] == "only the API"


def test_a_default_valued_flag_does_not_clobber_the_file(captured, tmp_path):
    # --max-phases was never typed, so the file's scope/caps must survive untouched.
    path = _engagement_file(tmp_path, "max_phases: 3\n")
    runner.invoke(cli.app, ["run", "--config", path, "--yes"])
    assert captured["cfg"].max_phases == 3


# --------------------------------------------------------------------------- flags alone
def test_exclude_flag_works_without_a_config_file(captured):
    runner.invoke(
        cli.app,
        [
            "run",
            "--target",
            "https://app.example.com",
            "--objective",
            "audit",
            "--exclude",
            "legacy.example.com",
            "--yes",
        ],
    )
    assert captured["cfg"].engagement.exclude == ["legacy.example.com"]


def test_spend_and_rate_ceilings_reach_the_config(captured):
    runner.invoke(
        cli.app,
        [
            "run",
            "--target",
            "https://app.example.com",
            "--objective",
            "audit",
            "--max-usd",
            "25",
            "--max-tokens",
            "1000000",
            "--max-rps",
            "5",
            "--fuzz-max-requests",
            "100",
            "--yes",
        ],
    )
    cfg = captured["cfg"]
    assert cfg.max_usd == 25
    assert cfg.max_tokens == 1_000_000
    assert cfg.max_rps == 5
    assert cfg.fuzz_max_requests == 100


# --------------------------------------------------------------------------- errors
def test_missing_targets_is_a_clean_error(captured):
    result = runner.invoke(cli.app, ["run", "--objective", "audit", "--yes"])
    assert result.exit_code == 2
    assert "No targets" in _text(result)
    assert "cfg" not in captured  # nothing ran


def test_missing_objective_is_a_clean_error(captured):
    result = runner.invoke(cli.app, ["run", "--target", "https://app.example.com", "--yes"])
    assert result.exit_code == 2
    assert "No objective" in _text(result)


def test_a_typo_in_the_engagement_file_aborts_before_anything_runs(captured, tmp_path):
    # A silently-ignored `exlude:` would widen the tested scope — the exact failure the file exists
    # to prevent, so it must abort rather than warn.
    path = tmp_path / "bad.yaml"
    path.write_text("exlude: [legacy.example.com]\n", encoding="utf-8")
    result = runner.invoke(cli.app, ["run", "--config", str(path), "--yes"])
    assert result.exit_code == 2
    assert "Invalid engagement file" in _text(result)
    assert "cfg" not in captured


def _prior_run(monkeypatch, **over):
    """Stub `list_runs` with one finished engagement's recorded metadata."""
    info = {
        "thread_id": "acme-run",
        "targets": ["https://app.example.com"],
        "in_scope": ["https://app.example.com"],
        "exclude": ["legacy.example.com", "/admin/billing"],
        "identity_names": [],
        "objective": "audit the shop",
    }
    info.update(over)
    monkeypatch.setattr(cli, "list_runs", lambda: [info])


def test_resume_restores_the_scope_carve_outs(captured, monkeypatch):
    """Regression: `resume` rebuilt the EngagementSpec from `targets` alone.

    Every `--exclude` carve-out was dropped, so a resumed run re-authorised exactly the hosts and
    paths the client had put off-limits — the one direction a scope mistake must never go.
    """
    _prior_run(monkeypatch)

    result = runner.invoke(cli.app, ["resume", "--name", "acme-run", "--yes", "--plain"])

    assert result.exit_code == 0, result.output
    eng = captured["cfg"].engagement
    assert eng.exclude == ["legacy.example.com", "/admin/billing"]
    assert eng.in_scope == ["https://app.example.com"]


def test_resume_warns_when_identities_cannot_be_restored(captured, monkeypatch):
    """Credentials are never written to report.json, so a resume without --config loses the
    authenticated surface. That has to be said out loud, not discovered in an empty report."""
    _prior_run(monkeypatch, identity_names=["alice", "bob"])

    result = runner.invoke(cli.app, ["resume", "--name", "acme-run", "--yes", "--plain"])

    assert result.exit_code == 0, result.output
    assert "alice, bob" in result.output
    assert "--config" in result.output


def test_resume_restores_identities_from_the_engagement_file(captured, monkeypatch, tmp_path):
    _prior_run(monkeypatch, identity_names=["alice"])
    path = _engagement_file(
        tmp_path,
        "identities:\n  - name: alice\n    headers: {Authorization: 'Bearer t'}\n",
    )

    result = runner.invoke(cli.app, ["resume", "--name", "acme-run", "--config", path, "--yes", "--plain"])

    assert result.exit_code == 0, result.output
    assert [i.name for i in captured["cfg"].engagement.identities] == ["alice"]
