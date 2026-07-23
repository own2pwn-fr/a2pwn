"""CLI authorization gate + backend parsing + burpwn-missing abort (RUNTIME audit regressions)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from a2pwn import cli
from a2pwn.config import RoleModels
from a2pwn.report import Report

runner = CliRunner()


def _seed_prior_run(tmp_path: Path, name: str, *, targets, objective, verified=0, confirmed=0) -> Path:
    """Write a minimal prior-run report.json under XDG_DATA_HOME so list/resume can discover it."""
    run_dir = tmp_path / "a2pwn" / "runs" / name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.json").write_text(
        json.dumps(
            {
                "engagement": name,
                "findings": [{"vuln_class": "xss"}] * verified,
                "confirmed_findings": [{"vuln_class": "sqli"}] * confirmed,
                "stats": {"by_severity": {"high": verified}},
                "objective": objective,
                "targets": targets,
            }
        )
    )
    return run_dir


def _text(res) -> str:
    """Combined stdout+stderr, robust to Click's stderr-capture split (>=8.2 separates them)."""
    out = res.output or ""
    try:
        out += res.stderr or ""
    except (ValueError, AttributeError):
        pass  # older Click merges stderr into output already
    return out


def _stub_run(monkeypatch, sink: dict):
    async def _fake_run(cfg, objective, thread_id, *, tui=False, formats=None):
        sink["cfg"] = cfg
        sink["objective"] = objective
        sink["thread_id"] = thread_id
        sink["tui"] = tui
        sink["formats"] = formats
        return Report(engagement="a2pwn")

    monkeypatch.setattr(cli, "run_engagement", _fake_run)
    monkeypatch.setattr(cli, "ensure_burpwn_available", lambda: None)


def test_declined_authorization_exits_2_and_never_runs(monkeypatch):
    sink: dict = {}
    _stub_run(monkeypatch, sink)
    res = runner.invoke(cli.app, ["run", "-t", "https://app.example.com", "-o", "audit"], input="no\n")
    assert res.exit_code == 2
    assert "cfg" not in sink  # run_engagement never invoked


def test_yes_runs_engagement(monkeypatch, tmp_path):
    sink: dict = {}
    _stub_run(monkeypatch, sink)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))  # keep artifacts out of the real home dir
    res = runner.invoke(cli.app, ["run", "-t", "https://app.example.com", "-o", "audit", "--yes"])
    assert res.exit_code == 0, res.output
    assert sink["objective"] == "audit"
    assert sink["cfg"].engagement.targets == ["https://app.example.com"]
    assert sink["cfg"].step_through is False


def test_step_through_flag_threads_into_config(monkeypatch, tmp_path):
    sink: dict = {}
    _stub_run(monkeypatch, sink)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    res = runner.invoke(
        cli.app,
        ["run", "-t", "https://app.example.com", "-o", "audit", "--yes", "--step-through"],
    )
    assert res.exit_code == 0, res.output
    assert sink["cfg"].step_through is True


def test_burpwn_missing_aborts_before_run(monkeypatch):
    sink: dict = {}
    _stub_run(monkeypatch, sink)

    def _raise():
        raise cli.BurpwnMissingError("burpwn is not installed or not on PATH.")

    monkeypatch.setattr(cli, "ensure_burpwn_available", _raise)
    res = runner.invoke(cli.app, ["run", "-t", "https://app.example.com", "-o", "audit", "--yes"])
    assert res.exit_code == 1
    assert "burpwn is not installed" in _text(res)
    assert "cfg" not in sink  # aborted before spending any model calls


def test_burpwn_missing_aborts_before_authorization_gate(monkeypatch):
    """The burpwn preflight runs BEFORE the auth gate: a missing binary exits 1 (not the 2 an
    interactive decline would give), and the operator is never asked to acknowledge the disclaimer."""
    sink: dict = {}
    _stub_run(monkeypatch, sink)

    def _raise():
        raise cli.BurpwnMissingError("burpwn is not installed or not on PATH.")

    monkeypatch.setattr(cli, "ensure_burpwn_available", _raise)
    # No --yes, and an interactive decline queued: if the gate ran first this would be exit 2.
    res = runner.invoke(cli.app, ["run", "-t", "https://app.example.com", "-o", "audit"], input="no\n")
    assert res.exit_code == 1
    assert "burpwn is not installed" in _text(res)
    assert "I AGREE" not in _text(res)  # gate never shown


# --- backend parsing -------------------------------------------------------- #
def test_parse_backend_provider_model():
    bc = cli._parse_backend("codex:gpt-5")
    assert (bc.provider, bc.model) == ("codex", "gpt-5")


def test_parse_backend_bare_model_defaults_subscription():
    bc = cli._parse_backend("sonnet")
    assert bc.provider == "claude-code"
    assert bc.model == "sonnet"


def test_build_models_no_overrides_is_default():
    assert cli._build_models(None, None) == RoleModels()


def test_build_models_executor_override():
    rm = cli._build_models("openai:gpt-4o", None)
    assert rm.executor.provider == "openai"
    assert rm.executor.model == "gpt-4o"


# --- run plan + format flag ------------------------------------------------- #
def test_run_plan_printed_and_format_threaded(monkeypatch, tmp_path):
    sink: dict = {}
    _stub_run(monkeypatch, sink)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    res = runner.invoke(
        cli.app,
        [
            "run",
            "-t",
            "https://app.example.com",
            "-o",
            "audit",
            "--yes",
            "--active-exploit",
            "--format",
            "md,json",
        ],
    )
    assert res.exit_code == 0, res.output
    # compact run-plan line is printed for traceability under --yes, before the run.
    assert "[run-plan]" in _text(res)
    assert "active_exploit=ON" in _text(res)
    # the parsed format list is threaded into run_engagement.
    assert sink["formats"] == ["md", "json"]
    assert sink["cfg"].max_wall_secs is None


def test_max_wall_secs_threads_into_config(monkeypatch, tmp_path):
    sink: dict = {}
    _stub_run(monkeypatch, sink)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    res = runner.invoke(
        cli.app,
        ["run", "-t", "https://app.example.com", "-o", "audit", "--yes", "--max-wall-secs", "900"],
    )
    assert res.exit_code == 0, res.output
    assert sink["cfg"].max_wall_secs == 900


# --- list ------------------------------------------------------------------- #
def test_list_empty(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    res = runner.invoke(cli.app, ["list"])
    assert res.exit_code == 0
    assert "No runs found" in _text(res)


def test_list_shows_prior_run(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    _seed_prior_run(
        tmp_path,
        "acme",
        targets=["https://app.example.com"],
        objective="audit the shop",
        verified=2,
        confirmed=1,
    )
    res = runner.invoke(cli.app, ["list"])
    assert res.exit_code == 0, res.output
    out = _text(res)
    assert "acme" in out
    assert "audit the shop" in out


# --- resume ----------------------------------------------------------------- #
def test_resume_uses_prior_metadata(monkeypatch, tmp_path):
    sink: dict = {}
    _stub_run(monkeypatch, sink)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    _seed_prior_run(tmp_path, "acme", targets=["https://app.example.com"], objective="audit the shop")
    res = runner.invoke(cli.app, ["resume", "--name", "acme", "--yes"])
    assert res.exit_code == 0, res.output
    assert "Resuming run 'acme'" in _text(res)
    # objective + targets recovered from the prior run's report.json, threaded into the re-drive.
    assert sink["objective"] == "audit the shop"
    assert sink["thread_id"] == "acme"
    assert sink["cfg"].engagement.targets == ["https://app.example.com"]


def test_resume_objective_override(monkeypatch, tmp_path):
    sink: dict = {}
    _stub_run(monkeypatch, sink)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    _seed_prior_run(tmp_path, "acme", targets=["https://app.example.com"], objective="old")
    res = runner.invoke(cli.app, ["resume", "--name", "acme", "-o", "new objective", "--yes"])
    assert res.exit_code == 0, res.output
    assert sink["objective"] == "new objective"


def test_resume_unknown_run_exits_2(monkeypatch, tmp_path):
    sink: dict = {}
    _stub_run(monkeypatch, sink)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    res = runner.invoke(cli.app, ["resume", "--name", "ghost", "--yes"])
    assert res.exit_code == 2
    assert "cfg" not in sink  # never reached run_engagement


# --- doctor ----------------------------------------------------------------- #
def test_doctor_missing_burpwn_exits_1(monkeypatch):
    monkeypatch.setattr(cli.shutil, "which", lambda _: None)
    res = runner.invoke(cli.app, ["doctor"])
    assert res.exit_code == 1
    out = _text(res)
    assert "not found on PATH" in out
    assert "a2pwn install-burpwn" in out


def test_doctor_ok_exits_0(monkeypatch):
    from a2pwn.burpwn import BurpwnClient

    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/local/bin/burpwn")
    monkeypatch.setattr(BurpwnClient, "cli_doctor", staticmethod(lambda: {"ok": True, "namespaces": "ok"}))
    res = runner.invoke(cli.app, ["doctor"])
    assert res.exit_code == 0, _text(res)
    out = _text(res)
    assert "burpwn on PATH" in out
    assert "ready to run" in out


def test_doctor_prerequisites_incomplete_exits_1(monkeypatch):
    from a2pwn.burpwn import BurpwnClient

    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/local/bin/burpwn")
    monkeypatch.setattr(BurpwnClient, "cli_doctor", staticmethod(lambda: {"ok": False, "userns": "missing"}))
    res = runner.invoke(cli.app, ["doctor"])
    assert res.exit_code == 1
    assert "prerequisites incomplete" in _text(res)


# --- install-burpwn --------------------------------------------------------- #
def test_install_burpwn_already_present_is_noop(monkeypatch):
    from a2pwn import installer

    monkeypatch.setattr(cli.shutil, "which", lambda _: "/usr/local/bin/burpwn")
    called: dict = {}
    monkeypatch.setattr(installer, "install_burpwn", lambda *a, **k: called.setdefault("ran", True))
    res = runner.invoke(cli.app, ["install-burpwn"])
    assert res.exit_code == 0
    assert "already installed" in _text(res)
    assert "ran" not in called  # nothing downloaded


def test_install_burpwn_happy_path_warns_when_off_path(monkeypatch, tmp_path):
    from a2pwn import installer

    dest = tmp_path / "somewhere" / "bin"
    monkeypatch.setattr(cli.shutil, "which", lambda _: None)  # not yet installed
    monkeypatch.setattr(installer, "release_triple", lambda *a, **k: "x86_64-unknown-linux-gnu")
    monkeypatch.setattr(installer, "install_burpwn", lambda target, **k: target / "burpwn")
    monkeypatch.setattr(installer, "on_path", lambda d: False)
    res = runner.invoke(cli.app, ["install-burpwn", "--dest", str(dest)])
    assert res.exit_code == 0, _text(res)
    out = _text(res)
    assert "installed burpwn" in out
    assert "not on your PATH" in out
    assert "a2pwn doctor" in out


def test_install_burpwn_reports_install_error(monkeypatch):
    from a2pwn import installer

    monkeypatch.setattr(cli.shutil, "which", lambda _: None)
    monkeypatch.setattr(installer, "release_triple", lambda *a, **k: "x86_64-unknown-linux-gnu")

    def _boom(*a, **k):
        raise installer.InstallError("failed to download …")

    monkeypatch.setattr(installer, "install_burpwn", _boom)
    res = runner.invoke(cli.app, ["install-burpwn"])
    assert res.exit_code == 1
    assert "Install failed" in _text(res)
