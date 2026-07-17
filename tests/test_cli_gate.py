"""CLI authorization gate + backend parsing + burpwn-missing abort (RUNTIME audit regressions)."""

from __future__ import annotations

from typer.testing import CliRunner

from a2pwn import cli
from a2pwn.config import RoleModels
from a2pwn.report import Report

runner = CliRunner()


def _text(res) -> str:
    """Combined stdout+stderr, robust to Click's stderr-capture split (>=8.2 separates them)."""
    out = res.output or ""
    try:
        out += res.stderr or ""
    except (ValueError, AttributeError):
        pass  # older Click merges stderr into output already
    return out


def _stub_run(monkeypatch, sink: dict):
    async def _fake_run(cfg, objective, thread_id, *, tui=False):
        sink["cfg"] = cfg
        sink["objective"] = objective
        sink["thread_id"] = thread_id
        sink["tui"] = tui
        return Report(engagement="a2pwn")

    monkeypatch.setattr(cli, "run_engagement", _fake_run)
    monkeypatch.setattr(cli, "ensure_burpwn_available", lambda: None)


def test_declined_authorization_exits_2_and_never_runs(monkeypatch):
    sink: dict = {}
    _stub_run(monkeypatch, sink)
    res = runner.invoke(
        cli.app, ["run", "-t", "https://app.example.com", "-o", "audit"], input="no\n"
    )
    assert res.exit_code == 2
    assert "cfg" not in sink  # run_engagement never invoked


def test_yes_runs_engagement(monkeypatch, tmp_path):
    sink: dict = {}
    _stub_run(monkeypatch, sink)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))  # keep artifacts out of the real home dir
    res = runner.invoke(
        cli.app, ["run", "-t", "https://app.example.com", "-o", "audit", "--yes"]
    )
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
    res = runner.invoke(
        cli.app, ["run", "-t", "https://app.example.com", "-o", "audit", "--yes"]
    )
    assert res.exit_code == 1
    assert "burpwn is not installed" in _text(res)
    assert "cfg" not in sink  # aborted before spending any model calls


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
