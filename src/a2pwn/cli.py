"""``uvx a2pwn run`` — assemble config, print the ToS disclaimer, drive the engagement.

a2pwn runs on the operator's own machine, using their own Claude Code login, against targets they
are authorized to test. The command refuses to start until authorization is acknowledged (``--yes``
or an interactive ``I AGREE``), then streams the run and writes the markdown report + per-workspace
HAR captures to the run directory.
"""

from __future__ import annotations

import asyncio
import logging
import sys

import typer

from a2pwn.config import A2pwnConfig, BackendConfig, EngagementSpec, RoleModels
from a2pwn.report import render_markdown
from a2pwn.runtime import BurpwnMissingError, ensure_burpwn_available, run_engagement, run_out_dir

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="Autonomous, evidence-grounded web-pentest orchestrator.")


@app.callback()
def _root() -> None:
    """a2pwn — dispatch adversarially-verified sub-agents at a target through the burpwn sandbox."""

_DISCLAIMER = """\
================================ a2pwn — authorization ================================
a2pwn is an autonomous web-pentest orchestrator. It drives REAL network traffic against
the targets you name and will attempt to prove exploitable vulnerabilities.

  * Only run this against systems you own or are EXPLICITLY authorized to test.
  * Unauthorized testing is illegal in most jurisdictions.
  * a2pwn runs on your machine using your own Claude Code subscription login; using a
    subscription for automated agent work is a gray area — you accept that risk.

By continuing you confirm you have written authorization for every in-scope target.
=======================================================================================
"""


def _parse_backend(spec: str) -> BackendConfig:
    """``model`` or ``provider:model`` — provider defaults to the subscription backend."""
    if ":" in spec:
        provider, model = spec.split(":", 1)
        return BackendConfig(provider=provider, model=model)  # type: ignore[arg-type]
    return BackendConfig(model=spec)


def _build_models(executor_model: str | None, verifier_model: str | None) -> RoleModels:
    overrides: dict = {}
    if executor_model:
        overrides["executor"] = _parse_backend(executor_model)
    if verifier_model:
        overrides["verifier"] = _parse_backend(verifier_model)
    return RoleModels(**overrides)


@app.command()
def run(
    target: list[str] = typer.Option(..., "--target", "-t", help="In-scope target URL/host (repeatable)."),
    objective: str = typer.Option(..., "--objective", "-o", help="Engagement objective for the planner."),
    name: str = typer.Option("a2pwn", "--name", help="Engagement + burpwn session name (thread id)."),
    active_exploit: bool = typer.Option(False, "--active-exploit", help="Allow active exploitation without a per-dispatch pause."),
    step_through: bool = typer.Option(False, "--step-through", help="Interactively approve EACH dispatch (default: upfront-only approval)."),
    dos: bool = typer.Option(False, "--dos", help="Advisory: signal to the planner that DoS-class techniques are permitted (prompt-only, not tool-enforced)."),
    oob_listener: str | None = typer.Option(None, "--oob-listener", help="External OOB collaborator base (host:port)."),
    checkpoint_uri: str | None = typer.Option(None, "--checkpoint-uri", help="Postgres URI (defaults to on-box SQLite)."),
    executor_model: str | None = typer.Option(None, "--executor-model", help="Override the executor role model."),
    verifier_model: str | None = typer.Option(None, "--verifier-model", help="Override the verifier (Opus-class) role model."),
    max_phases: int = typer.Option(12, "--max-phases", help="Hard cap on master planning phases."),
    max_dispatches: int = typer.Option(200, "--max-dispatches", help="Global dispatch budget ceiling."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Non-interactively acknowledge authorization."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose telemetry logging."),
    plain: bool = typer.Option(False, "--plain", help="Disable the live TUI; log telemetry instead."),
) -> None:
    """Run an autonomous, adversarially-verified engagement against the given targets."""
    # The live TUI owns the terminal, so only enable it on an interactive stdout that isn't verbose
    # or step-through (which need the raw log / an input prompt).
    use_tui = not plain and not verbose and not step_through and sys.stdout.isatty()
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if use_tui:  # silence the log stream so it doesn't fight the Live view
        logging.getLogger("a2pwn").setLevel(logging.WARNING)
    # Third-party debug logs (aiosqlite/httpx/checkpoint serde) drown the telemetry — cap them.
    for noisy in ("aiosqlite", "httpx", "httpcore", "urllib3", "asyncio",
                  "langgraph.checkpoint.serde.jsonplus", "claude_agent_sdk"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    typer.echo(_DISCLAIMER)
    ack = yes
    if not ack:
        reply = typer.prompt("Type 'I AGREE' to confirm authorization", default="")
        ack = reply.strip().lower() in ("i agree", "yes", "y")
    if not ack:
        typer.echo("Authorization not confirmed. Aborting.", err=True)
        raise typer.Exit(2)

    # Fail fast on the most common first-run failure before constructing models or spending LLM calls.
    try:
        ensure_burpwn_available()
    except BurpwnMissingError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc

    engagement = EngagementSpec(
        name=name,
        targets=target,
        in_scope=list(target),
        authorization_acknowledged=ack,
        active_exploit_allowed=active_exploit,
        dos_allowed=dos,
        oob_listener=oob_listener,
        session=name,
    )

    try:
        cfg = A2pwnConfig(
            engagement=engagement,
            models=_build_models(executor_model, verifier_model),
            max_phases=max_phases,
            max_dispatches=max_dispatches,
            checkpoint_uri=checkpoint_uri,
            disclaimer_ack=ack,
            step_through=step_through,
        )
    except ValueError as exc:
        typer.echo(f"Invalid configuration: {exc}", err=True)
        raise typer.Exit(2) from exc

    try:
        report = asyncio.run(run_engagement(cfg, objective, thread_id=name, tui=use_tui))
    except BurpwnMissingError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc

    out_dir = run_out_dir(cfg, name)
    md_path = out_dir / "report.md"
    md_path.write_text(render_markdown(report), encoding="utf-8")

    if use_tui:
        from a2pwn import tui

        tui.render_summary(report, str(out_dir))
    else:
        typer.echo("")
        typer.echo(f"Report:  {md_path}")
        for har in report.har_paths:
            typer.echo(f"HAR:     {har}")
        typer.echo(f"Findings (independently verified): {len(report.findings)}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
