"""``uvx a2pwn run`` — assemble config, print the ToS disclaimer, drive the engagement.

a2pwn runs on the operator's own machine, using their own Claude Code login, against targets they
are authorized to test. The command refuses to start until authorization is acknowledged (``--yes``
or an interactive ``I AGREE``), then streams the run and writes the markdown report + per-workspace
HAR captures to the run directory.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import sys
from datetime import datetime
from pathlib import Path

import typer

from a2pwn.config import A2pwnConfig, BackendConfig, EngagementSpec, RoleModels
from a2pwn.runtime import (
    BurpwnMissingError,
    ensure_burpwn_available,
    list_runs,
    run_engagement,
    run_out_dir,
)

_SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

app = typer.Typer(
    add_completion=False, no_args_is_help=True, help="Autonomous, evidence-grounded web-pentest orchestrator."
)


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


def _model_label(bc: BackendConfig) -> str:
    return f"{bc.provider}:{bc.model or 'default'}"


def _parse_formats(spec: str) -> list[str]:
    """Comma list -> normalized format tokens (md,json,sarif,html)."""
    return [tok.strip().lower() for tok in (spec or "").split(",") if tok.strip()]


def _truncate(text: str, limit: int) -> str:
    text = str(text or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _use_tui(*, plain: bool, verbose: bool, step_through: bool = False) -> bool:
    # The live TUI owns the terminal, so only enable it on an interactive stdout that isn't verbose
    # or step-through (which need the raw log / an input prompt).
    return not plain and not verbose and not step_through and sys.stdout.isatty()


def _init_logging(*, verbose: bool, use_tui: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if use_tui:  # silence the log stream so it doesn't fight the Live view
        logging.getLogger("a2pwn").setLevel(logging.WARNING)
    for noisy in (
        "aiosqlite",
        "httpx",
        "httpcore",
        "urllib3",
        "asyncio",
        "langgraph.checkpoint.serde.jsonplus",
        "claude_agent_sdk",
    ):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _print_run_plan(cfg: A2pwnConfig, objective: str, out_dir, *, compact: bool) -> None:
    """Show the operator exactly what will run BEFORE the authorization gate. ``compact`` (used with
    ``--yes``) collapses it to a single traceable log line for non-interactive automation."""
    eng = cfg.engagement
    ae = eng.active_exploit_allowed
    exec_lbl = _model_label(cfg.models.executor)
    ver_lbl = _model_label(cfg.models.verifier)
    if compact:
        typer.echo(
            f"[run-plan] targets={','.join(eng.targets)} "
            f"active_exploit={'ON' if ae else 'off'} dos={'on' if eng.dos_allowed else 'off'} "
            f"executor={exec_lbl} verifier={ver_lbl} "
            f"max_phases={cfg.max_phases} max_dispatches={cfg.max_dispatches} "
            f"executor_max_turns={cfg.executor_max_turns} out={out_dir}"
        )
        return
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="dim", no_wrap=True)
    grid.add_column()
    grid.add_row("targets", ", ".join(eng.targets))
    grid.add_row("objective", _truncate(objective, 88))
    grid.add_row(
        "active-exploit",
        Text("ON", style="bold red") if ae else Text("off", style="green"),
    )
    grid.add_row("dos", "on" if eng.dos_allowed else "off")
    grid.add_row("executor", exec_lbl)
    grid.add_row("verifier", ver_lbl)
    grid.add_row(
        "caps",
        f"max_phases={cfg.max_phases}  max_dispatches={cfg.max_dispatches}  "
        f"executor_max_turns={cfg.executor_max_turns}"
        + (f"  max_wall_secs={cfg.max_wall_secs}" if cfg.max_wall_secs else ""),
    )
    grid.add_row("output", str(out_dir))
    Console().print(Panel(grid, title="Run plan", title_align="left", border_style="magenta"))


def _authorize(yes: bool) -> bool:
    """Print the ToS disclaimer and take the one-time authorization acknowledgement."""
    typer.echo(_DISCLAIMER)
    if yes:
        return True
    reply = typer.prompt("Type 'I AGREE' to confirm authorization", default="")
    return reply.strip().lower() in ("i agree", "yes", "y")


def _emit_report(report, cfg: A2pwnConfig, thread_id: str) -> None:
    """Final summary. ``render_summary`` uses a rich Console that degrades cleanly in plain mode, so
    both TUI and headless runs get the full findings table + severity tally, then artifact paths."""
    from a2pwn import tui

    out_dir = run_out_dir(cfg, thread_id)
    tui.render_summary(report, str(out_dir))
    paths = getattr(report, "report_paths", {}) or {}
    if paths:
        typer.echo("")
        for key in ("md", "json", "sarif", "html"):
            if key in paths:
                typer.echo(f"{key:>5}: {paths[key]}")
    typer.echo(
        f"Findings — verified: {len(report.findings)}  confirmed-only: {len(report.confirmed_findings)}"
    )


@app.command()
def run(
    target: list[str] = typer.Option(..., "--target", "-t", help="In-scope target URL/host (repeatable)."),
    objective: str = typer.Option(..., "--objective", "-o", help="Engagement objective for the planner."),
    name: str = typer.Option("a2pwn", "--name", help="Engagement + burpwn session name (thread id)."),
    active_exploit: bool = typer.Option(
        False, "--active-exploit", help="Allow active exploitation without a per-dispatch pause."
    ),
    step_through: bool = typer.Option(
        False, "--step-through", help="Interactively approve EACH dispatch (default: upfront-only approval)."
    ),
    dos: bool = typer.Option(
        False,
        "--dos",
        help="Advisory: signal to the planner that DoS-class techniques are permitted (prompt-only, not tool-enforced).",
    ),
    oob_listener: str | None = typer.Option(
        None, "--oob-listener", help="External OOB collaborator base (host:port)."
    ),
    checkpoint_uri: str | None = typer.Option(
        None, "--checkpoint-uri", help="Postgres URI (defaults to on-box SQLite)."
    ),
    executor_model: str | None = typer.Option(
        None, "--executor-model", help="Override the executor role model."
    ),
    verifier_model: str | None = typer.Option(
        None, "--verifier-model", help="Override the verifier (Opus-class) role model."
    ),
    max_phases: int = typer.Option(12, "--max-phases", help="Hard cap on master planning phases."),
    max_dispatches: int = typer.Option(200, "--max-dispatches", help="Global dispatch budget ceiling."),
    max_wall_secs: int | None = typer.Option(
        None,
        "--max-wall-secs",
        help="Wall-clock deadline (seconds) for the whole engagement; past it the report is built from proven findings.",
    ),
    format: str = typer.Option(
        "md,json,sarif,html",
        "--format",
        help="Report artifacts to write (comma list of md,json,sarif,html). md+json are always written.",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Non-interactively acknowledge authorization."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose telemetry logging."),
    plain: bool = typer.Option(False, "--plain", help="Disable the live TUI; log telemetry instead."),
) -> None:
    """Run an autonomous, adversarially-verified engagement against the given targets."""
    use_tui = _use_tui(plain=plain, verbose=verbose, step_through=step_through)
    _init_logging(verbose=verbose, use_tui=use_tui)
    formats = _parse_formats(format)

    engagement = EngagementSpec(
        name=name,
        targets=target,
        in_scope=list(target),
        authorization_acknowledged=False,  # set once the gate is acknowledged below
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
            max_wall_secs=max_wall_secs,
            checkpoint_uri=checkpoint_uri,
            disclaimer_ack=False,
            step_through=step_through,
        )
    except ValueError as exc:
        typer.echo(f"Invalid configuration: {exc}", err=True)
        raise typer.Exit(2) from exc

    out_dir = run_out_dir(cfg, name)
    # Show the plan BEFORE the authorization gate so the operator can bail on a wrong scope/flag.
    _print_run_plan(cfg, objective, out_dir, compact=yes)

    # Fail fast on the most common first-run failure BEFORE the authorization gate — no point making
    # the operator acknowledge the disclaimer for a run that cannot capture traffic.
    try:
        ensure_burpwn_available()
    except BurpwnMissingError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc

    ack = _authorize(yes)
    if not ack:
        typer.echo("Authorization not confirmed. Aborting.", err=True)
        raise typer.Exit(2)
    cfg.disclaimer_ack = ack
    cfg.engagement.authorization_acknowledged = ack

    try:
        report = asyncio.run(run_engagement(cfg, objective, thread_id=name, tui=use_tui, formats=formats))
    except BurpwnMissingError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc

    _emit_report(report, cfg, name)


@app.command("list")
def list_cmd() -> None:
    """List prior runs (verified / confirmed-only counts, severity tally, last updated)."""
    runs = list_runs()
    if not runs:
        typer.echo("No runs found.")
        return
    from rich.console import Console
    from rich.table import Table

    table = Table(title="a2pwn runs", title_justify="left", border_style="grey37")
    table.add_column("run", no_wrap=True)
    table.add_column("verified", justify="right")
    table.add_column("confirmed", justify="right")
    table.add_column("severity")
    table.add_column("objective", overflow="ellipsis", max_width=40)
    table.add_column("updated", no_wrap=True)
    for r in runs:
        sev = r.get("by_severity") or {}
        sev_txt = (
            " ".join(f"{s[0].upper()}{sev[s]}" for s in sorted(sev, key=lambda k: -_SEVERITY_ORDER.get(k, 0)))
            or "—"
        )
        updated = datetime.fromtimestamp(r["mtime"]).strftime("%Y-%m-%d %H:%M") if r.get("mtime") else "—"
        has = r.get("has_report")
        table.add_row(
            r["thread_id"],
            str(r["verified"]) if has else "—",
            str(r["confirmed"]) if has else "—",
            sev_txt if has else "—",
            _truncate(r.get("objective", ""), 40) or "—",
            updated,
        )
    Console().print(table)


@app.command()
def resume(
    name: str = typer.Option(..., "--name", help="Existing run/thread id to resume (see `a2pwn list`)."),
    objective: str | None = typer.Option(
        None, "--objective", "-o", help="Objective (defaults to the prior run's, if recorded)."
    ),
    active_exploit: bool = typer.Option(
        False, "--active-exploit", help="Allow active exploitation without a per-dispatch pause."
    ),
    step_through: bool = typer.Option(False, "--step-through", help="Interactively approve EACH dispatch."),
    checkpoint_uri: str | None = typer.Option(
        None, "--checkpoint-uri", help="Postgres URI (defaults to on-box SQLite)."
    ),
    executor_model: str | None = typer.Option(
        None, "--executor-model", help="Override the executor role model."
    ),
    verifier_model: str | None = typer.Option(
        None, "--verifier-model", help="Override the verifier role model."
    ),
    max_phases: int = typer.Option(12, "--max-phases", help="Hard cap on master planning phases."),
    max_dispatches: int = typer.Option(200, "--max-dispatches", help="Global dispatch budget ceiling."),
    max_wall_secs: int | None = typer.Option(None, "--max-wall-secs", help="Wall-clock deadline (seconds)."),
    format: str = typer.Option("md,json,sarif,html", "--format", help="Report artifacts to write."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Non-interactively acknowledge authorization."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose telemetry logging."),
    plain: bool = typer.Option(False, "--plain", help="Disable the live TUI."),
) -> None:
    """Re-drive an existing engagement by its thread id — the checkpointer resumes where it left off."""
    prior = next((r for r in list_runs() if r["thread_id"] == name), None)
    if prior is None:
        typer.echo(f"No run named '{name}' found (see `a2pwn list`).", err=True)
        raise typer.Exit(2)
    targets = list(prior.get("targets") or [])
    if not targets:
        typer.echo(
            f"Run '{name}' has no recorded target metadata to resume from; start it with `a2pwn run` "
            "instead.",
            err=True,
        )
        raise typer.Exit(2)
    obj = objective or prior.get("objective") or ""
    if not obj:
        typer.echo("No objective recorded for this run; pass --objective to resume.", err=True)
        raise typer.Exit(2)

    use_tui = _use_tui(plain=plain, verbose=verbose, step_through=step_through)
    _init_logging(verbose=verbose, use_tui=use_tui)
    formats = _parse_formats(format)

    engagement = EngagementSpec(
        name=name,
        targets=targets,
        in_scope=list(targets),
        authorization_acknowledged=False,
        active_exploit_allowed=active_exploit,
        session=name,
    )
    try:
        cfg = A2pwnConfig(
            engagement=engagement,
            models=_build_models(executor_model, verifier_model),
            max_phases=max_phases,
            max_dispatches=max_dispatches,
            max_wall_secs=max_wall_secs,
            checkpoint_uri=checkpoint_uri,
            disclaimer_ack=False,
            step_through=step_through,
        )
    except ValueError as exc:
        typer.echo(f"Invalid configuration: {exc}", err=True)
        raise typer.Exit(2) from exc

    out_dir = run_out_dir(cfg, name)
    _print_run_plan(cfg, obj, out_dir, compact=yes)

    try:
        ensure_burpwn_available()
    except BurpwnMissingError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc

    ack = _authorize(yes)
    if not ack:
        typer.echo("Authorization not confirmed. Aborting.", err=True)
        raise typer.Exit(2)
    cfg.disclaimer_ack = ack
    cfg.engagement.authorization_acknowledged = ack

    typer.echo(f"Resuming run '{name}' …")
    try:
        report = asyncio.run(run_engagement(cfg, obj, thread_id=name, tui=use_tui, formats=formats))
    except BurpwnMissingError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc

    _emit_report(report, cfg, name)


@app.command()
def doctor() -> None:
    """Preflight the host: is burpwn installed, and does the sandbox have what it needs?

    A standalone environment check — no authorization gate, no engagement, no model calls. Run it
    right after install to confirm burpwn is on PATH and the host supports rootless user/network
    namespaces before spending a real run.
    """
    from a2pwn.burpwn import BurpwnClient
    from a2pwn.installer import BURPWN_REPO

    path = shutil.which("burpwn")
    if path is None:
        typer.echo("✗ burpwn: not found on PATH.", err=True)
        typer.echo(f"  Install it with `a2pwn install-burpwn` (or from {BURPWN_REPO}).", err=True)
        raise typer.Exit(1)
    typer.echo(f"✓ burpwn on PATH: {path}")

    try:
        report = BurpwnClient.cli_doctor()
    except Exception as exc:  # noqa: BLE001 - any doctor failure is a red preflight, reported cleanly
        typer.echo(f"✗ `burpwn doctor` failed: {exc}", err=True)
        raise typer.Exit(1) from exc

    ok = not (isinstance(report, dict) and report.get("ok") is False)
    if isinstance(report, dict):
        for key, value in report.items():
            if key == "ok":
                continue
            typer.echo(f"    {key}: {value}")
    if ok:
        typer.echo("✓ sandbox prerequisites OK — you're ready to run.")
    else:
        typer.echo(
            "✗ sandbox prerequisites incomplete (rootless user/network namespaces). "
            "See the burpwn doctor output above.",
            err=True,
        )
    raise typer.Exit(0 if ok else 1)


@app.command("install-burpwn")
def install_burpwn_cmd(
    dest: str | None = typer.Option(
        None,
        "--dest",
        help="Directory to install the burpwn binary into (default: a writable bin dir on PATH, e.g. ~/.local/bin).",
    ),
    version: str = typer.Option(
        "latest", "--version", help="burpwn release tag to install (default: the latest release)."
    ),
    force: bool = typer.Option(False, "--force", help="Reinstall even if burpwn is already on PATH."),
) -> None:
    """Download the burpwn release binary and install it on PATH — the one dep `uv sync` can't pull.

    burpwn is a prebuilt GitHub-release binary, not a Python package, so `git clone → uv sync → uv
    run` leaves it missing. This fetches the right build for your architecture and drops it in a bin
    dir on your PATH. Linux only (macOS/Windows: use the Docker image). Then run `a2pwn doctor`.
    """
    from a2pwn import installer

    existing = shutil.which("burpwn")
    if existing and not force:
        typer.echo(f"burpwn is already installed at {existing} (use --force to reinstall).")
        raise typer.Exit(0)

    try:
        triple = installer.release_triple()
        target_dir = Path(dest) if dest else installer.default_dest()
        typer.echo(f"Downloading burpwn ({triple}, {version}) → {target_dir} …")
        binpath = installer.install_burpwn(target_dir, version=version, triple=triple)
    except installer.InstallError as exc:
        typer.echo(f"Install failed: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"✓ installed burpwn → {binpath}")
    if not installer.on_path(target_dir):
        typer.echo(f"⚠ {target_dir} is not on your PATH. Add it, then re-open your shell:", err=True)
        typer.echo(f'    export PATH="{target_dir}:$PATH"', err=True)
    typer.echo("Next: run `a2pwn doctor` to verify the sandbox prerequisites.")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
