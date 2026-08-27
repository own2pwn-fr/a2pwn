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


#: What each overridable flag looks like when the operator did NOT pass it. typer cannot tell an
#: omitted flag from one passed at its default, so without this every engagement-file setting would
#: be silently clobbered by a default the operator never typed.
_FLAG_DEFAULTS = {
    "targets": [],
    "objective": "",
    "exclude": [],
    "active_exploit": False,
    "dos": False,
    "max_phases": 12,
    "max_dispatches": 200,
    "fuzz_max_requests": 5000,
    "no_research": False,
    "format": "md,json,sarif,html",
}


def _merge_config(config_path: str | None, cli_values: dict) -> dict:
    """Engagement file (if any) merged under the explicitly-passed CLI flags."""
    from a2pwn.runconfig import load_engagement_file, merge

    file_values = load_engagement_file(config_path) if config_path else {}
    return merge(file_values, cli_values, _FLAG_DEFAULTS)


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
            f"exclude={','.join(eng.exclude) or 'none'} "
            f"identities={','.join(i.name for i in eng.identities) or 'none'} "
            f"active_exploit={'ON' if ae else 'off'} dos={'on' if eng.dos_allowed else 'off'} "
            f"executor={exec_lbl} verifier={ver_lbl} "
            f"max_phases={cfg.max_phases} max_dispatches={cfg.max_dispatches} "
            f"max_usd={cfg.max_usd or '-'} max_rps={cfg.max_rps or '-'} "
            f"research={'on' if cfg.research_enabled else 'off'} "
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
    if eng.exclude:
        # Rendered in red: an operator scanning this panel must SEE the carve-outs, because the
        # cost of a missed exclusion is testing something the client did not authorise.
        grid.add_row("excluded", Text(", ".join(eng.exclude), style="bold red"))
    if eng.identities:
        grid.add_row(
            "identities",
            ", ".join(f"{i.name}{' (anon)' if i.anonymous else ''}" for i in eng.identities),
        )
    grid.add_row("objective", _truncate(objective, 88))
    # Stated before the authorization gate on purpose: this is the only traffic a2pwn sends that
    # burpwn does not capture, and the operator is the one who has to be comfortable with a client's
    # dependency names reaching a public database.
    grid.add_row(
        "cve research",
        "ON — package/version names discovered on the target are sent to public vulnerability "
        "databases (never the target itself); disable with --no-research"
        if cfg.research_enabled
        else "off",
    )
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
        + (f"  max_wall_secs={cfg.max_wall_secs}" if cfg.max_wall_secs else "")
        + (f"  max_usd=${cfg.max_usd}" if cfg.max_usd else "")
        + (f"  max_tokens={cfg.max_tokens}" if cfg.max_tokens else ""),
    )
    if cfg.max_rps:
        grid.add_row("rate limit", f"{cfg.max_rps} req/s (enforced at the tool layer)")
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
    config: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Engagement YAML file (targets, exclusions, identities, caps). Explicit flags override it. "
        "This is the only sane way to declare credentials — a password in a flag lands in shell history.",
    ),
    target: list[str] = typer.Option(
        [], "--target", "-t", help="In-scope target URL/host (repeatable). Required unless --config sets it."
    ),
    objective: str = typer.Option(
        "",
        "--objective",
        "-o",
        help="Engagement objective for the planner. Required unless --config sets it.",
    ),
    exclude: list[str] = typer.Option(
        [],
        "--exclude",
        "-x",
        help="Carve OUT of scope (repeatable): a host glob (legacy.example.com, *.internal.example.com), "
        "a URL path subtree (https://app.example.com/admin), or a bare path glob (/admin/billing). "
        "Always wins over the allow-list.",
    ),
    name: str | None = typer.Option(
        None,
        "--name",
        help="Engagement + burpwn session name (thread id). Defaults to a timestamped, unique "
        "name so unrelated runs never silently share a checkpoint/session — pass one explicitly "
        "only when you intend to `a2pwn resume` this exact run later.",
    ),
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
    max_usd: float | None = typer.Option(
        None,
        "--max-usd",
        help="REAL cost ceiling in dollars. Unlike --max-dispatches (a count), this bounds what the "
        "run actually spends; past it the report is built from proven findings.",
    ),
    max_tokens: int | None = typer.Option(None, "--max-tokens", help="Real token ceiling for the run."),
    max_rps: float | None = typer.Option(
        None,
        "--max-rps",
        help="Throttle ALL target-facing traffic to this many requests per second (enforced in the "
        "tool layer, not prompt guidance).",
    ),
    fuzz_max_requests: int = typer.Option(
        5000,
        "--fuzz-max-requests",
        help="Cap on payloads per Intruder attack (clamped, and the clamp is reported).",
    ),
    no_research: bool = typer.Option(
        False,
        "--no-research",
        help="Disable external CVE/advisory lookups. They are the only traffic that leaves this "
        "machine without going through burpwn — they can never reach the target, but discovered "
        "package and version names do reach public vulnerability databases.",
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
    try:
        settings = _merge_config(
            config,
            {
                "targets": list(target),
                "objective": objective,
                "exclude": list(exclude),
                "active_exploit": active_exploit,
                "dos": dos,
                "oob_listener": oob_listener,
                "executor_model": executor_model,
                "verifier_model": verifier_model,
                "max_phases": max_phases,
                "max_dispatches": max_dispatches,
                "max_wall_secs": max_wall_secs,
                "max_usd": max_usd,
                "max_tokens": max_tokens,
                "max_rps": max_rps,
                "fuzz_max_requests": fuzz_max_requests,
                "no_research": no_research,
                "checkpoint_uri": checkpoint_uri,
                "format": format,
            },
        )
    except Exception as exc:  # noqa: BLE001 - config errors are operator errors, reported cleanly
        typer.echo(f"Invalid engagement file: {exc}", err=True)
        raise typer.Exit(2) from exc

    target = settings.get("targets") or []
    objective = settings.get("objective") or ""
    if not target:
        typer.echo("No targets: pass --target (repeatable) or set `targets:` in --config.", err=True)
        raise typer.Exit(2)
    if not objective:
        typer.echo("No objective: pass --objective or set `objective:` in --config.", err=True)
        raise typer.Exit(2)
    active_exploit = bool(settings.get("active_exploit"))
    dos = bool(settings.get("dos"))
    oob_listener = settings.get("oob_listener")
    executor_model = settings.get("executor_model")
    verifier_model = settings.get("verifier_model")
    checkpoint_uri = settings.get("checkpoint_uri")
    format = settings.get("format") or "md,json,sarif,html"
    if name is None:
        name = settings.get("name")
    if name is None:
        # A hardcoded default ("a2pwn") meant every unnamed run silently resumed/mixed state with
        # whatever prior unnamed run's checkpoint existed — observed live as stray "Deserializing
        # unregistered type" warnings and reused burpwn session state at bootstrap. A per-invocation
        # timestamp keeps runs isolated by default; `--name` still opts into a stable id for `resume`.
        name = f"a2pwn-{datetime.now():%Y%m%d-%H%M%S}"
    use_tui = _use_tui(plain=plain, verbose=verbose, step_through=step_through)
    _init_logging(verbose=verbose, use_tui=use_tui)
    formats = _parse_formats(format)

    engagement = EngagementSpec(
        name=name,
        targets=target,
        in_scope=list(settings.get("in_scope") or target),
        exclude=list(settings.get("exclude") or []),
        identities=list(settings.get("identities") or []),
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
            max_phases=int(settings.get("max_phases") or 12),
            max_dispatches=int(settings.get("max_dispatches") or 200),
            max_wall_secs=settings.get("max_wall_secs"),
            max_usd=settings.get("max_usd"),
            max_tokens=settings.get("max_tokens"),
            max_rps=settings.get("max_rps"),
            fuzz_max_requests=int(settings.get("fuzz_max_requests") or 5000),
            research_enabled=not bool(settings.get("no_research")),
            block_threshold=int(settings.get("block_threshold") or 25),
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
    config: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Engagement YAML — the only way to restore IDENTITIES on a resume (credentials are "
        "deliberately never written to report.json).",
    ),
    exclude: list[str] = typer.Option(  # noqa: B008 - typer option factory
        [], "--exclude", "-x", help="Extra scope carve-out, on top of the prior run's."
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
    max_usd: float | None = typer.Option(
        None,
        "--max-usd",
        help="REAL cost ceiling in dollars for the resumed run. NOT inherited from the prior run — "
        "spend caps are operator intent, not run metadata, so a resume that wants one must say so.",
    ),
    max_tokens: int | None = typer.Option(None, "--max-tokens", help="Real token ceiling for the run."),
    max_rps: float | None = typer.Option(
        None,
        "--max-rps",
        help="Throttle ALL target-facing traffic to this many requests per second (enforced in the "
        "tool layer). NOT inherited from the prior run — pass it again to keep pacing the target.",
    ),
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

    # Restore the FULL scope envelope, not just the targets. Rebuilding from `targets` alone
    # re-authorised every host and path the operator had carved out with `--exclude`, which is the
    # one direction a scope mistake must never go.
    prior_exclude = list(prior.get("exclude") or [])
    prior_in_scope = list(prior.get("in_scope") or []) or list(targets)
    file_values: dict = {}
    if config:
        from a2pwn.runconfig import ConfigError, load_engagement_file

        try:
            file_values = load_engagement_file(config)
        except ConfigError as exc:
            typer.echo(f"Invalid engagement file: {exc}", err=True)
            raise typer.Exit(2) from exc
    identities = list(file_values.get("identities") or [])
    prior_exclude += [x for x in (file_values.get("exclude") or []) if x not in prior_exclude]
    # Budget/rate caps are NOT recorded in report.json, so a resume rebuilt them as None and
    # silently dropped both the spend ceiling and the throttle — the run came back unpaced against
    # a live target. An explicit flag wins; otherwise fall back to the engagement file.
    if max_usd is None:
        max_usd = file_values.get("max_usd")
    if max_tokens is None:
        max_tokens = file_values.get("max_tokens")
    if max_rps is None:
        max_rps = file_values.get("max_rps")
    if max_rps is None:
        typer.echo(
            "WARNING: no --max-rps on this resume — target-facing traffic will be unthrottled. "
            "Pass --max-rps (or set it in --config) to keep the prior run's pacing.",
            err=True,
        )
    prior_identity_names = list(prior.get("identity_names") or [])
    if prior_identity_names and not identities:
        typer.echo(
            f"WARNING: run '{name}' used identities ({', '.join(prior_identity_names)}) but none were "
            "supplied. Credentials are never stored in report.json, so the whole authenticated "
            "surface will be untestable on this resume — pass --config <engagement.yaml> to restore "
            "them.",
            err=True,
        )
    engagement = EngagementSpec(
        name=name,
        targets=targets,
        in_scope=prior_in_scope,
        exclude=prior_exclude + list(exclude),
        identities=identities,
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
            max_usd=max_usd,
            max_tokens=max_tokens,
            max_rps=max_rps,
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


def _load_baseline(baseline: str) -> tuple[list, dict]:
    """Load a prior ``report.json`` (by path or by run name) into (findings, report dict)."""
    import json

    from a2pwn.models import Finding

    path = Path(baseline)
    if not path.exists():
        prior = next((r for r in list_runs() if r["thread_id"] == baseline), None)
        if prior is None:
            raise typer.BadParameter(
                f"no such baseline: {baseline!r} is neither a report.json path nor a known run "
                "(see `a2pwn list`)."
            )
        path = Path(prior["path"]) / "report.json"
    if not path.exists():
        raise typer.BadParameter(f"baseline {path} does not exist")
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = [Finding(**f) for f in (data.get("findings") or [])]
    # A retest must also chase the weaker tier: a confirmed-but-not-independently-reproduced
    # finding is exactly the kind a client remediates and wants re-checked.
    findings += [Finding(**f) for f in (data.get("confirmed_findings") or [])]
    return findings, data


def _retest_tasks(findings: list) -> list:
    """One reproduce-this-finding task per baseline finding, seeded straight into ``pending``.

    Seeding concrete tasks (rather than describing the retest in the objective and hoping the
    planner derives them) means the first phase is deterministic: every baseline finding gets its
    own dispatch and its own fail-closed oracle re-derivation, and none can be quietly skipped
    because the planner judged it uninteresting.
    """
    from a2pwn.models import TaskSpec

    tasks = []
    for f in findings:
        tasks.append(
            TaskSpec(
                task=(
                    f"RETEST: determine whether {f.vuln_class} on {f.target} "
                    f"(param {f.param or 'n/a'}) is still exploitable after remediation. Reproduce "
                    f"it exactly as originally proven, then re-run the {f.oracle_kind} oracle. If it "
                    "no longer reproduces, try the obvious bypasses of a shallow fix (encoding, "
                    "casing, alternate verb/route, parameter pollution) before concluding it is "
                    "fixed. Report a finding ONLY if it still reproduces with captured evidence.\n"
                    f"Original evidence: {f.evidence[:600]}"
                ),
                intent="verify",
                target=f.target,
                hints=[f"baseline_key={f.key}", f"oracle={f.oracle_kind}", f"severity={f.severity}"],
            )
        )
    return tasks


@app.command()
def retest(
    baseline: str = typer.Option(
        ...,
        "--baseline",
        "-b",
        help="Prior report.json path, or a run name from `a2pwn list`, to re-check after remediation.",
    ),
    config: str | None = typer.Option(
        None,
        "--config",
        "-c",
        help="Engagement YAML (identities/exclusions). Reuses the baseline's targets if omitted.",
    ),
    name: str | None = typer.Option(None, "--name", help="Name for this retest run (default: timestamped)."),
    active_exploit: bool = typer.Option(
        False, "--active-exploit", help="Allow active exploitation without a per-dispatch pause."
    ),
    executor_model: str | None = typer.Option(None, "--executor-model", help="Override the executor model."),
    verifier_model: str | None = typer.Option(None, "--verifier-model", help="Override the verifier model."),
    max_phases: int = typer.Option(6, "--max-phases", help="Hard cap on master planning phases."),
    max_dispatches: int = typer.Option(60, "--max-dispatches", help="Global dispatch budget ceiling."),
    max_usd: float | None = typer.Option(None, "--max-usd", help="Real cost ceiling in dollars."),
    max_rps: float | None = typer.Option(
        None, "--max-rps", help="Throttle target traffic (requests/second)."
    ),
    format: str = typer.Option("md,json,sarif,html", "--format", help="Report artifacts to write."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Non-interactively acknowledge authorization."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose telemetry logging."),
    plain: bool = typer.Option(False, "--plain", help="Disable the live TUI."),
) -> None:
    """Re-check a prior engagement's findings after remediation, and report the delta.

    This is the pentest cycle's second half, which `run` alone could not express: seed one dispatch
    per baseline finding, re-derive each through the same fail-closed oracle kernel, and report what
    is STILL VULNERABLE versus what could no longer be reproduced. Findings that no longer reproduce
    are reported as "fixed or unreproducible", never flatly as "fixed" — a moved endpoint or an
    expired credential looks identical to a real fix, and signing a live bug off as remediated is
    the one mistake this command must not make.
    """
    baseline_findings, baseline_data = _load_baseline(baseline)
    if not baseline_findings:
        typer.echo(f"Baseline {baseline!r} has no findings to retest.", err=True)
        raise typer.Exit(2)

    try:
        settings = _merge_config(
            config,
            {
                "active_exploit": active_exploit,
                "executor_model": executor_model,
                "verifier_model": verifier_model,
                "max_phases": max_phases,
                "max_dispatches": max_dispatches,
                "max_usd": max_usd,
                "max_rps": max_rps,
                "format": format,
            },
        )
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"Invalid engagement file: {exc}", err=True)
        raise typer.Exit(2) from exc

    targets = list(settings.get("targets") or baseline_data.get("targets") or [])
    if not targets:
        typer.echo("Baseline records no targets; pass --config with `targets:`.", err=True)
        raise typer.Exit(2)
    if name is None:
        name = f"retest-{datetime.now():%Y%m%d-%H%M%S}"

    use_tui = _use_tui(plain=plain, verbose=verbose)
    _init_logging(verbose=verbose, use_tui=use_tui)
    formats = _parse_formats(settings.get("format") or format)
    objective = (
        f"Retest {len(baseline_findings)} finding(s) from the prior engagement "
        f"'{baseline_data.get('engagement', baseline)}' and determine which remain exploitable."
    )

    engagement = EngagementSpec(
        name=name,
        targets=targets,
        in_scope=list(settings.get("in_scope") or baseline_data.get("in_scope") or targets),
        # Carve-outs are inherited from the baseline the same way targets are. A retest that
        # forgot the original exclusions would probe hosts the client put off-limits, on a run
        # the operator reasonably assumes is narrower than the engagement it re-checks.
        exclude=list(settings.get("exclude") or baseline_data.get("exclude") or []),
        identities=list(settings.get("identities") or []),
        authorization_acknowledged=False,
        active_exploit_allowed=bool(settings.get("active_exploit")),
        session=name,
    )
    try:
        cfg = A2pwnConfig(
            engagement=engagement,
            models=_build_models(settings.get("executor_model"), settings.get("verifier_model")),
            max_phases=int(settings.get("max_phases") or 6),
            max_dispatches=int(settings.get("max_dispatches") or 60),
            max_usd=settings.get("max_usd"),
            max_tokens=settings.get("max_tokens"),
            max_rps=settings.get("max_rps"),
            fuzz_max_requests=int(settings.get("fuzz_max_requests") or 5000),
            # A retest hits the same WAF as the run it re-checks, so it needs the same tuned
            # breaker threshold; it was pinned to the default 25 no matter what the config said.
            block_threshold=int(settings.get("block_threshold") or 25),
            disclaimer_ack=False,
        )
    except ValueError as exc:
        typer.echo(f"Invalid configuration: {exc}", err=True)
        raise typer.Exit(2) from exc

    out_dir = run_out_dir(cfg, name)
    typer.echo(f"Retesting {len(baseline_findings)} finding(s) from {baseline!r} → {out_dir}")
    _print_run_plan(cfg, objective, out_dir, compact=yes)

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
        report = asyncio.run(
            run_engagement(
                cfg,
                objective,
                thread_id=name,
                tui=use_tui,
                formats=formats,
                seed_tasks=_retest_tasks(baseline_findings),
                baseline=baseline_findings,
            )
        )
    except BurpwnMissingError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(1) from exc

    _emit_report(report, cfg, name)
    delta = report.retest or {}
    still = delta.get("still_vulnerable") or []
    gone = delta.get("fixed_or_unreproducible") or []
    typer.echo("")
    typer.echo(f"Retest delta vs {baseline!r}:")
    typer.echo(f"  still vulnerable       : {len(still)}")
    for key in still:
        typer.echo(f"      ✗ {key}")
    typer.echo(f"  fixed / unreproducible : {len(gone)}")
    for key in gone:
        typer.echo(f"      ✓ {key}")
    if delta.get("new_since_baseline"):
        typer.echo(f"  new since baseline     : {len(delta['new_since_baseline'])}")


def _probe_capture() -> dict:
    """Run the live cleartext-capture probe against a throwaway burpwn session."""
    import asyncio

    from a2pwn.burpwn import BurpwnClient
    from a2pwn.preflight import probe_cleartext_capture

    async def _run() -> dict:
        client = BurpwnClient(session="a2pwn-doctor")
        try:
            return await probe_cleartext_capture(client)
        finally:
            await client.close()

    try:
        return asyncio.run(_run())
    except Exception as exc:  # noqa: BLE001 - unknown beats a false alarm
        return {"ok": None, "detail": f"capture probe could not run: {exc}"}


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
        typer.echo("✓ sandbox prerequisites OK.")
        # The prerequisites being present does not mean traffic is actually captured, and the
        # difference is the whole product: an uncaptured run still probes, still rejects every
        # candidate for an empty flow batch, and still reports a clean target.
        capture = _probe_capture()
        if capture["ok"] is True:
            typer.echo(f"✓ capture: {capture['detail']}")
            typer.echo("✓ ready to run.")
        elif capture["ok"] is None:
            typer.echo(f"? capture: {capture['detail']}")
            typer.echo("✓ prerequisites OK; capture unverified.")
        else:
            typer.echo(f"✗ capture: {capture['detail']}", err=True)
            ok = False
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
