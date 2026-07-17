"""Live, colored terminal dashboard for an autonomous a2pwn engagement.

A read-only consumer of the display-event bus (:mod:`a2pwn.progress`): it drains an
``asyncio.Queue`` of plain dicts and paints a ``rich`` live dashboard showing the
orchestrator ("master"), the concurrently dispatched sub-agents and what each is
doing, and findings as they are promoted. It never produces events and never mutates
graph state, so the clean-history invariant holds. Every event is defensively parsed
with ``.get()`` so a malformed dict can never crash the UI or the engagement.

Copyright (C) own2pwn. Licensed under the GNU AGPL v3 or later.
"""

from __future__ import annotations

import asyncio
import itertools
import time
from collections import deque
from typing import Any

from rich.align import Align
from rich.box import ROUNDED
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# ------------------------------------------------------------------------- #
# Palette / styling constants                                               #
# ------------------------------------------------------------------------- #

_ACCENT = "magenta"  # own2pwn brand violet/magenta
_ACCENT_BRIGHT = "bright_magenta"

# Stable per-dispatch colors, cycled deterministically as dispatches appear.
_DISPATCH_PALETTE = (
    "cyan",
    "green",
    "yellow",
    "bright_blue",
    "bright_magenta",
    "bright_cyan",
    "orange1",
    "spring_green2",
)

_SEVERITY_STYLE: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

# Finding status ranking (higher wins on dedupe) + presentation.
_STATUS_RANK: dict[str, int] = {
    "rejected": 0,
    "candidate": 1,
    "confirmed": 2,
    "verified": 3,
}
_STATUS_STYLE: dict[str, str] = {
    "candidate": "dim",
    "confirmed": "green",
    "verified": "bold green",
    "rejected": "dim red strike",
}
_STATUS_GLYPH: dict[str, str] = {
    "candidate": "…",
    "confirmed": "•",
    "verified": "✓",
    "rejected": "✗",
}

_INTENT_GLYPH: dict[str, str] = {"exploit": "⚔", "task": "⚔", "verify": "🔍"}
_STAGE_STYLE: dict[str, str] = {
    "exploit": "bright_red",
    "verify": "bright_cyan",
    "clarify": "yellow",
}
_DISPATCH_END_STYLE: dict[str, str] = {
    "confirmed": "green",
    "partial": "yellow",
    "no_finding": "dim",
    "blocked": "red",
}

_MAX_ACTIVE_ROWS = 8
_MAX_DONE_ROWS = 4
_MAX_FEED = 8
_MAX_FINDING_ROWS = 12


def _truncate(text: str, limit: int) -> str:
    text = str(text).replace("\n", " ").strip()
    if limit <= 1:
        return text[:limit]
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _fmt_elapsed(seconds: float) -> str:
    seconds = int(max(0.0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h:d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def _short_id(did: str) -> str:
    did = str(did or "master")
    return did if did == "master" else _truncate(did, 10)


# ------------------------------------------------------------------------- #
# Dashboard state                                                           #
# ------------------------------------------------------------------------- #


class _Dashboard:
    """Mutable render model updated from display events, painted by ``render``."""

    def __init__(self, target: str, model: str, objective: str) -> None:
        self.target = target or "?"
        self.model = model or "?"
        self.objective = objective or ""
        self.started = time.monotonic()

        self.phase = "starting"
        self.round = 0
        self.spent = 0
        self.max = 0

        # dispatch id -> record dict
        self.dispatches: dict[str, dict[str, Any]] = {}
        self.done: deque[dict[str, Any]] = deque(maxlen=_MAX_DONE_ROWS)
        # ordered finding rows keyed by (vuln_class, target)
        self.findings: dict[tuple[str, str], dict[str, Any]] = {}
        self.feed: deque[Text] = deque(maxlen=_MAX_FEED)
        self.logs: deque[str] = deque(maxlen=4)

        self._color_cycle = itertools.cycle(_DISPATCH_PALETTE)
        self._colors: dict[str, str] = {"master": _ACCENT_BRIGHT}
        self._spinner = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

    # -- color assignment -------------------------------------------------- #

    def _color_for(self, did: str) -> str:
        did = did or "master"
        if did not in self._colors:
            self._colors[did] = next(self._color_cycle)
        return self._colors[did]

    # -- event ingestion --------------------------------------------------- #

    def apply(self, ev: dict[str, Any]) -> None:
        kind = ev.get("kind")
        handler = getattr(self, f"_on_{kind}", None)
        if handler is not None:
            try:
                handler(ev)
            except Exception:  # noqa: BLE001 - a bad event must never break the UI
                pass

    def _on_engagement(self, ev: dict[str, Any]) -> None:
        self.target = ev.get("target") or self.target
        self.model = ev.get("model") or self.model
        self.objective = ev.get("objective") or self.objective

    def _on_phase(self, ev: dict[str, Any]) -> None:
        self.phase = str(ev.get("phase") or self.phase)
        self.round = int(ev.get("round") or 0)
        self.spent = int(ev.get("spent") or 0)
        self.max = int(ev.get("max") or 0)

    def _on_dispatch_start(self, ev: dict[str, Any]) -> None:
        did = str(ev.get("id") or "?")
        intent = str(ev.get("intent") or "task")
        self.dispatches[did] = {
            "id": did,
            "intent": intent,
            "task": str(ev.get("task") or ""),
            "activity": Text("dispatched", style="dim"),
            "started": time.monotonic(),
        }
        self._color_for(did)

    def _on_activity(self, ev: dict[str, Any]) -> None:
        did = str(ev.get("dispatch") or "master")
        stage = str(ev.get("stage") or "")
        text = str(ev.get("text") or "")
        style = _STAGE_STYLE.get(stage, "white")
        line = Text(text, style=style)
        rec = self.dispatches.get(did)
        if rec is not None:
            rec["activity"] = Text(_truncate(text, 60), style=style)
        self._push_feed(did, line, tool=True)

    def _on_thought(self, ev: dict[str, Any]) -> None:
        did = str(ev.get("dispatch") or "master")
        text = str(ev.get("text") or "")
        self._push_feed(did, Text(_truncate(text, 68), style="italic dim"), tool=False)

    def _on_finding(self, ev: dict[str, Any]) -> None:
        vuln = str(ev.get("vuln_class") or "?")
        target = str(ev.get("target") or "?")
        status = str(ev.get("status") or "candidate")
        severity = str(ev.get("severity") or "info")
        key = (vuln, target)
        prev = self.findings.get(key)
        if prev is not None and _STATUS_RANK.get(status, 0) < _STATUS_RANK.get(prev["status"], 0):
            # keep the highest status already seen, but a worse severity should not downgrade
            if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER.get(prev["severity"], 0):
                prev["severity"] = severity
            return
        self.findings[key] = {
            "vuln_class": vuln,
            "target": target,
            "status": status,
            "severity": severity,
        }

    def _on_dispatch_end(self, ev: dict[str, Any]) -> None:
        did = str(ev.get("id") or "?")
        rec = self.dispatches.pop(did, None)
        status = str(ev.get("status") or "done")
        task = rec["task"] if rec else ""
        intent = rec["intent"] if rec else "task"
        self.done.appendleft(
            {
                "id": did,
                "intent": intent,
                "task": task,
                "status": status,
                "n_findings": int(ev.get("n_findings") or 0),
            }
        )

    def _on_log(self, ev: dict[str, Any]) -> None:
        level = str(ev.get("level") or "info")
        text = str(ev.get("text") or "")
        self.logs.append(f"[{level}] {text}")

    def _push_feed(self, did: str, body: Text, *, tool: bool) -> None:
        color = self._color_for(did)
        prefix = Text(f"{_short_id(did):>10} ", style=f"bold {color}")
        sep = Text("│ " if tool else "· ", style="dim")
        self.feed.append(Text.assemble(prefix, sep, body))

    # -- rendering --------------------------------------------------------- #

    def _finding_counts(self) -> dict[str, int]:
        counts = {"verified": 0, "confirmed": 0, "candidate": 0, "rejected": 0}
        for f in self.findings.values():
            counts[f["status"]] = counts.get(f["status"], 0) + 1
        return counts

    def _severity_tally(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for f in self.findings.values():
            if f["status"] == "rejected":
                continue
            tally[f["severity"]] = tally.get(f["severity"], 0) + 1
        return tally

    def render_header(self) -> Panel:
        elapsed = _fmt_elapsed(time.monotonic() - self.started)
        budget_bar = _budget_bar(self.spent, self.max)
        left = Text.assemble(
            ("a2pwn", f"bold {_ACCENT_BRIGHT}"),
            ("  autonomous web-pentest", "dim"),
        )
        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="right")
        meta = Text.assemble(
            ("target ", "dim"),
            (_truncate(self.target, 40), "bold white"),
            ("   model ", "dim"),
            (_truncate(self.model, 24), "white"),
        )
        phase = Text.assemble(
            ("phase ", "dim"),
            (_truncate(self.phase, 22), f"bold {_ACCENT}"),
            (f"  round {self.round}", "white"),
            ("   budget ", "dim"),
            budget_bar,
            ("   ⏱ ", "dim"),
            (elapsed, "bold white"),
        )
        grid.add_row(left, phase)
        grid.add_row(meta, Text(_truncate(self.objective, 60), style="italic dim"))
        return Panel(grid, box=ROUNDED, border_style=_ACCENT, padding=(0, 1))

    def render_dispatches(self) -> Panel:
        table = Table(box=None, expand=True, padding=(0, 1), show_edge=False)
        table.add_column("", width=1, no_wrap=True)
        table.add_column("id", style="bold", no_wrap=True, width=10)
        table.add_column("task", ratio=2, no_wrap=True, overflow="ellipsis")
        table.add_column("latest activity", ratio=3, no_wrap=True, overflow="ellipsis")

        active = list(self.dispatches.values())[:_MAX_ACTIVE_ROWS]
        for rec in active:
            did = rec["id"]
            color = self._color_for(did)
            glyph = _INTENT_GLYPH.get(rec["intent"], "•")
            table.add_row(
                Text(glyph, style=color),
                Text(_short_id(did), style=color),
                Text(_truncate(rec["task"], 40), style="white"),
                rec["activity"],
            )
        if not active:
            table.add_row("", Text("—", style="dim"), Text("no active dispatches", style="dim"), "")

        for rec in self.done:
            style = _DISPATCH_END_STYLE.get(rec["status"], "dim")
            table.add_row(
                Text("◌", style="dim"),
                Text(_short_id(rec["id"]), style="dim"),
                Text(_truncate(rec["task"], 40), style="dim strike"),
                Text.assemble(
                    (rec["status"], style),
                    (f"  ({rec['n_findings']} findings)", "dim"),
                ),
            )
        title = Text.assemble(("⚡ Dispatches ", f"bold {_ACCENT}"), (f"{len(self.dispatches)} active", "dim"))
        return Panel(table, title=title, title_align="left", box=ROUNDED, border_style="grey37")

    def render_findings(self) -> Panel:
        table = Table(box=None, expand=True, padding=(0, 1), show_edge=False)
        table.add_column("sev", no_wrap=True, width=9)
        table.add_column("vuln class", no_wrap=True, overflow="ellipsis", ratio=2)
        table.add_column("target", no_wrap=True, overflow="ellipsis", ratio=3)
        table.add_column("status", no_wrap=True, width=12)

        rows = sorted(
            self.findings.values(),
            key=lambda f: (
                -_STATUS_RANK.get(f["status"], 0),
                -_SEVERITY_ORDER.get(f["severity"], 0),
            ),
        )[:_MAX_FINDING_ROWS]
        for f in rows:
            sev = f["severity"]
            status = f["status"]
            sev_style = _SEVERITY_STYLE.get(sev, "white")
            st_style = _STATUS_STYLE.get(status, "white")
            table.add_row(
                Text(f" {sev.upper():<7}", style=sev_style),
                Text(_truncate(f["vuln_class"], 26), style=sev_style),
                Text(_truncate(f["target"], 40), style="white"),
                Text(f"{_STATUS_GLYPH.get(status, '')} {status}", style=st_style),
            )
        if not rows:
            table.add_row("", Text("no findings yet", style="dim"), "", "")
        title = Text.assemble(("🎯 Findings ", f"bold {_ACCENT}"), (f"{len(self.findings)}", "dim"))
        return Panel(table, title=title, title_align="left", box=ROUNDED, border_style="grey37")

    def render_feed(self) -> Panel:
        if self.feed:
            body: Any = Group(*self.feed)
        else:
            body = Align.center(Text("waiting for activity…", style="dim"), vertical="middle")
        return Panel(
            body,
            title=Text("📡 Live activity", style=f"bold {_ACCENT}"),
            title_align="left",
            box=ROUNDED,
            border_style="grey37",
        )

    def render_footer(self) -> Panel:
        counts = self._finding_counts()
        tally = self._severity_tally()
        sev_txt = Text()
        for sev in ("critical", "high", "medium", "low", "info"):
            if tally.get(sev):
                sev_txt.append(f" {sev[0].upper()}{tally[sev]}", style=_SEVERITY_STYLE.get(sev, "white"))
        parts = Text.assemble(
            (next(self._spinner), _ACCENT_BRIGHT),
            ("  dispatches ", "dim"),
            (str(len(self.dispatches)), "bold white"),
            ("   ✓ verified ", "dim"),
            (str(counts["verified"]), "bold green"),
            ("   • confirmed ", "dim"),
            (str(counts["confirmed"]), "green"),
            ("   … candidate ", "dim"),
            (str(counts["candidate"]), "yellow"),
            ("    severity", "dim"),
        )
        parts.append_text(sev_txt)
        if self.logs:
            parts.append("    " + self.logs[-1], style="dim italic")
        return Panel(parts, box=ROUNDED, border_style=_ACCENT, padding=(0, 1))

    def render(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(self.render_header(), name="header", size=4),
            Layout(name="body", ratio=1),
            Layout(self.render_feed(), name="feed", size=_MAX_FEED + 2),
            Layout(self.render_footer(), name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(self.render_dispatches(), name="dispatches", ratio=3),
            Layout(self.render_findings(), name="findings", ratio=2),
        )
        return layout


def _budget_bar(spent: int, total: int) -> Text:
    if total <= 0:
        return Text(f"{spent}", style="white")
    width = 10
    filled = min(width, round(width * spent / total)) if total else 0
    ratio = spent / total if total else 0.0
    color = "green" if ratio < 0.66 else "yellow" if ratio < 0.9 else "red"
    bar = Text()
    bar.append("█" * filled, style=color)
    bar.append("░" * (width - filled), style="grey37")
    bar.append(f" {spent}/{total}", style="white")
    return bar


# ------------------------------------------------------------------------- #
# Public interface                                                          #
# ------------------------------------------------------------------------- #


async def run_tui(queue: asyncio.Queue, *, target: str, model: str, objective: str) -> None:
    """Drain ``queue`` and paint the live dashboard until a ``done`` event / ``None``.

    Never raises on a malformed event; returns when the ``{"kind":"done"}`` event
    arrives or the queue yields a ``None`` sentinel.
    """

    dash = _Dashboard(target=target, model=model, objective=objective)
    console = Console()
    with Live(
        dash.render(),
        console=console,
        refresh_per_second=8,
        screen=False,
        transient=False,
    ) as live:
        while True:
            ev = await queue.get()
            if ev is None:
                break
            if not isinstance(ev, dict):
                continue
            dash.apply(ev)
            live.update(dash.render(), refresh=True)
            if ev.get("kind") == "done":
                break


def render_summary(report: Any, out_dir: str | None = None) -> None:
    """Print a final static summary of a promoted :class:`a2pwn.report.Report`."""

    console = Console()
    engagement = getattr(report, "engagement", "engagement")
    findings = list(getattr(report, "findings", []) or [])
    cross_chains = list(getattr(report, "cross_chains", []) or [])
    stats = dict(getattr(report, "stats", {}) or {})
    har_paths = list(getattr(report, "har_paths", []) or [])

    console.print()
    console.print(
        Panel(
            Align.center(
                Text.assemble(
                    ("a2pwn ", f"bold {_ACCENT_BRIGHT}"),
                    ("engagement complete", "bold white"),
                    (f"\n{engagement}", "dim"),
                )
            ),
            box=ROUNDED,
            border_style=_ACCENT,
        )
    )

    if not findings:
        console.print(
            Panel(
                Text("No independently verified findings.", style="dim italic"),
                title="Findings",
                title_align="left",
                border_style="grey37",
                box=ROUNDED,
            )
        )
    else:
        table = Table(box=ROUNDED, border_style="grey37", expand=True, title="Verified findings")
        table.add_column("sev", no_wrap=True)
        table.add_column("vuln class")
        table.add_column("variant", style="dim")
        table.add_column("target", overflow="fold")
        table.add_column("param", style="dim")
        for f in findings:
            sev = str(getattr(f, "severity", "info"))
            table.add_row(
                Text(sev.upper(), style=_SEVERITY_STYLE.get(sev, "white")),
                Text(str(getattr(f, "vuln_class", "?")), style=_SEVERITY_STYLE.get(sev, "white")),
                str(getattr(f, "sub_variant", "") or "—"),
                str(getattr(f, "target", "?")),
                str(getattr(f, "param", "") or "*"),
            )
        console.print(table)

    # Severity tally
    by_sev: dict[str, int] = dict(stats.get("by_severity") or {})
    if not by_sev:
        for f in findings:
            sev = str(getattr(f, "severity", "info"))
            by_sev[sev] = by_sev.get(sev, 0) + 1
    if by_sev:
        tally = Text("  ")
        for sev in ("critical", "high", "medium", "low", "info"):
            if by_sev.get(sev):
                tally.append(f" {sev} {by_sev[sev]} ", style=_SEVERITY_STYLE.get(sev, "white"))
        console.print(Text.assemble(("Count by severity:", "bold"), tally))

    # Cross-chains
    if cross_chains:
        chain_lines = Group(
            *[
                Text.assemble(("  ⛓ ", _ACCENT), (" → ".join(str(k) for k in chain), "white"))
                for chain in cross_chains
            ]
        )
        console.print(
            Panel(chain_lines, title="Cross-chains", title_align="left", border_style="grey37", box=ROUNDED)
        )

    # Artifact paths
    art = Text()
    report_md = None
    if out_dir is not None:
        import os

        report_md = os.path.join(out_dir, "report.md")
        art.append("  report.md : ", style="dim")
        art.append(report_md + "\n", style="cyan")
    if har_paths:
        art.append("  HAR       : ", style="dim")
        art.append("\n              ".join(har_paths), style="cyan")
    if art.plain.strip():
        console.print(Panel(art, title="Artifacts", title_align="left", border_style="grey37", box=ROUNDED))


# ------------------------------------------------------------------------- #
# Synthetic demo (eyeball only) — never runs on import.                     #
# ------------------------------------------------------------------------- #


async def _demo() -> None:  # pragma: no cover - manual visual check
    import random

    queue: asyncio.Queue = asyncio.Queue()

    async def feed() -> None:
        await queue.put({"kind": "engagement", "target": "https://ginandjuice.shop",
                         "model": "claude-opus-4", "objective": "Full-scope web pentest"})
        dispatches = [f"d{i}-{name}" for i, name in enumerate(("sqli", "ssrf", "idor", "xss"))]
        vulns = ["sql_injection", "ssrf", "idor", "reflected_xss", "auth_bypass"]
        for rnd in range(1, 4):
            await queue.put({"kind": "phase", "phase": "planning", "round": rnd,
                             "spent": rnd * 4, "max": 20})
            await asyncio.sleep(0.4)
            for did in dispatches[: rnd + 1]:
                intent = "verify" if "xss" in did else "task"
                await queue.put({"kind": "dispatch_start", "id": did, "intent": intent,
                                 "task": f"probe {did.split('-')[1]} on /api"})
                await asyncio.sleep(0.15)
            for _ in range(6):
                did = random.choice(dispatches[: rnd + 1])
                stage = random.choice(("exploit", "verify", "clarify"))
                await queue.put({"kind": "activity", "dispatch": did, "stage": stage,
                                 "text": f"burpwn_exec curl -si https://ginandjuice.shop/api/x?q={random.randint(1,99)}"})
                await queue.put({"kind": "thought", "dispatch": did,
                                 "text": "response length differs, likely injectable"})
                await asyncio.sleep(0.25)
            for did in dispatches[: rnd + 1]:
                v = random.choice(vulns)
                sev = random.choice(("critical", "high", "medium", "low", "info"))
                await queue.put({"kind": "finding", "status": "candidate", "vuln_class": v,
                                 "severity": sev, "target": f"https://ginandjuice.shop/{v}"})
                await asyncio.sleep(0.1)
                await queue.put({"kind": "finding", "status": "verified", "vuln_class": v,
                                 "severity": sev, "target": f"https://ginandjuice.shop/{v}"})
                await queue.put({"kind": "dispatch_end", "id": did,
                                 "status": random.choice(("confirmed", "partial", "no_finding")),
                                 "n_findings": random.randint(0, 3)})
                await asyncio.sleep(0.15)
        await queue.put({"kind": "log", "level": "warning", "text": "budget nearly exhausted"})
        await queue.put({"kind": "done", "report": "report.md", "har": [], "n_verified": 3})

    task = asyncio.create_task(feed())
    await run_tui(queue, target="https://ginandjuice.shop", model="claude-opus-4",
                  objective="Full-scope web pentest")
    await task


if __name__ == "__main__":  # pragma: no cover
    asyncio.run(_demo())
