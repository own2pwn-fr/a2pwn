"""Report assembly: only independently_verified findings are promoted, and a HAR
is exported exactly once per distinct evidence workspace."""

from __future__ import annotations

import json

from a2pwn.config import EngagementSpec
from a2pwn.models import Finding, FlowBatchRef
from a2pwn.report import build_report, render_markdown


def _finding(
    vuln_class: str,
    target: str,
    param: str | None,
    *,
    workspace: str,
    severity: str = "high",
    independently_verified: bool = True,
    confirmed: bool = True,
    enables: list[str] | None = None,
) -> Finding:
    return Finding(
        key=Finding.make_key(vuln_class, target, param),
        vuln_class=vuln_class,
        severity=severity,
        target=target,
        param=param,
        evidence=f"{vuln_class} proof on {param}",
        confirmed=confirmed,
        independently_verified=independently_verified,
        oracle_kind="differential",
        flow_batch=FlowBatchRef(
            workspace=workspace,
            workspace_id=hash(workspace) % 1000,
            tag=vuln_class,
            flow_ids=[1, 2],
            key_flow=1,
            note=f"{vuln_class} note",
        ),
        enables=enables or [],
    )


def _engagement() -> EngagementSpec:
    return EngagementSpec(name="acme", targets=["https://app.example.com"], session="acme")


def _record_har(client) -> list[tuple[str, str, int | None]]:
    calls: list[tuple[str, str, int | None]] = []

    def cli_export_har(session: str, out: str, workspace_id: int | None = None) -> dict:
        calls.append((session, out, workspace_id))
        open(out, "w").close()  # the real export writes a file; build_report only lists existing ones
        return {"path": out}

    client.cli_export_har = cli_export_har  # type: ignore[method-assign]
    return calls


async def test_only_independently_verified_promoted(fake_client, tmp_path):
    _record_har(fake_client)
    ssrf = Finding.make_key("ssrf", "https://app.example.com/fetch", "url")
    findings = [
        _finding("xss", "https://app.example.com/s", "q", workspace="xss-poc", enables=[ssrf]),
        _finding("ssrf", "https://app.example.com/fetch", "url", workspace="ssrf-poc"),
        # confirmed-but-not-independently-verified: must NOT be promoted
        _finding(
            "sqli",
            "https://app.example.com/id",
            "id",
            workspace="sqli-poc",
            independently_verified=False,
            confirmed=True,
        ),
        # bare candidate: must NOT be promoted
        _finding(
            "idor",
            "https://app.example.com/obj",
            "oid",
            workspace="idor-poc",
            independently_verified=False,
            confirmed=False,
        ),
    ]
    state = {"engagement": _engagement(), "findings": findings, "objective": "x"}

    report = await build_report(state, fake_client, str(tmp_path))

    promoted_classes = {f.vuln_class for f in report.findings}
    assert promoted_classes == {"xss", "ssrf"}
    assert all(f.independently_verified for f in report.findings)
    assert report.engagement == "acme"
    assert report.stats["total_findings"] == 2


async def test_har_exported_once_per_workspace(fake_client, tmp_path):
    calls = _record_har(fake_client)
    findings = [
        # two promoted findings sharing ONE workspace -> a single HAR export
        _finding("xss", "https://app.example.com/a", "q", workspace="shared-ws"),
        _finding("csrf", "https://app.example.com/b", "t", workspace="shared-ws"),
        _finding("ssrf", "https://app.example.com/c", "url", workspace="ssrf-ws"),
        # non-promoted: its workspace must never be exported
        _finding(
            "sqli",
            "https://app.example.com/d",
            "id",
            workspace="ghost-ws",
            independently_verified=False,
        ),
    ]
    state = {"engagement": _engagement(), "findings": findings, "objective": "x"}

    report = await build_report(state, fake_client, str(tmp_path))

    exported = [out for _session, out, _wid in calls]
    # a whole-session evidence HAR + one per DISTINCT promoted workspace (shared-ws deduped)
    assert str(tmp_path / "evidence-all.har") in exported
    assert str(tmp_path / "shared-ws.har") in exported
    assert str(tmp_path / "ssrf-ws.har") in exported
    assert len(calls) == 3  # evidence-all + shared-ws + ssrf-ws (shared-ws exported once)
    assert all(session == "acme" for session, _out, _wid in calls)
    assert not any("ghost-ws" in out for out in exported)
    assert sorted(report.har_paths) == sorted(exported)


async def test_one_failing_har_export_still_builds_the_report(fake_client, tmp_path):
    # A single workspace whose HAR export raises must not lose the whole report: the other
    # workspaces are still exported and the report is returned with the surviving HAR paths.
    def cli_export_har(session: str, out: str, workspace_id: int | None = None) -> dict:
        if "boom-ws" in out:
            raise RuntimeError("burpwn export har failed for this workspace")
        open(out, "w").close()
        return {"path": out}

    fake_client.cli_export_har = cli_export_har  # type: ignore[method-assign]
    findings = [
        _finding("xss", "https://app.example.com/a", "q", workspace="ok-ws"),
        _finding("ssrf", "https://app.example.com/c", "url", workspace="boom-ws"),
    ]
    state = {"engagement": _engagement(), "findings": findings, "objective": "x"}

    report = await build_report(state, fake_client, str(tmp_path))

    # boom-ws raises and is skipped; the whole-session evidence + ok-ws still export.
    assert str(tmp_path / "evidence-all.har") in report.har_paths
    assert str(tmp_path / "ok-ws.har") in report.har_paths
    assert not any("boom-ws" in p for p in report.har_paths)
    assert {f.vuln_class for f in report.findings} == {"xss", "ssrf"}
    assert report.stats["evidence_workspaces"] == 2  # both workspaces are still evidence


async def test_cross_chains_and_markdown(fake_client, tmp_path):
    _record_har(fake_client)
    ssrf_key = Finding.make_key("ssrf", "https://app.example.com/fetch", "url")
    rce_key = Finding.make_key("rce", "https://internal/admin", None)
    findings = [
        _finding(
            "xss",
            "https://app.example.com/s",
            "q",
            workspace="xss-poc",
            severity="medium",
            enables=[ssrf_key],
        ),
        _finding(
            "ssrf",
            "https://app.example.com/fetch",
            "url",
            workspace="ssrf-poc",
            severity="high",
            enables=[rce_key],
        ),
        _finding("rce", "https://internal/admin", None, workspace="rce-poc", severity="critical"),
    ]
    state = {"engagement": _engagement(), "findings": findings, "objective": "x"}

    report = await build_report(state, fake_client, str(tmp_path))

    xss_key = Finding.make_key("xss", "https://app.example.com/s", "q")
    assert [xss_key, ssrf_key, rce_key] in report.cross_chains
    assert report.stats["cross_chains"] == 1

    md = render_markdown(report)
    assert "# a2pwn report — acme" in md
    assert "Cross-chain map" in md
    assert "critical" in md.lower()
    # most-severe finding renders first
    assert md.index("rce") < md.index("xss")


async def test_confirmed_not_reproduced_tier_split(fake_client, tmp_path):
    # A confirmed-but-not-independently-verified finding must land in the SEPARATE confirmed tier
    # (never the strict verified tier) and be rendered across json/sarif/html.
    _record_har(fake_client)
    findings = [
        _finding("xss", "https://app.example.com/s", "q", workspace="xss-poc"),  # verified
        _finding(
            "sqli",
            "https://app.example.com/id",
            "id",
            workspace="sqli-poc",
            severity="critical",
            independently_verified=False,  # oracle-confirmed, not reproduced -> tier 2
            confirmed=True,
        ),
    ]
    state = {"engagement": _engagement(), "findings": findings, "objective": "audit the shop"}

    report = await build_report(state, fake_client, str(tmp_path))

    # strict tier keeps only the verified finding; the confirmed-only sqli is quarantined.
    assert {f.vuln_class for f in report.findings} == {"xss"}
    assert {f.vuln_class for f in report.confirmed_findings} == {"sqli"}
    assert report.stats["total_findings"] == 1
    assert report.stats["confirmed_only"] == 1
    # metadata threaded through from the terminal state.
    assert report.objective == "audit the shop"
    assert report.targets == ["https://app.example.com"]

    # all four artifacts written and discoverable via report_paths.
    for key in ("md", "json", "sarif", "html"):
        assert key in report.report_paths
        assert (tmp_path / f"report.{key}").exists()

    # JSON carries both tiers distinctly.
    data = json.loads((tmp_path / "report.json").read_text())
    assert [f["vuln_class"] for f in data["findings"]] == ["xss"]
    assert [f["vuln_class"] for f in data["confirmed_findings"]] == ["sqli"]

    # SARIF: the confirmed-only sqli is present and tagged as not reproduced.
    sarif = json.loads((tmp_path / "report.sarif").read_text())
    results = sarif["runs"][0]["results"]
    tiers = {r["ruleId"]: r["properties"]["proofTier"] for r in results}
    assert tiers == {"xss": "verified", "sqli": "confirmed_not_reproduced"}
    assert sarif["version"] == "2.1.0"

    # HTML: both classes appear, the confirmed tier is clearly labelled.
    html_doc = (tmp_path / "report.html").read_text()
    assert "sqli" in html_doc and "xss" in html_doc
    assert "not independently reproduced" in html_doc.lower()


async def test_format_selection_gates_sarif_and_html(fake_client, tmp_path):
    _record_har(fake_client)
    findings = [_finding("xss", "https://app.example.com/s", "q", workspace="xss-poc")]
    state = {"engagement": _engagement(), "findings": findings, "objective": "x"}

    report = await build_report(state, fake_client, str(tmp_path), formats=["md", "json"])

    # md + json always written; sarif/html suppressed when not requested.
    assert set(report.report_paths) == {"md", "json"}
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.json").exists()
    assert not (tmp_path / "report.sarif").exists()
    assert not (tmp_path / "report.html").exists()
