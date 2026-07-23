"""report_finding builds a Finding artifact tied to a captured flow batch."""

from __future__ import annotations

from langchain_core.messages import ToolMessage

from a2pwn.models import Finding
from a2pwn.tools.finding_tools import finding_tools


async def test_report_finding_emits_finding_artifact(fake_client):
    tool = finding_tools(fake_client)[0]
    assert tool.name == "report_finding"
    msg = await tool.ainvoke(
        {
            "args": {
                "vuln_class": "sqli",
                "severity": "critical",
                "target": "https://demo.testfire.net/login.jsp",
                "param": "uid",
                "evidence": "auth bypass with ' or '1'='1",
                "flow_ids": [15, 16],
                "oracle_kind": "differential",
                "workspace": "sqli-poc",
            },
            "id": "call-1",
            "name": "report_finding",
            "type": "tool_call",
        }
    )
    assert isinstance(msg, ToolMessage)
    finding = msg.artifact
    assert isinstance(finding, Finding)
    assert finding.vuln_class == "sqli"
    assert finding.severity == "critical"
    assert finding.flow_batch.flow_ids == [15, 16]
    assert finding.key == Finding.make_key("sqli", "https://demo.testfire.net/login.jsp", "uid")


async def test_report_finding_accepts_state_change_oracle(fake_client):
    """Regression: state_change (the business-logic/CSRF oracle, CHANGELOG-shipped) was missing
    from _ORACLES, so every state_change finding was silently rewritten to "signature" here — the
    adjudicator then re-derived the WRONG oracle against the wrong flow shape and rejected
    genuinely-proven findings with no signal to the operator."""
    tool = finding_tools(fake_client)[0]
    msg = await tool.ainvoke(
        {
            "args": {
                "vuln_class": "broken-access-control",
                "severity": "high",
                "target": "https://api.example.com/subscribers",
                "evidence": "marker present before, absent after an unauthenticated delete",
                "flow_ids": [10, 11],
                "oracle_kind": "state_change",
                "oracle_expect": {"must_disappear": "marker-xyz"},
            },
            "id": "call-sc",
            "name": "report_finding",
            "type": "tool_call",
        }
    )
    assert msg.artifact.oracle_kind == "state_change"


async def test_report_finding_bad_enums_default_safely(fake_client):
    tool = finding_tools(fake_client)[0]
    msg = await tool.ainvoke(
        {
            "args": {
                "vuln_class": "xss",
                "severity": "spicy",  # invalid -> medium
                "target": "https://x/",
                "evidence": "reflected",
                "flow_ids": [1],
                "oracle_kind": "vibes",  # invalid -> signature
            },
            "id": "call-2",
            "name": "report_finding",
            "type": "tool_call",
        }
    )
    assert msg.artifact.severity == "medium"
    assert msg.artifact.oracle_kind == "signature"


async def test_report_finding_threads_oracle_inputs_and_exec_ids(fake_client):
    tool = finding_tools(fake_client)[0]
    msg = await tool.ainvoke(
        {
            "args": {
                "vuln_class": "ssrf",
                "severity": "high",
                "target": "https://app.example.com/fetch",
                "param": "url",
                "evidence": "blind SSRF confirmed by OOB callback",
                "flow_ids": [21],
                "oracle_kind": "oob",
                "exec_ids": ["exec-9"],
                "oracle_signals": ["nslookup", "http-hit"],
                "correlation_id": "corr-abc123",
                "oracle_expect": {"threshold_ms": 5000},
            },
            "id": "call-3",
            "name": "report_finding",
            "type": "tool_call",
        }
    )
    finding = msg.artifact
    # oracle inputs threaded onto the Finding so the verifier can faithfully replay it
    assert finding.oracle_signals == ["nslookup", "http-hit"]
    assert finding.correlation_id == "corr-abc123"
    assert finding.oracle_expect == {"threshold_ms": 5000}
    # exec ids threaded onto the flow batch so the sandbox-escape alarm can attribute them
    assert finding.flow_batch.exec_ids == ["exec-9"]


async def test_report_finding_threads_cvss_and_cwe(fake_client):
    tool = finding_tools(fake_client)[0]
    msg = await tool.ainvoke(
        {
            "args": {
                "vuln_class": "broken-access-control",
                "severity": "high",
                "target": "https://api.example.com/metrics",
                "evidence": "unauthenticated internal metrics",
                "flow_ids": [1],
                "oracle_kind": "differential",
                "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "cwe_ids": ["CWE-306", "CWE-200"],
            },
            "id": "call-4",
            "name": "report_finding",
            "type": "tool_call",
        }
    )
    finding = msg.artifact
    assert finding.cvss_vector == "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    assert finding.cwe_ids == ["CWE-306", "CWE-200"]
