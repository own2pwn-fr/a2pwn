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


async def test_report_finding_bad_enums_default_safely(fake_client):
    tool = finding_tools(fake_client)[0]
    msg = await tool.ainvoke(
        {
            "args": {
                "vuln_class": "xss",
                "severity": "spicy",       # invalid -> medium
                "target": "https://x/",
                "evidence": "reflected",
                "flow_ids": [1],
                "oracle_kind": "vibes",    # invalid -> signature
            },
            "id": "call-2",
            "name": "report_finding",
            "type": "tool_call",
        }
    )
    assert msg.artifact.severity == "medium"
    assert msg.artifact.oracle_kind == "signature"
