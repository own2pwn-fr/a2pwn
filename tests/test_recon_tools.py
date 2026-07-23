"""propose_targets: recon-discovered follow-up hosts become concrete TaskSpecs, scope-filtered."""

from __future__ import annotations

from types import SimpleNamespace

from langchain_core.messages import ToolMessage

from a2pwn.models import TaskSpec
from a2pwn.tools.recon_tools import recon_tools


def _call(tool, hosts):
    return tool.ainvoke(
        {"args": {"hosts": hosts}, "id": "call-1", "name": "propose_targets", "type": "tool_call"}
    )


async def test_propose_targets_builds_task_specs():
    tool = recon_tools()[0]
    assert tool.name == "propose_targets"
    msg = await _call(
        tool,
        [
            {"host": "coreapi.example.com", "note": "gunicorn, 200 on /"},
            {"host": "https://portal.example.com/", "note": ""},
        ],
    )
    assert isinstance(msg, ToolMessage)
    tasks = msg.artifact
    assert len(tasks) == 2
    assert all(isinstance(t, TaskSpec) for t in tasks)
    assert tasks[0].target == "https://coreapi.example.com"
    assert "gunicorn" in tasks[0].task
    assert tasks[1].target == "https://portal.example.com/"


async def test_propose_targets_skips_blank_hosts():
    tool = recon_tools()[0]
    msg = await _call(tool, [{"host": "  ", "note": "x"}, {"host": "real.example.com"}])
    assert len(msg.artifact) == 1
    assert msg.artifact[0].target == "https://real.example.com"


async def test_propose_targets_no_hosts_returns_empty_artifact():
    tool = recon_tools()[0]
    msg = await _call(tool, [])
    assert msg.artifact == []
    assert "no new targets" in msg.content


async def test_propose_targets_filters_off_scope_hosts():
    eng = SimpleNamespace(targets=["https://app.example.com/"], in_scope=[])
    tool = recon_tools(eng)[0]
    msg = await _call(
        tool,
        [
            {"host": "sub.app.example.com", "note": "in scope"},
            {"host": "evil.attacker.net", "note": "off scope"},
        ],
    )
    targets = {t.target for t in msg.artifact}
    assert targets == {"https://sub.app.example.com"}


async def test_propose_targets_permissive_without_engagement():
    # No engagement given -> no filtering (mirrors burpwn_tools' own default-permissive stance).
    tool = recon_tools()[0]
    msg = await _call(tool, [{"host": "anything.example.com"}])
    assert len(msg.artifact) == 1
