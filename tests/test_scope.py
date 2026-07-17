"""Deterministic scope enforcement: host parsing + in-scope decision + tool refusal.

Prompt text cannot keep an actively-attacking agent in scope; ``a2pwn.scope`` and the
burpwn tool wrappers must refuse out-of-scope destinations (incl. 169.254.169.254)
before any command runs.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from a2pwn.scope import argv_hosts, host_of, in_scope
from a2pwn.tools.burpwn_tools import burpwn_tools


@pytest.mark.parametrize(
    "token,expected",
    [
        ("https://demo.testfire.net/login.jsp", "demo.testfire.net"),
        ("http://169.254.169.254/latest/meta-data/", "169.254.169.254"),
        ("demo.testfire.net", "demo.testfire.net"),
        ("demo.testfire.net:8443", "demo.testfire.net"),
        ("demo.testfire.net/path?x=1", "demo.testfire.net"),
        ("--url=http://evil.example.com/x", "evil.example.com"),
        ("//cdn.example.com/a.js", "cdn.example.com"),
        ("EVIL.Example.COM", "evil.example.com"),
        # non-host argv tokens / payloads must NOT parse as hosts
        ("-H", None),
        ("GET", None),
        ("User-Agent", None),
        ("1' OR '1'='1", None),
        ("application/json", None),
        ("", None),
    ],
)
def test_host_of(token, expected):
    assert host_of(token) == expected


def test_in_scope_exact_and_subdomain():
    targets = ["https://app.example.com/"]
    assert in_scope("app.example.com", targets, []) is True
    assert in_scope("api.app.example.com", targets, []) is True  # subdomain
    assert in_scope("example.com", targets, []) is False  # parent is not in scope
    assert in_scope("evil.com", targets, []) is False
    assert in_scope("169.254.169.254", targets, []) is False


def test_in_scope_prefers_in_scope_list_then_targets():
    assert in_scope("staging.acme.test", ["prod.acme.test"], ["acme.test"]) is True
    assert in_scope("prod.acme.test", ["prod.acme.test"], ["acme.test"]) is True


def test_in_scope_fails_closed_on_empty_allowlist():
    assert in_scope("anything.com", [], []) is False
    assert in_scope("", ["a.com"], []) is False


def test_argv_hosts_extracts_and_dedups():
    argv = ["curl", "-s", "https://a.example.com/x", "https://a.example.com/y", "169.254.169.254"]
    assert argv_hosts(argv) == ["a.example.com", "169.254.169.254"]


def _engagement(targets, allow=None):
    return SimpleNamespace(targets=targets, in_scope=allow or [])


async def test_burpwn_exec_refuses_out_of_scope_host(fake_client):
    eng = _engagement(["https://app.example.com/"])
    tools = {t.name: t for t in burpwn_tools(fake_client, eng)}
    res = await tools["burpwn_exec"].ainvoke(
        {"argv": ["curl", "http://169.254.169.254/latest/meta-data/"]}
    )
    assert res["refused"] is True
    assert res["off_scope_hosts"] == ["169.254.169.254"]
    # nothing was run
    assert fake_client.execs == []


async def test_burpwn_exec_allows_in_scope_host(fake_client):
    eng = _engagement(["https://app.example.com/"])
    tools = {t.name: t for t in burpwn_tools(fake_client, eng)}
    res = await tools["burpwn_exec"].ainvoke(
        {"argv": ["curl", "https://api.app.example.com/health"]}
    )
    assert res == fake_client.exec_return
    assert len(fake_client.execs) == 1


async def test_burpwn_fuzz_refuses_ssrf_payload_to_metadata(fake_client):
    eng = _engagement(["https://app.example.com/"])
    tools = {t.name: t for t in burpwn_tools(fake_client, eng)}
    res = await tools["burpwn_fuzz"].ainvoke(
        {
            "flow": 1,
            "positions": ["§url§"],
            "payloads": ["http://169.254.169.254/latest/meta-data/"],
        }
    )
    assert res["refused"] is True
    assert fake_client.fuzzes == []


async def test_burpwn_req_replay_refuses_offscope_host_header(fake_client):
    eng = _engagement(["https://app.example.com/"])
    tools = {t.name: t for t in burpwn_tools(fake_client, eng)}
    res = await tools["burpwn_req_replay"].ainvoke(
        {"id": 5, "set_headers": [{"name": "Host", "value": "evil.example.org"}]}
    )
    assert res["refused"] is True
    assert fake_client.replays == []


async def test_no_engagement_means_no_enforcement(fake_client):
    tools = {t.name: t for t in burpwn_tools(fake_client)}
    res = await tools["burpwn_exec"].ainvoke(
        {"argv": ["curl", "http://169.254.169.254/"]}
    )
    assert res == fake_client.exec_return
    assert len(fake_client.execs) == 1


async def test_burpwn_exec_refuses_mixed_scope_argv(fake_client):
    # One in-scope + one out-of-scope destination in the same argv => refuse the whole command,
    # reporting only the offending host, and run nothing.
    eng = _engagement(["https://app.example.com/"])
    tools = {t.name: t for t in burpwn_tools(fake_client, eng)}
    res = await tools["burpwn_exec"].ainvoke(
        {"argv": ["curl", "https://api.app.example.com/ok", "http://evil.example.org/x"]}
    )
    assert res["refused"] is True
    assert res["off_scope_hosts"] == ["evil.example.org"]
    assert fake_client.execs == []


async def test_burpwn_exec_allows_argv_without_destination_hosts(fake_client):
    # A local/argv-only command with no parseable destination host is allowed even with enforcement
    # on (nothing to refuse), so scope guarding never blocks legitimate tool invocations.
    eng = _engagement(["https://app.example.com/"])
    tools = {t.name: t for t in burpwn_tools(fake_client, eng)}
    res = await tools["burpwn_exec"].ainvoke({"argv": ["nmap", "-sV", "-Pn"]})
    assert res == fake_client.exec_return
    assert len(fake_client.execs) == 1


async def test_burpwn_fuzz_allows_in_scope_payload_url(fake_client):
    # An absolute-URL payload aimed at an in-scope subdomain must pass the guard and run.
    eng = _engagement(["https://app.example.com/"])
    tools = {t.name: t for t in burpwn_tools(fake_client, eng)}
    res = await tools["burpwn_fuzz"].ainvoke(
        {
            "flow": 1,
            "positions": ["§url§"],
            "payloads": ["https://api.app.example.com/callback"],
        }
    )
    assert res == fake_client.fuzz_return
    assert len(fake_client.fuzzes) == 1
