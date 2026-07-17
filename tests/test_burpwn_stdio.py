"""BurpwnClient stdio transport: a single MCP response line larger than asyncio's default
64 KiB StreamReader limit (captured response bodies can be multi-MiB) must be read, not crash
with LimitOverrunError ("Separator is not found, and chunk exceed the limit")."""

from __future__ import annotations

import sys
import textwrap

import pytest

from a2pwn.burpwn import BurpwnClient

# A minimal stdio JSON-RPC "MCP server": answers `initialize` and returns, for any `tools/call`,
# a result whose text block carries a payload of the requested size. Lets us drive a >64 KiB line
# through the real BurpwnClient read path without needing the burpwn binary.
_FAKE_MCP = textwrap.dedent(
    """
    import sys, json
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        mid = msg.get("id")
        method = msg.get("method")
        if method == "initialize":
            out = {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": "2024-11-05",
                   "serverInfo": {"name": "fake", "version": "0"}, "capabilities": {}}}
        elif method == "notifications/initialized":
            continue
        elif method == "tools/call":
            n = msg["params"]["arguments"].get("size", 0)
            payload = json.dumps({"big": "A" * n})
            out = {"jsonrpc": "2.0", "id": mid,
                   "result": {"content": [{"type": "text", "text": payload}]}}
        else:
            out = {"jsonrpc": "2.0", "id": mid, "result": {}}
        sys.stdout.write(json.dumps(out) + "\\n")
        sys.stdout.flush()
    """
)


async def _client() -> BurpwnClient:
    return BurpwnClient("fake", command=[sys.executable, "-c", _FAKE_MCP])


@pytest.mark.parametrize("size", [1024, 512 * 1024, 4 * 1024 * 1024])
async def test_large_mcp_line_is_read(size):
    client = await _client()
    try:
        result = await client._call_tool("req_show", {"size": size})
    finally:
        await client.close()
    # The raised StreamReader limit lets the multi-MiB single-line response through intact.
    assert result["big"] == "A" * size


# An MCP server that answers exactly ONE tools/call then exits, so the NEXT call hits a dead pipe.
_ONE_SHOT_MCP = textwrap.dedent(
    """
    import sys, json
    served = False
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        mid = msg.get("id")
        method = msg.get("method")
        if method == "initialize":
            out = {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": "2024-11-05",
                   "serverInfo": {"name": "fake", "version": "0"}, "capabilities": {}}}
        elif method == "notifications/initialized":
            continue
        elif method == "tools/call":
            out = {"jsonrpc": "2.0", "id": mid,
                   "result": {"content": [{"type": "text", "text": json.dumps({"ok": True})}]}}
            sys.stdout.write(json.dumps(out) + "\\n")
            sys.stdout.flush()
            sys.exit(0)  # die after serving one call
        else:
            out = {"jsonrpc": "2.0", "id": mid, "result": {}}
        sys.stdout.write(json.dumps(out) + "\\n")
        sys.stdout.flush()
    """
)


async def test_crashed_server_is_respawned():
    # REGRESSION: when `burpwn mcp` dies, `_started` used to stay True and every subsequent call
    # failed forever. The health-check must reap the dead process and respawn on the next call.
    client = BurpwnClient("fake", command=[sys.executable, "-c", _ONE_SHOT_MCP])
    try:
        first = await client._call_tool("session_stats", {})
        assert first == {"ok": True}
        # The server exited after the first call; the second call must transparently reconnect.
        second = await client._call_tool("session_stats", {})
        assert second == {"ok": True}
        assert client._spawns == 2  # one respawn happened
    finally:
        await client.close()


async def test_crash_loop_gives_up():
    # A server that dies immediately (before answering initialize) must not respawn forever.
    from a2pwn.burpwn import BurpwnError

    client = BurpwnClient("fake", command=[sys.executable, "-c", "import sys; sys.exit(1)"])
    try:
        with pytest.raises(BurpwnError):
            await client._call_tool("session_stats", {})
        assert client._spawns <= 4  # bounded by _MAX_SPAWNS
    finally:
        await client.close()
