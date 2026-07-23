"""`limit`-style params are sanitised to burpwn's u16 domain before the MCP call.

Regression: executors routinely pass ``limit=-1`` (meaning "no cap"); burpwn's schema then rejects
it with ``invalid value: integer -1, expected u16`` and the whole req_list/fuzz_results call fails.
Observed live via the a2pwn.executor tool logging on a real engagement.
"""

from __future__ import annotations

from a2pwn.burpwn import BurpwnClient, _u16_or_none


def test_u16_or_none_maps_negative_to_none():
    assert _u16_or_none(-1) is None
    assert _u16_or_none(-9999) is None


def test_u16_or_none_passes_valid_and_clamps_overflow():
    assert _u16_or_none(None) is None
    assert _u16_or_none(0) == 0
    assert _u16_or_none(50) == 50
    assert _u16_or_none(65535) == 65535
    assert _u16_or_none(70000) == 65535  # clamp to u16 max, don't 400 the call


def test_u16_or_none_coerces_and_degrades():
    assert _u16_or_none("10") == 10
    assert _u16_or_none("nope") is None
    assert _u16_or_none(3.9) == 3  # int() truncation, still valid u16


async def test_req_list_omits_negative_limit():
    client = BurpwnClient("s")
    seen: dict = {}

    async def _fake_call(tool, args):
        seen["tool"] = tool
        seen["args"] = args
        return {}

    client._call_tool = _fake_call  # type: ignore[assignment]
    await client.req_list(limit=-1, host="coreapi.example.com")
    assert seen["tool"] == "req_list"
    assert "limit" not in seen["args"]  # negative -> omitted, not sent as -1
    assert seen["args"]["host"] == "coreapi.example.com"


async def test_req_list_keeps_valid_limit():
    client = BurpwnClient("s")
    seen: dict = {}

    async def _fake_call(tool, args):
        seen["args"] = args
        return {}

    client._call_tool = _fake_call  # type: ignore[assignment]
    await client.req_list(limit=25)
    assert seen["args"]["limit"] == 25


async def test_fuzz_results_omits_negative_limit():
    client = BurpwnClient("s")
    seen: dict = {}

    async def _fake_call(tool, args):
        seen["args"] = args
        return {}

    client._call_tool = _fake_call  # type: ignore[assignment]
    await client.fuzz_results(attack_id=7, limit=-1)
    assert "limit" not in seen["args"]
    assert seen["args"]["attack_id"] == 7
