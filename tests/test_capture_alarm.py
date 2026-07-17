"""Guard: a network exec that captured zero flows is a loud ALARM.

``session_stats.escaped_execs`` lists network-facing execs whose flow_count was
0 — traffic that escaped the sandbox. ``assert_capture`` must reject any batch
whose exec ids appear there, and pass only when capture is proven.
"""

from a2pwn.burpwn import FlowBatchManager
from a2pwn.models import FlowBatchRef


def _ref() -> FlowBatchRef:
    return FlowBatchRef(workspace="probe", workspace_id=4, tag="probe")


async def test_assert_capture_flags_escaped_exec(fake_client):
    fake_client.stats = {
        "total_execs": 1,
        "network_execs": 1,
        "network_zero_flow_execs": 1,
        "escaped_execs": [{"exec_id": "e-escaped", "cmd": "curl https://t/"}],
    }
    fbm = FlowBatchManager(fake_client)
    ok, reason = await fbm.assert_capture(_ref(), ["e-escaped"])
    assert ok is False
    assert "ALARM" in reason
    assert "e-escaped" in reason


async def test_assert_capture_passes_when_captured(fake_client):
    fake_client.stats = {
        "total_execs": 1,
        "network_execs": 1,
        "network_zero_flow_execs": 0,
        "escaped_execs": [],
    }
    fbm = FlowBatchManager(fake_client)
    ok, reason = await fbm.assert_capture(_ref(), ["e-good"])
    assert ok is True
    assert reason == ""


async def test_assert_capture_ignores_unrelated_escaped_execs(fake_client):
    # An escaped exec from a different batch must not fail this one.
    fake_client.stats = {"escaped_execs": [{"exec_id": "other", "cmd": "nmap"}]}
    fbm = FlowBatchManager(fake_client)
    ok, _ = await fbm.assert_capture(_ref(), ["mine"])
    assert ok is True
