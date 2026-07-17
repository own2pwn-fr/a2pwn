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


async def test_assert_capture_flags_network_zero_flow_exec(fake_client):
    # A network exec that captured 0 flows is reported via network_zero_flow_execs
    # (list-of-id shape) — it must ALARM even when escaped_execs is empty.
    fake_client.stats = {
        "total_execs": 1,
        "network_execs": 1,
        "network_zero_flow_execs": ["e-zero"],
        "escaped_execs": [],
    }
    fbm = FlowBatchManager(fake_client)
    ok, reason = await fbm.assert_capture(_ref(), ["e-zero"])
    assert ok is False
    assert "ALARM" in reason
    assert "e-zero" in reason


async def test_assert_capture_handles_plain_string_escaped_shape(fake_client):
    # escaped_execs may be a list of bare id strings, not dicts — must not crash.
    fake_client.stats = {"escaped_execs": ["e-escaped"]}
    fbm = FlowBatchManager(fake_client)
    ok, reason = await fbm.assert_capture(_ref(), ["e-escaped"])
    assert ok is False
    assert "e-escaped" in reason


async def test_assert_capture_no_exec_ids_rejects_when_something_escaped(fake_client):
    # With no exec ids to attribute AND an escaped exec in the session, capture is not
    # provable — must ALARM rather than silently pass because exec_ids is empty.
    fake_client.stats = {"escaped_execs": [{"exec_id": "leaked"}]}
    ref = FlowBatchRef(workspace="probe", workspace_id=4, tag="probe", flow_ids=[1, 2])
    fbm = FlowBatchManager(fake_client)
    ok, reason = await fbm.assert_capture(ref, [])
    assert ok is False
    assert "ALARM" in reason


async def test_assert_capture_no_exec_ids_no_flows_rejects(fake_client):
    fake_client.stats = {"escaped_execs": []}
    ref = FlowBatchRef(workspace="probe", workspace_id=4, tag="probe", flow_ids=[])
    fbm = FlowBatchManager(fake_client)
    ok, reason = await fbm.assert_capture(ref, [])
    assert ok is False
    assert "cannot prove capture" in reason


async def test_assert_capture_no_exec_ids_with_clean_flows_passes(fake_client):
    fake_client.stats = {"escaped_execs": []}
    ref = FlowBatchRef(workspace="probe", workspace_id=4, tag="probe", flow_ids=[1, 2])
    fbm = FlowBatchManager(fake_client)
    ok, reason = await fbm.assert_capture(ref, [])
    assert ok is True
    assert reason == ""


async def test_assert_capture_falls_back_to_ref_exec_ids(fake_client):
    # When the caller passes no exec_ids, the ref's own exec_ids are consulted.
    fake_client.stats = {"escaped_execs": [{"exec_id": "e-ref"}]}
    ref = FlowBatchRef(
        workspace="probe", workspace_id=4, tag="probe", flow_ids=[1], exec_ids=["e-ref"]
    )
    fbm = FlowBatchManager(fake_client)
    ok, reason = await fbm.assert_capture(ref, [])
    assert ok is False
    assert "e-ref" in reason
