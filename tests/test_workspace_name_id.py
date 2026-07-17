"""Guard: the NAME↔id workspace asymmetry is handled.

MCP ``req_list`` filters by an i64 workspace *id*, while ``exec``/CLI take a
workspace *name*. A batch must therefore resolve the name to an int id once and
filter flows by that int — never leak the name into ``req_list``.
"""

import pytest

from a2pwn.burpwn import FlowBatchManager
from a2pwn.models import FlowBatchRef


async def test_workspace_id_of_resolves_name_to_int(fake_client):
    fake_client.workspaces = [
        {"id": 1, "name": "default"},
        {"id": 7, "name": "sqli-poc"},
    ]
    wid = await fake_client.workspace_id_of("sqli-poc")
    assert wid == 7
    assert isinstance(wid, int)


async def test_workspace_id_of_missing_raises(fake_client):
    with pytest.raises(KeyError):
        await fake_client.workspace_id_of("does-not-exist")


async def test_open_batch_stores_int_workspace_id(fake_client):
    fbm = FlowBatchManager(fake_client)
    ref = await fbm.open_batch("xss-poc")
    assert ref.workspace == "xss-poc"
    assert isinstance(ref.workspace_id, int)
    assert "xss-poc" in fake_client.workspaces_created


async def test_tls_passthru_check_filters_by_int_id_not_name(fake_client):
    # Flows are keyed by the int workspace id; a str name would never match.
    fake_client.flows_by_ws = {9: [{"id": 1, "protocol": "tls-passthru"}]}
    ref = FlowBatchRef(workspace="pinned", workspace_id=9, tag="pin")
    fbm = FlowBatchManager(fake_client)

    assert await fbm.tls_passthru_blocked(ref) is True
    # the id passed to req_list is the int, not the workspace name
    assert fake_client.req_list_calls[-1]["workspace_id"] == 9

    # a batch pointing at an id with only h1 flows is not blocked
    ref2 = FlowBatchRef(workspace="ok", workspace_id=3, tag="ok")
    fake_client.flows_by_ws[3] = [{"id": 2, "protocol": "h1"}]
    assert await fbm.tls_passthru_blocked(ref2) is False
