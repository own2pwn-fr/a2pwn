"""tls-passthru invariant: a flow captured as protocol ``tls-passthru`` (cert-pinned
or QUIC target the MITM could not open) makes the batch *not testable* — the finding
must be reported ``blocked``, never a false-negative ``no_finding``."""

from a2pwn.burpwn import FlowBatchManager
from a2pwn.models import CleanResult, FlowBatchRef


class FakeClient:
    """Answers both possible FlowBatchManager read paths (req_list over the workspace,
    or req_show per flow id) with a preset protocol per flow id."""

    def __init__(self, protocols_by_id: dict[int, str]):
        self.protocols_by_id = protocols_by_id

    async def req_list(
        self, workspace_id=None, host=None, protocol=None, status=None, method=None, limit=None
    ):
        flows = [
            {"id": i, "workspace_id": workspace_id, "protocol": p}
            for i, p in self.protocols_by_id.items()
        ]
        if protocol is not None:
            flows = [f for f in flows if f["protocol"] == protocol]
        return {"flows": flows, "count": len(flows)}

    async def req_show(self, id, raw=False):
        return {"id": id, "protocol": self.protocols_by_id.get(id)}


def _ref():
    return FlowBatchRef(workspace="idor-poc", workspace_id=3, tag="idor", flow_ids=[10, 11])


async def test_tls_passthru_flow_marks_batch_blocked():
    client = FakeClient({10: "h1", 11: "tls-passthru"})
    mgr = FlowBatchManager(client)
    blocked = await mgr.tls_passthru_blocked(_ref())
    assert blocked is True

    # invariant: a blocked batch is reported 'blocked', NEVER silently 'no_finding'
    status = "blocked" if blocked else "no_finding"
    assert status == "blocked"
    assert status != "no_finding"
    result = CleanResult(dispatch_id="d1", status=status)
    assert result.status == "blocked"


async def test_all_plain_http_flows_not_blocked():
    client = FakeClient({10: "h1", 11: "h2"})
    mgr = FlowBatchManager(client)
    blocked = await mgr.tls_passthru_blocked(_ref())
    assert blocked is False

    status = "blocked" if blocked else "no_finding"
    assert status == "no_finding"


async def test_blocked_is_a_valid_distinct_cleanresult_status():
    # schema-level guard: 'blocked' and 'no_finding' are distinct terminal states
    assert CleanResult(dispatch_id="x", status="blocked").status != (
        CleanResult(dispatch_id="x", status="no_finding").status
    )
