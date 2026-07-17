"""Deterministic deserialization oracle.

Primary: an out-of-band callback (URLDNS-style) carrying the ``correlation_id``
proves the blob was deserialized. Fallback: a signature match for RCE command
output in the target flow. A blob that merely round-trips is not a finding.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult, oob, signature

_RCE_SIGNALS = ["uid=", "gid=", "groups=", "root:x:0:0:"]


async def verify(ctx: dict) -> OracleResult:
    collab = ctx.get("collaborator") or ctx.get("collab")
    correlation_id = ctx.get("correlation_id")
    if collab is not None and correlation_id:
        oob_res = await oob(collab, correlation_id)
        if oob_res.confirmed:
            return oob_res

    client = ctx.get("client")
    flow_id = ctx.get("flow_id")
    signals = ctx.get("signals") or _RCE_SIGNALS
    if client is not None and flow_id is not None:
        return await signature(client, flow_id, signals)

    return OracleResult(
        confirmed=False,
        kind="oob",
        evidence="deserialization: no OOB callback and no RCE-output flow to inspect (abstain)",
    )
