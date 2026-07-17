"""Deterministic XXE oracle.

Primary: an out-of-band exfil callback carrying the ``correlation_id`` proves
blind XXE. Fallback: a signature match for known local-file content (``/etc/passwd``,
Windows ``win.ini``) in the response flow (in-band read).
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult, oob, signature

_FILE_SIGNALS = ["root:x:0:0:", "daemon:x:", "[fonts]", "for 16-bit app support"]


async def verify(ctx: dict) -> OracleResult:
    collab = ctx.get("collaborator") or ctx.get("collab")
    correlation_id = ctx.get("correlation_id")
    if collab is not None and correlation_id:
        oob_res = await oob(collab, correlation_id)
        if oob_res.confirmed:
            return oob_res

    client = ctx.get("client")
    flow_id = ctx.get("flow_id")
    signals = ctx.get("signals") or _FILE_SIGNALS
    if client is not None and flow_id is not None:
        return await signature(client, flow_id, signals)

    return OracleResult(
        confirmed=False,
        kind="oob",
        evidence="xxe: no OOB callback and no in-band flow to inspect (abstain)",
    )
