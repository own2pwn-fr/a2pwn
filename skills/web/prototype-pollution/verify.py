"""Deterministic prototype-pollution oracle.

Server-side: a differential between the baseline response (``flow_a``) and the
polluted response (``flow_b``) — a status change, body reformat, or length delta
proves the polluted global changed behaviour. Gadget-to-RCE/SSRF is proven via
the out-of-band oracle when a ``correlation_id`` + collaborator are present.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult, differential, oob


async def verify(ctx: dict) -> OracleResult:
    collab = ctx.get("collaborator") or ctx.get("collab")
    correlation_id = ctx.get("correlation_id")
    if collab is not None and correlation_id:
        oob_res = await oob(collab, correlation_id)
        if oob_res.confirmed:
            return oob_res

    client = ctx.get("client")
    flow_a = ctx.get("flow_a")
    flow_b = ctx.get("flow_b")
    if client is None or flow_a is None or flow_b is None:
        return OracleResult(
            confirmed=False,
            kind="differential",
            evidence="proto-pollution: need flow_a (baseline) + flow_b (polluted) (abstain)",
        )

    expect = dict(ctx.get("expect") or {})
    expect.setdefault("signal", "any")
    return await differential(client, flow_a, flow_b, expect)
