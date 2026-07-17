"""Deterministic path-traversal / LFI oracle.

Primary: a signature match for known local-file content (``/etc/passwd``,
Windows ``win.ini``) in the target flow proves the read. Fallback: an out-of-band
callback (RFI / ``php://``-style wrapper fetch) carrying the ``correlation_id``.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult, oob, signature

_FILE_SIGNALS = ["root:x:0:0:", "daemon:x:", "[fonts]", "for 16-bit app support", "<?php"]


async def verify(ctx: dict) -> OracleResult:
    client = ctx.get("client")
    flow_id = ctx.get("flow_id")
    signals = ctx.get("signals") or _FILE_SIGNALS

    if client is not None and flow_id is not None:
        sig_res = await signature(client, flow_id, signals)
        if sig_res.confirmed:
            return sig_res

    collab = ctx.get("collaborator") or ctx.get("collab")
    correlation_id = ctx.get("correlation_id")
    if collab is not None and correlation_id:
        return await oob(collab, correlation_id)

    if client is not None and flow_id is not None:
        return OracleResult(
            confirmed=False,
            kind="signature",
            evidence=f"path-traversal: no known-file marker in flow {flow_id} (abstain)",
            flow_ids=[flow_id],
        )
    return OracleResult(
        confirmed=False,
        kind="signature",
        evidence="path-traversal: need flow_id or (collaborator + correlation_id) (abstain)",
    )
