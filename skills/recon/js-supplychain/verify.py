"""Deterministic JS supply-chain oracle.

A dependency version-match is explicitly **not** a finding. Confirmation requires
live proof, in priority order:

1. an out-of-band gadget callback carrying the ``correlation_id`` (gadget fired);
2. a leaked bundle secret that authorizes against the live API (``secret_flow``
   returns ``2xx``);
3. an exploited-behaviour marker (``signals``) present in a live response flow.

Otherwise the oracle abstains — do NOT report a version-only match.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult, oob, signature


def _status(detail: dict) -> int | None:
    resp = (detail or {}).get("response") or {}
    status = resp.get("status")
    return status if isinstance(status, int) else None


async def verify(ctx: dict) -> OracleResult:
    client = ctx.get("client")
    collab = ctx.get("collaborator") or ctx.get("collab")
    correlation_id = ctx.get("correlation_id")

    # (1) gadget fired out-of-band (proto-pollution / DOM-clobbering / SSRF gadget)
    if collab is not None and correlation_id:
        oob_res = await oob(collab, correlation_id)
        if oob_res.confirmed:
            return oob_res

    # (2) leaked bundle secret authorizes against the live API
    secret_flow = ctx.get("secret_flow")
    if client is not None and secret_flow is not None:
        status = _status(await client.req_show(secret_flow, raw=False))
        if isinstance(status, int) and 200 <= status < 400:
            return OracleResult(
                confirmed=True,
                kind="signature",
                evidence=f"js-supplychain: leaked bundle secret authorized "
                f"(flow {secret_flow} status {status})",
                flow_ids=[secret_flow],
            )

    # (3) exploited-behaviour marker in a live response
    flow_id = ctx.get("flow_id")
    signals = ctx.get("signals")
    if client is not None and flow_id is not None and signals:
        sig_res = await signature(client, flow_id, signals)
        if sig_res.confirmed:
            return sig_res

    return OracleResult(
        confirmed=False,
        kind="signature",
        evidence="js-supplychain: dependency version-match only; vulnerable path not proven to "
        "fire on the live target (0-FP: abstain, do NOT report)",
    )
