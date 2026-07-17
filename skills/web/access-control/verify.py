"""Deterministic broken-access-control oracle.

Prefers the two-identity differential (privileged response reproduced for the
unprivileged identity). Falls back to a status+signature check on a single
anonymous/low-priv flow: confirmed only when it returned ``2xx`` **and** the body
carries privileged markers.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult, signature, two_identity

_ADMIN_SIGNALS = ['"role":"admin"', "isAdmin", "dashboard", "manage users", "admin panel"]


def _status(detail: dict) -> int | None:
    resp = (detail or {}).get("response") or {}
    status = resp.get("status")
    return status if isinstance(status, int) else None


async def verify(ctx: dict) -> OracleResult:
    client = ctx.get("client")
    a_ref = ctx.get("a_ref")
    b_ref = ctx.get("b_ref")
    if client is not None and a_ref is not None and b_ref is not None:
        return await two_identity(client, a_ref, b_ref)

    flow_id = ctx.get("flow_id")
    if client is None or flow_id is None:
        return OracleResult(
            confirmed=False,
            kind="two_identity",
            evidence="access-control: need (a_ref,b_ref) or a single flow_id (abstain)",
        )

    status = _status(await client.req_show(flow_id, raw=False))
    if not (isinstance(status, int) and 200 <= status < 400):
        return OracleResult(
            confirmed=False,
            kind="signature",
            evidence=f"access-control: unprivileged request flow {flow_id} returned {status} "
            "(control held)",
            flow_ids=[flow_id],
        )

    signals = ctx.get("signals") or _ADMIN_SIGNALS
    return await signature(client, flow_id, signals)
