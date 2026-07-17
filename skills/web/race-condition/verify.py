"""Deterministic race-condition oracle.

Counts the successful (``2xx``/``3xx``) state-changing flows captured in the burst
workspace and confirms only when that count exceeds the intended limit
(``expect_max``, default 1) — i.e. the per-user/per-object cap was overrun.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult


def _flow_status(row: dict) -> int | None:
    status = row.get("status")
    return status if isinstance(status, int) else None


async def verify(ctx: dict) -> OracleResult:
    client = ctx.get("client")
    workspace_id = ctx.get("workspace_id")
    expect_max = int(ctx.get("expect_max", 1))
    path_sub = ctx.get("path")

    if client is None or workspace_id is None:
        return OracleResult(
            confirmed=False,
            kind="differential",
            evidence="race: need client + workspace_id of the burst batch (abstain)",
        )

    res = await client.req_list(workspace_id=workspace_id)
    flows = res.get("flows", []) if isinstance(res, dict) else list(res)

    successes: list[int] = []
    for row in flows:
        status = _flow_status(row)
        if status is None or not (200 <= status < 400):
            continue
        if path_sub and path_sub not in (row.get("path") or ""):
            continue
        flow_id = row.get("id")
        if isinstance(flow_id, int):
            successes.append(flow_id)

    confirmed = len(successes) > expect_max
    evidence = (
        f"race: {len(successes)} successful state-changing responses in workspace "
        f"{workspace_id} (limit {expect_max}) => "
        f"{'limit overrun' if confirmed else 'within limit'}"
    )
    return OracleResult(
        confirmed=confirmed, kind="differential", evidence=evidence, flow_ids=successes
    )
