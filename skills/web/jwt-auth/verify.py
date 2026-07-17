"""Deterministic JWT oracle.

A forged token is confirmed only when it flips a privileged endpoint from a
denial (``401``/``403``) to success (``2xx``/``3xx``). When only the forged flow
is available the oracle still confirms on success but marks the weaker signal.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult


def _status(detail: dict) -> int | None:
    resp = (detail or {}).get("response") or {}
    status = resp.get("status")
    return status if isinstance(status, int) else None


async def verify(ctx: dict) -> OracleResult:
    client = ctx.get("client")
    forged = ctx.get("flow_forged")
    if forged is None:
        forged = ctx.get("flow_id")
    baseline = ctx.get("flow_baseline")
    if baseline is None:
        baseline = ctx.get("flow_a")

    if client is None or forged is None:
        return OracleResult(
            confirmed=False,
            kind="differential",
            evidence="jwt: missing client/forged flow (abstain)",
        )

    forged_status = _status(await client.req_show(forged, raw=False))
    forged_ok = isinstance(forged_status, int) and 200 <= forged_status < 400

    if baseline is not None:
        baseline_status = _status(await client.req_show(baseline, raw=False))
        denied = baseline_status in (401, 403)
        confirmed = forged_ok and denied
        evidence = (
            f"jwt: baseline flow {baseline} status {baseline_status} (denied={denied}) -> "
            f"forged flow {forged} status {forged_status} (accepted={forged_ok})"
        )
        return OracleResult(
            confirmed=confirmed,
            kind="differential",
            evidence=evidence,
            flow_ids=[baseline, forged],
        )

    evidence = (
        f"jwt: forged token flow {forged} status {forged_status} accepted={forged_ok} "
        "(no baseline denial flow provided; weaker signal)"
    )
    return OracleResult(
        confirmed=forged_ok, kind="differential", evidence=evidence, flow_ids=[forged]
    )
