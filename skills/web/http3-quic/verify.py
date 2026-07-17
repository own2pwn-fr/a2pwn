"""Verification oracle for HTTP/3 / QUIC connection contamination.

Strongest-first: a ``differential`` oracle proving a response served for the
*wrong* host (cross-routing over a coalesced QUIC/h3 or downgraded connection),
then a ``signature`` match of a wrong-host back-end marker. Exposes ``verify(ctx)``
for the adversarial verifier, which builds the class's
:class:`~a2pwn.oracles.VerificationOracle` and delegates to
:func:`~a2pwn.oracles.run_oracle`.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult, VerificationOracle, run_oracle

ORACLE_PRIORITY: tuple[str, ...] = ("differential", "signature")
SIGNALS: list[str] = ["wrong-host", "cross-host", "X-Served-By", "0-RTT", "early-data"]
EXPECT: dict[str, dict] = {"differential": {"signal": "any"}}


def _present(ctx: dict, key: str) -> bool:
    return ctx.get(key) is not None


def _correlation(ctx: dict) -> str | None:
    return ctx.get("correlation_id")


def _available(ctx: dict, kind: str) -> bool:
    if kind == "differential":
        return _present(ctx, "flow_a") and _present(ctx, "flow_b")
    if kind == "timing":
        return _present(ctx, "attack_id")
    if kind == "oob":
        collab = ctx.get("collaborator") or ctx.get("collab")
        return collab is not None and _correlation(ctx) is not None
    if kind == "marker":
        return ctx.get("client") is not None and _correlation(ctx) is not None
    if kind == "two_identity":
        return _present(ctx, "a_ref") and _present(ctx, "b_ref")
    if kind == "signature":
        return _present(ctx, "flow_id")
    return False


def _select(ctx: dict) -> str:
    override = ctx.get("oracle_kind")
    if override:
        return override
    for kind in ORACLE_PRIORITY:
        if _available(ctx, kind):
            return kind
    return ORACLE_PRIORITY[0]


async def verify(ctx: dict) -> OracleResult:
    kind = _select(ctx)
    expect = {**EXPECT.get(kind, {}), **ctx.get("expect", {})}
    spec = VerificationOracle(
        kind=kind,
        expect=expect,
        signals=ctx.get("signals", SIGNALS),
        correlation_id=_correlation(ctx),
    )
    return await run_oracle(spec, ctx)
