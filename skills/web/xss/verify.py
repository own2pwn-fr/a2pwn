"""Verification oracle for XSS.

Strongest-first: a reflected-context ``differential`` (marker survives into the
reflected byte set), a ``marker`` full-text search across decrypted history for
stored/blind sinks, then an ``oob`` collaborator callback for blind exfil
payloads. Exposes ``verify(ctx)`` which the adversarial verifier calls with the
live handles (``client``, ``collaborator``) plus the relevant flow ids /
correlation id captured during exploitation; it builds the class's
:class:`~a2pwn.oracles.VerificationOracle` and delegates to the single 0-FP
kernel :func:`~a2pwn.oracles.run_oracle`.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult, VerificationOracle, run_oracle

ORACLE_PRIORITY: tuple[str, ...] = ("differential", "marker", "oob", "signature")
SIGNALS: list[str] = []
EXPECT: dict[str, dict] = {"differential": {"signal": "reflection"}}


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
    if kind == "differential" and "marker" not in expect and _correlation(ctx):
        expect["marker"] = _correlation(ctx)
    spec = VerificationOracle(
        kind=kind,
        expect=expect,
        signals=ctx.get("signals", SIGNALS),
        correlation_id=_correlation(ctx),
    )
    return await run_oracle(spec, ctx)
