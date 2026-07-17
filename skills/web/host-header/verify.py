"""Verification oracle for HTTP Host-header attacks.

Strongest-first: a ``marker`` oracle proving the injected Host token reflected
into a link/redirect/reset across decrypted history (the app trusted a client-
controlled Host into output), then a ``differential`` behavioural change between a
baseline and a tampered-Host response, an ``oob`` callback for routing-based SSRF,
and a ``signature`` match of the host marker. Exposes ``verify(ctx)`` for the
adversarial verifier, which builds the class's
:class:`~a2pwn.oracles.VerificationOracle` and delegates to
:func:`~a2pwn.oracles.run_oracle`.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult, VerificationOracle, run_oracle

ORACLE_PRIORITY: tuple[str, ...] = ("marker", "differential", "oob", "signature")
SIGNALS: list[str] = ["evil", "attacker.com", "collaborator", "Location:", "reset"]
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
