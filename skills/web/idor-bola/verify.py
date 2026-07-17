"""Deterministic IDOR/BOLA oracle — the two-identity differential.

``a_ref`` = attacker identity A reaching victim identity B's object;
``b_ref`` = owner B fetching the same object (ground truth). Delegates to
:func:`a2pwn.oracles.two_identity`, which confirms only when A's access
reproduces B's object.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult, two_identity


async def verify(ctx: dict) -> OracleResult:
    client = ctx.get("client")
    a_ref = ctx.get("a_ref")
    b_ref = ctx.get("b_ref")
    if client is None or a_ref is None or b_ref is None:
        return OracleResult(
            confirmed=False,
            kind="two_identity",
            evidence="idor: need client + a_ref (attacker->B object) + b_ref (owner B) (abstain)",
        )
    return await two_identity(client, a_ref, b_ref)
