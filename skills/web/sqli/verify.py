"""Verification oracle for SQL injection.

Strongest-first: a ``timing`` oracle on a controlled ``SLEEP``/``pg_sleep`` delay
(a delay cannot be coincidental — the cleanest 0-FP signal), then ``signature``
matching of DBMS error strings, an ``oob`` DNS/HTTP exfil callback, a
``differential`` boolean TRUE/FALSE diff, and a ``marker`` full-text search for
second-order propagation. Exposes ``verify(ctx)`` for the adversarial verifier,
which builds the class's :class:`~a2pwn.oracles.VerificationOracle` and delegates
to :func:`~a2pwn.oracles.run_oracle`.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult, VerificationOracle, run_oracle

ORACLE_PRIORITY: tuple[str, ...] = ("timing", "signature", "oob", "differential", "marker")
SIGNALS: list[str] = [
    "you have an error in your SQL syntax",
    "SQLITE_ERROR",
    "ORA-0",
    "PG::",
    "SQLSTATE",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
    "MySQLSyntaxErrorException",
    "SQLite3::",
    "org.postgresql.util.PSQLException",
    "Microsoft OLE DB Provider for SQL Server",
    "Warning: mysql_",
]
EXPECT: dict[str, dict] = {
    "timing": {"threshold_ms": 5000},
    "differential": {"signal": "any"},
}


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
