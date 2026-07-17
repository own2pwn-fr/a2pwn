"""Deterministic CORS oracle.

Confirmed only when the attacker-supplied ``Origin`` is reflected into
``Access-Control-Allow-Origin`` (or the ``null`` origin is trusted) **and**
``Access-Control-Allow-Credentials: true`` — i.e. a credentialed cross-origin
read is actually possible. Wildcard-without-credentials is rejected.
"""

from __future__ import annotations

from a2pwn.oracles import OracleResult


def _resp_headers_text(detail: dict) -> str:
    resp = (detail or {}).get("response") or {}
    headers = resp.get("headers")
    if isinstance(headers, str):
        return headers
    if isinstance(headers, dict):
        return "\n".join(f"{k}: {v}" for k, v in headers.items())
    if isinstance(headers, list):
        rows: list[str] = []
        for pair in headers:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                rows.append(f"{pair[0]}: {pair[1]}")
            else:
                rows.append(str(pair))
        return "\n".join(rows)
    return str(headers or "")


async def verify(ctx: dict) -> OracleResult:
    client = ctx.get("client")
    flow_id = ctx.get("flow_id")
    origin = (ctx.get("attacker_origin") or ctx.get("origin") or "https://evil.example").lower()
    if client is None or flow_id is None:
        return OracleResult(
            confirmed=False,
            kind="signature",
            evidence="cors: missing client/flow_id in ctx (abstain)",
        )

    detail = await client.req_show(flow_id, raw=False)
    text = _resp_headers_text(detail).lower()
    reflected = (
        f"access-control-allow-origin: {origin}" in text
        or "access-control-allow-origin: null" in text
    )
    creds = "access-control-allow-credentials: true" in text
    confirmed = reflected and creds
    evidence = (
        f"cors flow {flow_id}: ACAO reflects {origin!r}={reflected}, "
        f"Allow-Credentials:true={creds} => "
        f"{'credentialed cross-origin read' if confirmed else 'not exploitable'}"
    )
    return OracleResult(confirmed=confirmed, kind="signature", evidence=evidence, flow_ids=[flow_id])
