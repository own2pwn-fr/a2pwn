"""Deterministic open-redirect oracle.

Confirmed when a redirect response (``3xx``) carries a ``Location`` whose
effective host is attacker-controlled (handling ``//``, ``user@host``, and
encoded slashes). Falls back to a JS/DOM-redirect check in the body.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from a2pwn.oracles import OracleResult

_REDIRECT_STATUS = {301, 302, 303, 307, 308}


def _headers_text(detail: dict, section: str) -> str:
    part = (detail or {}).get(section) or {}
    headers = part.get("headers")
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


def _location(detail: dict) -> str | None:
    for line in _headers_text(detail, "response").splitlines():
        if line.lower().startswith("location:"):
            return line.split(":", 1)[1].strip()
    return None


def _dest_host(location: str) -> str:
    loc = location.strip()
    if loc.startswith("//"):
        loc = "http:" + loc
    elif loc.startswith("/\\") or loc.startswith("\\/"):
        loc = "http://" + loc.lstrip("/\\")
    host = urlsplit(loc).netloc
    if "@" in host:  # https://trusted.com@evil.example -> evil.example
        host = host.rsplit("@", 1)[1]
    return host.split(":", 1)[0].lower()


async def verify(ctx: dict) -> OracleResult:
    client = ctx.get("client")
    flow_id = ctx.get("flow_id")
    attacker = (ctx.get("attacker_host") or "evil.example").lower()
    if client is None or flow_id is None:
        return OracleResult(
            confirmed=False,
            kind="signature",
            evidence="open-redirect: missing client/flow_id (abstain)",
        )

    detail = await client.req_show(flow_id, raw=False)
    resp = (detail or {}).get("response") or {}
    status = resp.get("status")
    location = _location(detail)

    if not location:
        body = resp.get("body") or ""
        body_l = body.lower() if isinstance(body, str) else str(body).lower()
        confirmed = attacker in body_l and ("location" in body_l or "window.location" in body_l)
        return OracleResult(
            confirmed=confirmed,
            kind="signature",
            evidence=f"open-redirect flow {flow_id}: no Location header; "
            f"JS-redirect-to-{attacker}={confirmed}",
            flow_ids=[flow_id],
        )

    host = _dest_host(location)
    is_redirect = isinstance(status, int) and status in _REDIRECT_STATUS
    confirmed = is_redirect and (host == attacker or host.endswith("." + attacker))
    evidence = (
        f"open-redirect flow {flow_id}: status {status}, Location host {host!r} "
        f"(attacker {attacker!r}) => {'controlled redirect' if confirmed else 'not controlled'}"
    )
    return OracleResult(confirmed=confirmed, kind="signature", evidence=evidence, flow_ids=[flow_id])
