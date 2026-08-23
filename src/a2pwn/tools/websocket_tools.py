"""WebSocket tools: the missing half of the ``websocket`` vulnerability class.

a2pwn could already *see* WebSocket flows (burpwn labels them ``protocol: "ws"``) but had no way to
*send* a frame, so every methodology step in ``skills/web/websocket/SKILL.md`` — origin-swapped
handshake, subscribing to another tenant's topic, injection through the message channel — bottomed
out at "run websocat", a binary the sandbox does not carry and the tool registry never installed.
These two tools close that gap with the stdlib client in :mod:`a2pwn._ws_client`, driven through
:mod:`a2pwn.websocket`.

``ws_replay`` is the one that makes the class testable at all: the interesting attack is not opening
an anonymous socket, it is re-opening a *captured, authenticated* channel with tampered content —
which needs the original handshake's cookies, and therefore needs the captured flow.

Both tools enforce the engagement policy in exactly the order :func:`a2pwn.toolcore.build_tool_specs`
does — scope refusal, then the traffic circuit breaker, then the rate limit — and return the same
refusal envelopes, so the containment story does not depend on which tool the model happens to pick.
The specs are :class:`~a2pwn.toolcore.ToolSpec` values so both executor paths (LangChain and the
native SDK) can adapt them from one definition, the way every other tool already does.

This file is part of a2pwn and is distributed under the GNU Affero General Public License v3.0
or later; see the repository ``LICENSE`` for the full text.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.tools import BaseTool, StructuredTool

from a2pwn.identity import IdentityError, IdentityStore
from a2pwn.scope import ScopeGuard
from a2pwn.throttle import Throttle
from a2pwn.toolcore import ToolSpec, active_refusal
from a2pwn.websocket import (
    DEFAULT_WORKSPACE,
    flow_ws_url,
    parse_header_block,
    replayable_headers,
    run_ws_client,
)

_log = logging.getLogger("a2pwn.tools.websocket")

WS_CONNECT_DESC = (
    "Open a WebSocket connection through the burpwn sandbox, send messages, and get back the "
    "handshake plus every frame exchanged. This is the ONLY way to originate WebSocket traffic — "
    "burpwn captures ws flows the browser makes, but cannot send a frame you chose. Use it to test "
    "cross-site WebSocket hijacking (repeat the handshake with a foreign Origin header and the "
    "victim's cookie: a 101 plus real data means no Origin validation), authorization applied only "
    "at the handshake (connect as one identity, then reference another's room/order/id in a "
    "message), and injection through the message channel. url is ws:// or wss:// (http/https "
    "accepted). headers is a list of {\"name\", \"value\"} — Origin and Cookie are the two that "
    "matter. messages are sent in order as text frames; wait_secs is how long to keep reading "
    "replies afterwards. The result carries captured_request_ids: the burpwn flows that prove this "
    "exchange really happened, which an oracle needs before any of it counts as a finding."
)

WS_REPLAY_DESC = (
    "Take a CAPTURED WebSocket flow, reuse its URL and its handshake headers (cookies, "
    "Authorization, subprotocol), and send a message of your choosing over that re-established "
    "channel. This is the high-value WebSocket test: replaying an AUTHENTICATED channel with "
    "tampered content, which is how you prove the server authorizes at the handshake and then "
    "trusts every message. Find the flow id with burpwn_req_list(protocol=\"ws\") or "
    "burpwn_req_search for \"Upgrade: websocket\". Pass extra_headers to override what was captured "
    "(set Origin to a foreign site for the CSWSH test). Per-connection handshake headers "
    "(Sec-WebSocket-Key, Upgrade, Host) are regenerated, never replayed."
)

WS_CONNECT_SCHEMA: dict = {
    "url": str,
    "headers": list,
    "messages": list,
    "wait_secs": float,
    "as_identity": str,
}
WS_REPLAY_SCHEMA: dict = {
    "flow_id": int,
    "message": str,
    "extra_headers": list,
    "wait_secs": float,
    "as_identity": str,
}


def _headers_dict(headers: Any) -> dict[str, str]:
    """Normalise the tool's ``[{name, value}]`` header list (a bare dict is tolerated)."""
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items()}
    out: dict[str, str] = {}
    for item in headers or []:
        if isinstance(item, dict) and item.get("name"):
            out[str(item["name"])] = str(item.get("value", ""))
    return out


def build_ws_tool_specs(
    client: Any,
    *,
    guard: ScopeGuard | None = None,
    identities: IdentityStore | None = None,
    throttle: Throttle | None = None,
    active_allowed: bool = True,
) -> list[ToolSpec]:
    """Build the WebSocket tool specs bound to one client + engagement policy.

    Defaults match :func:`a2pwn.toolcore.build_tool_specs`: no guard means no client-side refusal
    (burpwn's own containment still applies), no throttle means unlimited and never-tripping.
    """
    guard = guard or ScopeGuard()
    throttle = throttle or Throttle()

    async def _gate(where: str, tokens: list[str], *, active: bool = True) -> dict | None:
        """Scope + breaker + rate limit, in that order. Mirrors ``toolcore._gate`` exactly: a
        divergence here would mean a destination refused by one tool is reachable by another."""
        if active and not active_allowed:
            name = where.split()[0]
            _log.warning("%s REFUSED: active exploitation not authorised", name)
            return active_refusal(name)
        bad = guard.off_scope_tokens(tokens)
        if bad:
            _log.warning("%s REFUSED: out-of-scope destination(s) %s", where, bad)
            return guard.refusal(bad, where)
        if throttle.tripped:
            return throttle.refusal(where)
        await throttle.acquire()
        return None

    async def _identity_headers(name: str | None) -> tuple[dict[str, str], dict | None]:
        """Credentials for a named identity, or ``({}, error_envelope)``."""
        if not name:
            return {}, None
        if not identities:
            return {}, {
                "error": "no-identities",
                "refused": True,
                "message": (
                    f"REFUSED: as_identity={name!r} but this engagement declares no identities. "
                    "Run unauthenticated, or ask the operator to declare identities in the config."
                ),
            }
        try:
            resolved = await identities.resolve(name)
        except IdentityError as exc:
            _log.warning("identity %s could not be resolved: %s", name, exc)
            return {}, {"error": "identity-failed", "refused": True, "message": f"REFUSED: {exc}"}
        return dict(resolved.all_headers()), None

    async def _observe_capture(result: dict) -> None:
        """Feed the breaker the captured handshake flow.

        A ws exchange is driven through ``exec``, whose result carries no status — same blind spot
        ``toolcore._observe_exec`` exists to close. Without this a WAF blocking every upgrade would
        never trip the breaker and the run would read as "no WebSocket issues found".
        """
        if not throttle.block_threshold or throttle.tripped:
            return
        flow_ids = list(result.get("captured_request_ids") or [])
        if not flow_ids:
            return
        try:
            throttle.observe(await client.req_show(flow_ids[-1]))
        except Exception as exc:  # noqa: BLE001 - observability must never break the call it watches
            _log.debug("breaker could not read flow %s: %s", flow_ids[-1], exc)

    async def ws_connect(
        url: str,
        headers: list | None = None,
        messages: list | None = None,
        wait_secs: float = 5.0,
        as_identity: str | None = None,
    ) -> dict:
        refusal = await _gate("ws_connect url", [url])
        if refusal:
            return refusal
        ident, err = await _identity_headers(as_identity)
        if err:
            return err
        # Explicit headers win over the identity's: an Origin/Cookie the model set deliberately is
        # the test itself, and silently overwriting it would quietly void the CSWSH check.
        merged = {**ident, **_headers_dict(headers)}
        result = await run_ws_client(
            client,
            url,
            headers=merged,
            messages=[str(m) for m in (messages or [])],
            wait_secs=float(wait_secs),
        )
        await _observe_capture(result)
        return result

    async def ws_replay(
        flow_id: int,
        message: str,
        extra_headers: list | None = None,
        wait_secs: float = 5.0,
        as_identity: str | None = None,
    ) -> dict:
        try:
            flow = await client.req_show(int(flow_id))
        except Exception as exc:  # noqa: BLE001 - a bad flow id is a model mistake, not a crash
            return {"error": f"could not read flow {flow_id}: {exc}"}
        url = flow_ws_url(flow if isinstance(flow, dict) else {})
        if not url:
            return {
                "error": "not-a-websocket-flow",
                "message": (
                    f"flow {flow_id} does not look like a WebSocket upgrade (no host/path to rebuild "
                    'a ws:// URL from). List candidates with burpwn_req_list(protocol="ws").'
                ),
            }
        refusal = await _gate("ws_replay url", [url])
        if refusal:
            return refusal
        request = flow.get("request") if isinstance(flow.get("request"), dict) else {}
        captured = replayable_headers(parse_header_block(request.get("headers")))
        ident, err = await _identity_headers(as_identity)
        if err:
            return err
        merged = {**captured, **ident, **_headers_dict(extra_headers)}
        result = await run_ws_client(
            client,
            url,
            headers=merged,
            messages=[str(message)],
            wait_secs=float(wait_secs),
            workspace=DEFAULT_WORKSPACE,
        )
        await _observe_capture(result)
        return {**result, "replayed_from_flow": int(flow_id), "replayed_headers": sorted(merged)}

    return [
        ToolSpec("ws_connect", WS_CONNECT_DESC, WS_CONNECT_SCHEMA, ws_connect, active=True),
        ToolSpec("ws_replay", WS_REPLAY_DESC, WS_REPLAY_SCHEMA, ws_replay, active=True),
    ]


def websocket_tools(
    client: Any,
    engagement: Any = None,
    *,
    identities: IdentityStore | None = None,
    throttle: Throttle | None = None,
) -> list[BaseTool]:
    """LangChain adapters over :func:`build_ws_tool_specs` (mirrors ``tools.burpwn_tools``)."""
    specs = build_ws_tool_specs(
        client,
        guard=ScopeGuard.from_engagement(engagement),
        identities=identities,
        throttle=throttle,
        active_allowed=bool(getattr(engagement, "active_exploit_allowed", True)),
    )
    return [
        StructuredTool.from_function(coroutine=spec.fn, name=spec.name, description=spec.description)
        for spec in specs
    ]
