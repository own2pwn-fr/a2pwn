"""THE single definition of every target-facing tool: behaviour, description and schema.

Both executor paths — the LangChain ``StructuredTool`` adapters in :mod:`a2pwn.tools.burpwn_tools`
and the native ``claude-agent-sdk`` MCP wrappers in :mod:`a2pwn.sdk_agent` — are thin adapters over
the :class:`ToolSpec` list this module builds. They used to be independent hand-maintained copies,
and that duplication is what let real defects ship:

* the ``state_change`` oracle was missing from one copy's allow-list and silently rewritten to
  ``signature``, rejecting genuinely-proven findings;
* the client-side scope refusal existed on the LangChain path only — i.e. it was OFF on the
  ``claude-code`` DEFAULT backend, so the documented containment was not actually running in a
  normal engagement;
* the ``positions``/``what`` contract fixes had to be written twice, and were.

One definition means a fix lands on both paths at once, and :func:`tool_names` gives the parity test
something to assert against.

Every target-facing wrapper here enforces, in order: the scope guard (refuse out-of-scope/excluded
destinations before anything runs), the traffic circuit breaker (refuse once the target is provably
blocking), the rate limit, and — when the call names an identity — credential injection.

This file is part of a2pwn and is distributed under the GNU Affero General Public License v3.0
or later; see the repository ``LICENSE`` for the full text.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from a2pwn.identity import IdentityError, IdentityStore, apply_identity_to_argv, merge_identity_headers
from a2pwn.scope import ScopeGuard, host_of
from a2pwn.throttle import Throttle, clamp_fuzz_payloads

_log = logging.getLogger("a2pwn.tools")


@dataclass
class ToolSpec:
    """One tool, defined once: its name, model-facing description, SDK schema and coroutine.

    ``fn`` has a real (non-``**kwargs``) signature so LangChain can infer its args schema, while the
    SDK path calls it as ``fn(**args)`` against ``schema``.
    """

    name: str
    description: str
    schema: dict[str, Any]
    fn: Callable[..., Any]
    #: True for tools that generate real, potentially destructive target traffic.
    active: bool = False


# Tool names that must hard-block when the engagement did not pre-authorise active exploitation.
ACTIVE_TOOL_NAMES = frozenset(
    {"burpwn_exec", "burpwn_fuzz", "burpwn_req_replay", "burpwn_intercept_forward", "identity_request"}
)


def _identity_help(store: IdentityStore | None) -> str:
    if not store:
        return ""
    return (
        " Set as_identity to one of the engagement's declared identities ("
        + ", ".join(store.names())
        + ") to issue this request with that identity's credentials."
    )


def build_tool_specs(
    client: Any,
    *,
    guard: ScopeGuard | None = None,
    identities: IdentityStore | None = None,
    throttle: Throttle | None = None,
    fuzz_cap: int = 0,
) -> list[ToolSpec]:
    """Build every tool spec bound to one client + engagement policy.

    ``guard`` defaults to a non-enforcing guard (no allow-list => no client-side refusal, which is
    the historical behaviour when no engagement is passed); ``throttle`` defaults to an unlimited,
    never-tripping one; ``identities`` of ``None``/empty simply omits the identity tools.
    """
    guard = guard or ScopeGuard()
    throttle = throttle or Throttle()
    ident_help = _identity_help(identities)

    async def _gate(where: str, tokens: list[str]) -> dict | None:
        """Scope + breaker + rate limit. Returns a refusal envelope, or ``None`` to proceed."""
        bad = guard.off_scope_tokens(tokens)
        if bad:
            _log.warning("%s REFUSED: out-of-scope destination(s) %s", where, bad)
            return guard.refusal(bad, where)
        if throttle.tripped:
            return throttle.refusal(where)
        await throttle.acquire()
        return None

    async def _as_identity(name: str | None):
        """Resolve an identity name to credentials, or ``(None, error_envelope)``."""
        if not name:
            return None, None
        if not identities:
            return None, {
                "error": "no-identities",
                "refused": True,
                "message": (
                    f"REFUSED: as_identity={name!r} but this engagement declares no identities. "
                    "Run unauthenticated, or ask the operator to declare identities in the config."
                ),
            }
        try:
            return await identities.resolve(name), None
        except IdentityError as exc:
            _log.warning("identity %s could not be resolved: %s", name, exc)
            return None, {"error": "identity-failed", "refused": True, "message": f"REFUSED: {exc}"}

    async def _observe_exec(result: Any) -> None:
        """Feed an ``exec``-shaped result to the breaker via its CAPTURED flow.

        A burpwn ``exec`` result carries only ``captured_request_ids``/``exec_id``/``exit_code`` —
        no status, no body (verified live). Without this the breaker saw nothing from exec-driven
        traffic, which is most of a run's traffic, so a WAF-blocked engagement would never trip it.
        One extra ``req_show`` per exec, only while the breaker is armed, and only on the last
        captured flow (a consecutive-run breaker does not need every one).
        """
        if not throttle.block_threshold or throttle.tripped or not isinstance(result, dict):
            return
        flow_ids = list(result.get("captured_request_ids") or [])
        if not flow_ids:
            return
        try:
            throttle.observe(await client.req_show(flow_ids[-1]))
        except Exception as exc:  # noqa: BLE001 - observability must never break the call it watches
            _log.debug("breaker could not read flow %s: %s", flow_ids[-1], exc)

    def _maybe_reauth(name: str | None, result: Any) -> None:
        """Drop a cached identity when the target answered 401/403 — the session likely expired.

        Without this, a session that expires mid-engagement turns every later access-control probe
        into a false "access control held" negative that no oracle can distinguish from real
        enforcement.
        """
        if not name or not identities or not isinstance(result, dict):
            return
        status = (result.get("response") or {}).get("status", result.get("status"))
        try:
            if int(status) in (401, 403):
                identities.invalidate(name)
        except (TypeError, ValueError):
            pass

    # ---- burpwn hot loop -------------------------------------------------------------
    async def burpwn_exec(
        argv: list[str],
        workspace: str | None = None,
        timeout_secs: int | None = None,
        as_identity: str | None = None,
    ) -> dict:
        refusal = await _gate("burpwn_exec argv", list(argv or []))
        if refusal:
            return refusal
        argv = list(argv or [])
        note: str | None = None
        if as_identity:
            resolved, err = await _as_identity(as_identity)
            if err:
                return err
            argv, note = apply_identity_to_argv(argv, resolved)
        result = await client.exec(argv, workspace=workspace, timeout_secs=timeout_secs)
        await _observe_exec(result)
        if note and isinstance(result, dict):
            result = {**result, "identity_warning": note}
        return result

    async def burpwn_req_list(
        workspace_id: int | None = None,
        host: str | None = None,
        protocol: str | None = None,
        status: int | None = None,
        method: str | None = None,
        limit: int | None = None,
    ) -> dict:
        return await client.req_list(
            workspace_id=workspace_id,
            host=host,
            protocol=protocol,
            status=status,
            method=method,
            limit=limit,
        )

    async def burpwn_req_show(id: int, raw: bool = False) -> dict:
        return await client.req_show(id, raw=raw)

    async def burpwn_req_search(query: str) -> list[int]:
        return await client.req_search(query)

    async def burpwn_req_replay(
        id: int,
        set_headers: list[dict] | None = None,
        set_body: str | None = None,
        method: str | None = None,
        as_identity: str | None = None,
    ) -> dict:
        override_hosts: list[str] = []
        for hdr in set_headers or []:
            if str(hdr.get("name", "")).lower() in {"host", ":authority"}:
                parsed = host_of(str(hdr.get("value", "")))
                if parsed:
                    override_hosts.append(parsed)
        refusal = await _gate("burpwn_req_replay Host override", override_hosts)
        if refusal:
            return refusal
        headers = list(set_headers or [])
        if as_identity:
            resolved, err = await _as_identity(as_identity)
            if err:
                return err
            headers = merge_identity_headers(headers, resolved)
        result = await client.req_replay(id, set_headers=headers, set_body=set_body, method=method)
        throttle.observe(result)
        _maybe_reauth(as_identity, result)
        return result

    async def burpwn_fuzz(
        flow: int,
        positions: list[str],
        payloads: list[str],
        mode: str = "sniper",
        concurrency: int | None = None,
        delay_ms: int | None = None,
        marker: str | None = None,
        name: str | None = None,
    ) -> dict:
        refusal = await _gate("burpwn_fuzz payload", [str(p) for p in (payloads or [])])
        if refusal:
            return refusal
        clamped, notice = clamp_fuzz_payloads(list(payloads or []), fuzz_cap)
        result = await client.fuzz(
            flow,
            positions,
            clamped,
            mode=mode,
            concurrency=concurrency,
            delay_ms=delay_ms,
            marker=marker,
            name=name,
        )
        throttle.observe(result)
        if notice and isinstance(result, dict):
            result = {**result, "clamp_notice": notice}
        return result

    async def burpwn_fuzz_results(attack_id: int, sort: str = "anomaly", limit: int | None = None) -> dict:
        result = await client.fuzz_results(attack_id, sort=sort, limit=limit)
        throttle.observe(result)
        return result

    async def burpwn_compare(flow_a: int, flow_b: int, what: str = "all") -> dict:
        return await client.compare(flow_a, flow_b, what=what)

    async def burpwn_tag_add(flow_id: int, name: str, color: str | None = None) -> dict:
        return await client.tag_add(flow_id, name, color=color)

    async def burpwn_note_add(flow_id: int, body: str) -> dict:
        return await client.note_add(flow_id, body)

    # ---- identities ------------------------------------------------------------------
    async def identity_list() -> list[dict]:
        return identities.describe() if identities else []

    async def identity_request(
        url: str,
        as_identity: str,
        method: str = "GET",
        headers: list[dict] | None = None,
        body: str | None = None,
    ) -> dict:
        refusal = await _gate("identity_request url", [url])
        if refusal:
            return refusal
        resolved, err = await _as_identity(as_identity)
        if err:
            return err
        argv = ["curl", "-s", "-i", "-X", method.upper(), *resolved.curl_args()]
        for hdr in headers or []:
            argv += ["-H", f"{hdr.get('name')}: {hdr.get('value')}"]
        if body is not None:
            argv += ["--data-raw", body]
        argv.append(url)
        result = await client.exec(argv, workspace=f"identity-{as_identity}")
        await _observe_exec(result)
        # An exec result carries no status, so the 401/403 re-auth signal has to come from the
        # captured flow too — otherwise an expired identity would never notice it expired.
        flow_ids = list((result or {}).get("captured_request_ids") or [])
        if flow_ids:
            try:
                _maybe_reauth(as_identity, await client.req_show(flow_ids[-1]))
            except Exception as exc:  # noqa: BLE001 - best-effort; never break the request itself
                _log.debug("could not read flow %s for re-auth check: %s", flow_ids[-1], exc)
        return result

    specs: list[ToolSpec] = [
        ToolSpec(
            "burpwn_exec",
            "Run a target-facing command inside the burpwn sandbox (all traffic captured/MITM'd). "
            "argv is the command vector; workspace groups this run's captured flows; "
            "timeout_secs caps a long network exec. Out-of-scope or excluded destinations parsed "
            "from argv are refused without running anything." + ident_help,
            {"argv": list, "workspace": str, "timeout_secs": int, "as_identity": str},
            burpwn_exec,
            active=True,
        ),
        ToolSpec(
            "burpwn_req_list",
            "List captured flows, optionally filtered by workspace_id, host, protocol, status, "
            "method, limit.",
            {
                "workspace_id": int,
                "host": str,
                "protocol": str,
                "status": int,
                "method": str,
                "limit": int,
            },
            burpwn_req_list,
        ),
        ToolSpec(
            "burpwn_req_show",
            "Show one captured flow (decrypted request+response); raw=true adds verbatim bytes.",
            {"id": int, "raw": bool},
            burpwn_req_show,
        ),
        ToolSpec(
            "burpwn_req_search",
            "Full-text search across all decrypted request/response history; returns matching flow ids.",
            {"query": str},
            burpwn_req_search,
        ),
        ToolSpec(
            "burpwn_req_replay",
            "Repeater: replay a flow with edited headers/body/method. A Host header override "
            "pointing off-scope is refused." + ident_help,
            {"id": int, "set_headers": list, "set_body": str, "method": str, "as_identity": str},
            burpwn_req_replay,
            active=True,
        ),
        ToolSpec(
            "burpwn_fuzz",
            "Intruder: fuzz payload positions in a flow; results ranked by status/len/time anomaly. "
            'positions is a list of "start:end" BYTE OFFSET strings into the flow\'s raw request '
            "(NOT a field name or marker string) — call burpwn_req_show with raw=true first to get "
            "the verbatim request bytes and compute the offset of your injection point, e.g. "
            '["142:145"] to fuzz a 3-byte span starting at byte 142. mode is one of '
            "sniper/battering-ram/pitchfork/cluster-bomb. Payloads that are absolute URLs to an "
            "out-of-scope host (e.g. an SSRF payload aimed at 169.254.169.254) are refused before "
            "the attack runs.",
            {
                "flow": int,
                "positions": list,
                "payloads": list,
                "mode": str,
                "concurrency": int,
                "delay_ms": int,
                "marker": str,
                "name": str,
            },
            burpwn_fuzz,
            active=True,
        ),
        ToolSpec(
            "burpwn_fuzz_results",
            "Fetch Intruder results for an attack, anomaly-ranked (the blind oracle).",
            {"attack_id": int, "sort": str, "limit": int},
            burpwn_fuzz_results,
        ),
        ToolSpec(
            "burpwn_compare",
            "Structured status/header/body diff + reflection check between two flows. what MUST be "
            'exactly one of "headers", "body" or "all" (a single value, never a comma list) — '
            'defaults to "all" if omitted.',
            {"flow_a": int, "flow_b": int, "what": str},
            burpwn_compare,
        ),
        ToolSpec(
            "burpwn_tag_add",
            "Tag/highlight a flow (marks it as belonging to a finding batch).",
            {"flow_id": int, "name": str, "color": str},
            burpwn_tag_add,
        ),
        ToolSpec(
            "burpwn_note_add",
            "Attach an evidence note to a flow.",
            {"flow_id": int, "body": str},
            burpwn_note_add,
        ),
    ]

    if identities:
        specs += [
            ToolSpec(
                "identity_list",
                "List the identities this engagement can act as, and how each authenticates. Use "
                "two DISTINCT authenticated identities plus the anonymous one to prove access-control "
                "findings with the two_identity oracle: A reaching B's object, B fetching its own "
                "object (ground truth), and the anonymous identity as the negative control that "
                "rules out a merely public resource.",
                {},
                identity_list,
            ),
            ToolSpec(
                "identity_request",
                "Issue an HTTP request AS a named identity (credentials are attached for you; the "
                "identity logs in on first use and re-authenticates if its session expires). This is "
                "the reliable way to produce the attacker/owner/control flows the two_identity "
                "oracle needs. Runs through the burpwn sandbox, so the request is captured like any "
                'other. headers is an optional list of {"name": ..., "value": ...} to add on top.',
                {"url": str, "as_identity": str, "method": str, "headers": list, "body": str},
                identity_request,
                active=True,
            ),
        ]
    return specs


def tool_names(specs: list[ToolSpec]) -> list[str]:
    """Tool names in definition order — the parity test's assertion target."""
    return [s.name for s in specs]
