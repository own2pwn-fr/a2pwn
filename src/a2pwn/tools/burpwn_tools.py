"""LangChain BaseTool adapters over a bound :class:`BurpwnClient`.

These expose the burpwn MCP hot loop (exec / query / repeater / intruder / analysis /
tag / note) to a ReAct executor. Every call is async and delegates straight to the
already-connected client — the agent process itself stays outside the sandbox.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import BaseTool, StructuredTool

from a2pwn.burpwn import BurpwnClient
from a2pwn.scope import argv_hosts, host_of, in_scope


def burpwn_tools(client: BurpwnClient, engagement: Any = None) -> list[BaseTool]:
    """Tools over a bound client. When ``engagement`` is given, every target-facing tool
    deterministically REFUSES out-of-scope destinations (parsed from argv / replay Host
    overrides / fuzz payloads) before anything runs — a prompt-injected ``fetch
    http://attacker/`` or a stray ``169.254.169.254`` cannot drive real traffic off-scope.
    """
    targets = list(getattr(engagement, "targets", None) or [])
    allow = list(getattr(engagement, "in_scope", None) or [])
    enforce = bool(engagement is not None and (targets or allow))

    def _refuse(hosts: list[str], where: str) -> dict:
        return {
            "error": "out-of-scope",
            "refused": True,
            "off_scope_hosts": hosts,
            "message": (
                f"REFUSED: {where} targets out-of-scope host(s) {hosts}; only "
                f"{allow or targets} (and their subdomains) are in scope. Nothing was run."
            ),
        }

    def _off_scope(hosts: list[str]) -> list[str]:
        if not enforce:
            return []
        return [h for h in hosts if not in_scope(h, targets, allow)]

    async def burpwn_exec(
        argv: list[str], workspace: str | None = None, timeout_secs: int | None = None
    ) -> dict:
        """Run a target-facing command inside the burpwn sandbox (all traffic captured/MITM'd).

        Out-of-scope destinations parsed from ``argv`` are refused without running anything.
        """
        bad = _off_scope(argv_hosts(list(argv or [])))
        if bad:
            return _refuse(bad, "burpwn_exec argv")
        return await client.exec(argv, workspace=workspace, timeout_secs=timeout_secs)

    async def burpwn_req_list(
        workspace_id: int | None = None,
        host: str | None = None,
        protocol: str | None = None,
        status: int | None = None,
        method: str | None = None,
        limit: int | None = None,
    ) -> dict:
        """List captured flows, optionally filtered by workspace id, host, protocol, status, method."""
        return await client.req_list(
            workspace_id=workspace_id,
            host=host,
            protocol=protocol,
            status=status,
            method=method,
            limit=limit,
        )

    async def burpwn_req_show(id: int, raw: bool = False) -> dict:
        """Show one captured flow (decrypted request+response); raw=True adds verbatim bytes."""
        return await client.req_show(id, raw=raw)

    async def burpwn_req_search(query: str) -> list[int]:
        """Full-text search across all decrypted request/response history; returns flow ids."""
        return await client.req_search(query)

    async def burpwn_req_replay(
        id: int,
        set_headers: list[dict] | None = None,
        set_body: str | None = None,
        method: str | None = None,
    ) -> dict:
        """Repeater: replay a flow with edited headers/body/method.

        A ``Host`` header override pointing off-scope is refused (re-targeting a captured
        flow at an out-of-scope host).
        """
        override_hosts: list[str] = []
        for hdr in set_headers or []:
            name = str(hdr.get("name", "")).lower()
            if name in {"host", ":authority"}:
                h = host_of(str(hdr.get("value", "")))
                if h:
                    override_hosts.append(h)
        bad = _off_scope(override_hosts)
        if bad:
            return _refuse(bad, "burpwn_req_replay Host override")
        return await client.req_replay(
            id, set_headers=set_headers or [], set_body=set_body, method=method
        )

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
        """Intruder: fuzz payload positions in a flow; results ranked by status/len/time anomaly.

        Payloads that are absolute URLs to an out-of-scope host (e.g. an SSRF payload aimed
        at ``169.254.169.254``) are refused before the attack runs.
        """
        payload_hosts: list[str] = []
        for p in payloads or []:
            h = host_of(str(p))
            if h:
                payload_hosts.append(h)
        bad = _off_scope(payload_hosts)
        if bad:
            return _refuse(bad, "burpwn_fuzz payload")
        return await client.fuzz(
            flow,
            positions,
            payloads,
            mode=mode,
            concurrency=concurrency,
            delay_ms=delay_ms,
            marker=marker,
            name=name,
        )

    async def burpwn_fuzz_results(
        attack_id: int, sort: str = "anomaly", limit: int | None = None
    ) -> dict:
        """Fetch Intruder results for an attack, anomaly-ranked (the blind oracle)."""
        return await client.fuzz_results(attack_id, sort=sort, limit=limit)

    async def burpwn_compare(flow_a: int, flow_b: int, what: str = "all") -> dict:
        """Structured status/header/body diff + reflection check between two flows."""
        return await client.compare(flow_a, flow_b, what=what)

    async def burpwn_tag_add(flow_id: int, name: str, color: str | None = None) -> dict:
        """Tag/highlight a flow (marks it as belonging to a finding batch)."""
        return await client.tag_add(flow_id, name, color=color)

    async def burpwn_note_add(flow_id: int, body: str) -> dict:
        """Attach an evidence note to a flow."""
        return await client.note_add(flow_id, body)

    return [
        StructuredTool.from_function(coroutine=burpwn_exec, name="burpwn_exec"),
        StructuredTool.from_function(coroutine=burpwn_req_list, name="burpwn_req_list"),
        StructuredTool.from_function(coroutine=burpwn_req_show, name="burpwn_req_show"),
        StructuredTool.from_function(coroutine=burpwn_req_search, name="burpwn_req_search"),
        StructuredTool.from_function(coroutine=burpwn_req_replay, name="burpwn_req_replay"),
        StructuredTool.from_function(coroutine=burpwn_fuzz, name="burpwn_fuzz"),
        StructuredTool.from_function(coroutine=burpwn_fuzz_results, name="burpwn_fuzz_results"),
        StructuredTool.from_function(coroutine=burpwn_compare, name="burpwn_compare"),
        StructuredTool.from_function(coroutine=burpwn_tag_add, name="burpwn_tag_add"),
        StructuredTool.from_function(coroutine=burpwn_note_add, name="burpwn_note_add"),
    ]
