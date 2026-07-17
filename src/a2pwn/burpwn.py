"""burpwn integration: MCP-stdio hot loop + CLI lifecycle/export, and the
FlowBatchManager that makes a captured flow batch double as finding evidence.

The hot capture/query/tag/replay loop is driven over a single long-lived MCP
stdio server (``burpwn mcp --session <session>``); its 31 tools return uniform
JSON on the normal channel (the ``exec`` fd-3 plumbing is handled server-side).
Lifecycle/export operations the MCP surface does not cover (session new/rm,
note list, export har, ca export, doctor) shell out to ``burpwn --json`` and
parse the single-line ``{ok,data,error}`` envelope from stdout.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from a2pwn.models import FlowBatchRef

_PROTOCOL_VERSION = "2024-11-05"
_CLIENT_INFO = {"name": "a2pwn", "version": "0.1.0"}
# Max bytes for a single MCP stdout line. burpwn caps a stored body at ~8 MiB; a req_show can
# carry request + response bodies plus JSON escaping, so allow generous headroom (64 MiB) above
# asyncio's default 64 KiB StreamReader limit.
_STDOUT_LINE_LIMIT = 64 * 1024 * 1024

_log = logging.getLogger("a2pwn.burpwn")


class BurpwnError(RuntimeError):
    """Raised when a burpwn MCP tool or CLI command fails."""


def _compact(**kwargs: Any) -> dict[str, Any]:
    """Drop ``None`` values so optional MCP params are simply omitted."""

    return {k: v for k, v in kwargs.items() if v is not None}


def _tool_text(result: dict) -> str:
    """Extract the text block from an MCP ``CallToolResult`` payload."""

    content = result.get("content") or []
    for block in content:
        if block.get("type") == "text":
            return block.get("text", "")
    return ""


def _parse_tool_result(result: dict) -> Any:
    """Turn an MCP tool result into the decoded JSON value it carries."""

    text = _tool_text(result)
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}


class BurpwnClient:
    """Async client over a per-engagement ``burpwn mcp --session`` stdio server.

    The subprocess is spawned lazily on first use (``__init__`` stays sync per
    the contract); the MCP ``initialize`` handshake runs once behind a startup
    lock, and every tool call is serialized behind a request lock so the
    single stdout channel stays coherent under concurrent callers.
    """

    def __init__(
        self,
        session: str,
        request_timeout: float | None = None,
        command: list[str] | None = None,
    ):
        self.session = session
        # Overridable for tests (spawn a fake stdio MCP server); defaults to the real burpwn MCP.
        self._argv = command or ["burpwn", "mcp", "--session", session]
        self._proc: asyncio.subprocess.Process | None = None
        self._id = 0
        self._req_lock = asyncio.Lock()
        self._start_lock = asyncio.Lock()
        self._started = False
        # Per-request read timeout (seconds); None disables it so long-running network
        # execs (sqlmap/nmap/…) are not cut off. Set it to fail a wedged server fast.
        self._request_timeout = request_timeout
        self._stderr_task: asyncio.Task | None = None

    # ---- lifecycle --------------------------------------------------------
    async def _ensure_started(self) -> None:
        if self._started:
            return
        async with self._start_lock:
            if self._started:
                return
            env = os.environ.copy()
            env.pop("ANTHROPIC_API_KEY", None)
            self._proc = await asyncio.create_subprocess_exec(
                *self._argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                # A single MCP response line (e.g. req_show with a full captured response body,
                # up to burpwn's multi-MiB BODY_CAP, JSON-escaped) far exceeds asyncio's default
                # 64 KiB StreamReader limit — readline() would raise LimitOverrunError
                # ("Separator is not found, and chunk exceed the limit") and wedge the tool call.
                limit=_STDOUT_LINE_LIMIT,
            )
            # Continuously drain stderr so >64KB of burpwn logging cannot fill the OS
            # pipe buffer and wedge the child's stdout responses (pipe-buffer deadlock).
            self._stderr_task = asyncio.ensure_future(self._drain_stderr())
            await self._request(
                "initialize",
                {
                    "protocolVersion": _PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": _CLIENT_INFO,
                },
            )
            await self._notify("notifications/initialized", {})
            self._started = True

    async def _drain_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        try:
            while True:
                line = await proc.stderr.readline()
                if not line:
                    return
                _log.debug("burpwn[stderr] %s", line.decode(errors="replace").rstrip())
        except (asyncio.CancelledError, ValueError):  # ValueError: transport closed
            return
        except Exception as exc:  # noqa: BLE001 - draining must never crash the client
            _log.debug("burpwn stderr drain stopped: %s", exc)

    async def close(self) -> None:
        proc = self._proc
        if proc is None:
            return
        self._proc = None
        self._started = False
        task = self._stderr_task
        self._stderr_task = None
        if task is not None:
            task.cancel()
        if proc.returncode is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                return
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except (TimeoutError, ProcessLookupError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

    # ---- JSON-RPC-over-stdio plumbing -------------------------------------
    async def _send(self, msg: dict) -> None:
        assert self._proc is not None and self._proc.stdin is not None
        self._proc.stdin.write((json.dumps(msg) + "\n").encode())
        await self._proc.stdin.drain()

    async def _recv(self) -> dict:
        assert self._proc is not None and self._proc.stdout is not None
        # Skip blank / non-JSON stdout lines (a stray log leaking to stdout must not
        # kill the in-flight call) — keep reading until a valid JSON object or EOF.
        while True:
            line = await self._proc.stdout.readline()
            if not line:
                raise BurpwnError("burpwn mcp server closed the stream")
            text = line.decode(errors="replace").strip()
            if not text:
                continue
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                _log.debug("burpwn: skipping non-JSON stdout line: %s", text[:200])
                continue

    async def _notify(self, method: str, params: dict) -> None:
        async with self._req_lock:
            await self._send({"jsonrpc": "2.0", "method": method, "params": params})

    async def _request(self, method: str, params: dict, timeout: float | None = None) -> dict:
        timeout = timeout if timeout is not None else self._request_timeout
        async with self._req_lock:
            self._id += 1
            rid = self._id
            await self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
            while True:
                try:
                    resp = await asyncio.wait_for(self._recv(), timeout=timeout)
                except TimeoutError as exc:
                    raise BurpwnError(f"{method}: timed out after {timeout}s") from exc
                if resp.get("id") != rid:
                    continue  # skip server notifications / unrelated ids
                if "error" in resp:
                    err = resp["error"]
                    msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                    raise BurpwnError(f"{method}: {msg}")
                return resp.get("result", {})

    async def _call_tool(self, name: str, arguments: dict) -> Any:
        await self._ensure_started()
        result = await self._request("tools/call", {"name": name, "arguments": arguments})
        if result.get("isError"):
            raise BurpwnError(f"{name}: {_tool_text(result)}")
        return _parse_tool_result(result)

    # ---- hot loop over MCP -------------------------------------------------
    async def exec(
        self, argv: list[str], workspace: str | None = None, timeout_secs: int | None = None
    ) -> dict:
        return await self._call_tool(
            "exec", _compact(argv=argv, workspace=workspace, timeout_secs=timeout_secs)
        )

    async def req_list(
        self,
        workspace_id: int | None = None,
        host: str | None = None,
        protocol: str | None = None,
        status: int | None = None,
        method: str | None = None,
        limit: int | None = None,
    ) -> dict:
        return await self._call_tool(
            "req_list",
            _compact(
                workspace=workspace_id,
                host=host,
                protocol=protocol,
                status=status,
                method=method,
                limit=limit,
            ),
        )

    async def req_show(self, id: int, raw: bool = False) -> dict:
        return await self._call_tool("req_show", {"id": id, "raw": raw})

    async def req_search(self, query: str) -> list[int]:
        res = await self._call_tool("req_search", {"query": query})
        return list(res.get("flow_ids", []))

    async def req_replay(
        self,
        id: int,
        set_headers: list[dict] | None = None,
        set_body: str | None = None,
        method: str | None = None,
    ) -> dict:
        return await self._call_tool(
            "req_replay",
            _compact(id=id, set_headers=list(set_headers or []), set_body=set_body, method=method),
        )

    async def fuzz(
        self,
        flow: int,
        positions: list[str],
        payloads: list[str],
        mode: str = "sniper",
        concurrency: int | None = None,
        delay_ms: int | None = None,
        marker: str | None = None,
        name: str | None = None,
    ) -> dict:
        return await self._call_tool(
            "fuzz",
            _compact(
                flow=flow,
                positions=list(positions),
                payloads=list(payloads),
                mode=mode,
                concurrency=concurrency,
                delay_ms=delay_ms,
                marker=marker,
                name=name,
            ),
        )

    async def fuzz_results(self, attack_id: int, sort: str = "anomaly", limit: int | None = None) -> dict:
        return await self._call_tool("fuzz_results", _compact(attack_id=attack_id, sort=sort, limit=limit))

    async def compare(self, flow_a: int, flow_b: int, what: str = "all") -> dict:
        return await self._call_tool("compare", {"flow_a": flow_a, "flow_b": flow_b, "what": what})

    async def tag_add(self, flow_id: int, name: str, color: str | None = None) -> dict:
        return await self._call_tool("tag_add", _compact(flow_id=flow_id, name=name, color=color))

    async def note_add(self, flow_id: int, body: str) -> dict:
        return await self._call_tool("note_add", {"flow_id": flow_id, "body": body})

    async def workspace_new(self, name: str) -> int:
        res = await self._call_tool("workspace_new", {"name": name})
        return int(res["workspace_id"])

    async def workspace_id_of(self, name: str) -> int:
        res = await self._call_tool("workspace_list", {})
        for ws in res.get("workspaces", []):
            if ws.get("name") == name:
                return int(ws["id"])
        raise BurpwnError(f"workspace {name!r} not found")

    async def session_stats(self) -> dict:
        return await self._call_tool("session_stats", {})

    async def intercept_enable(self) -> dict:
        return await self._call_tool("intercept_enable", {})

    async def await_intercept(self, timeout_secs: int | None = None) -> dict:
        return await self._call_tool("await_intercept", _compact(timeout_secs=timeout_secs))

    async def intercept_forward(self, id: int, **kw: Any) -> dict:
        return await self._call_tool("intercept_forward", {"id": id, **_compact(**kw)})

    async def intercept_scope(self, **kw: Any) -> dict:
        return await self._call_tool("intercept_scope", _compact(**kw))

    async def encode(self, scheme: str, value: str) -> dict:
        return await self._call_tool("encode", {"scheme": scheme, "value": value})

    async def decode(self, scheme: str, value: str) -> dict:
        return await self._call_tool("decode", {"scheme": scheme, "value": value})

    # ---- CLI-only lifecycle/export ----------------------------------------
    @staticmethod
    def _cli(args: list[str]) -> Any:
        proc = subprocess.run(
            ["burpwn", "--json", *args], capture_output=True, text=True
        )
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        if not lines:
            raise BurpwnError(
                f"burpwn {' '.join(args)} produced no output: {proc.stderr.strip()}"
            )
        env = json.loads(lines[-1])
        if not env.get("ok", False):
            raise BurpwnError(env.get("error") or f"burpwn {' '.join(args)} failed")
        return env.get("data")

    @staticmethod
    def cli_session_new(name: str) -> dict:
        return BurpwnClient._cli(["session", "new", "--name", name]) or {}

    @staticmethod
    def cli_export_har(session: str, out: str) -> dict:
        return BurpwnClient._cli(["--session", session, "export", "har", "-o", out]) or {}

    @staticmethod
    def cli_ca_export(out: str) -> dict:
        data = BurpwnClient._cli(["ca", "export"]) or {}
        pem = data.get("pem", "")
        Path(out).write_text(pem)
        return {"path": out, "pem": pem}

    @staticmethod
    def cli_note_list(flow_id: int) -> list[str]:
        data = BurpwnClient._cli(["note", "list", str(flow_id)])
        if not data:
            return []
        return [n.get("body", "") for n in data]

    @staticmethod
    def cli_doctor() -> dict:
        return BurpwnClient._cli(["doctor"]) or {}


class FlowBatchManager:
    """Groups a run of captured flows into one workspace and marks the batch as
    a finding's evidence (tag + colour highlight + a note on the key flow), then
    enforces the two capture invariants: a network exec that captured zero flows
    is a loud ALARM (traffic escaped the sandbox), and any ``tls-passthru`` flow
    means the target's MITM is blocked (cert-pinned/QUIC) — not testable.
    """

    def __init__(self, client: BurpwnClient):
        self.client = client

    async def open_batch(self, slug: str) -> FlowBatchRef:
        workspace_id = await self.client.workspace_new(slug)
        return FlowBatchRef(workspace=slug, workspace_id=workspace_id, tag=slug)

    async def seal(
        self,
        ref: FlowBatchRef,
        captured_request_ids: list[int],
        tag: str,
        color: str,
        note_body: str,
        key_flow: int | None = None,
    ) -> FlowBatchRef:
        for flow_id in captured_request_ids:
            await self.client.tag_add(flow_id, tag, color)
        note = self.strip_nul(note_body)
        key = key_flow if key_flow is not None else (captured_request_ids[0] if captured_request_ids else None)
        if key is not None:
            await self.client.note_add(key, note)
        return ref.model_copy(
            update={
                "flow_ids": list(captured_request_ids),
                "tag": tag,
                "color": color,
                "key_flow": key,
                "note": note,
            }
        )

    @staticmethod
    def _exec_id_set(value: Any) -> set[str]:
        """Extract exec ids from a session_stats field that may be a list of id
        strings/ints or a list of ``{exec_id/id: ...}`` dicts (defensive on shape)."""
        out: set[str] = set()
        if isinstance(value, list):
            for e in value:
                if isinstance(e, dict):
                    eid = e.get("exec_id", e.get("id"))
                    if eid is not None:
                        out.add(str(eid))
                elif isinstance(e, (str, int)):
                    out.add(str(e))
        return out

    async def assert_capture(self, ref: FlowBatchRef, exec_ids: list[str]) -> tuple[bool, str]:
        """Prove the batch's target traffic was actually MITM'd/contained.

        Consults ``session_stats``: any exec whose id appears in ``escaped_execs`` (traffic
        left the sandbox) or ``network_zero_flow_execs`` (a network exec that captured no
        flow) is a loud ALARM. Only returns ``(True, "")`` when capture is provably real —
        never merely because ``exec_ids`` happens to be empty.
        """
        stats = await self.client.session_stats()
        escaped = self._exec_id_set(stats.get("escaped_execs"))
        zero_flow = self._exec_id_set(stats.get("network_zero_flow_execs"))
        bad = escaped | zero_flow

        ids = [str(e) for e in (exec_ids or ref.exec_ids or [])]
        offenders = [eid for eid in ids if eid in bad]
        if offenders:
            return (
                False,
                "ALARM: traffic escaped the sandbox — network exec(s) "
                f"{offenders} captured 0 flows / escaped capture; evidence rejected",
            )
        if ids:
            # Every attributed exec captured flows and none escaped.
            return True, ""
        # No exec ids to attribute this batch to. Capture is provable only via the
        # sealed flows, and only if nothing escaped the sandbox in this session.
        if escaped:
            return (
                False,
                "ALARM: unattributable capture — no exec ids on the batch while the "
                f"session reports escaped network exec(s) {sorted(escaped)}; evidence rejected",
            )
        if not ref.flow_ids:
            return (
                False,
                "cannot prove capture: batch has neither exec ids nor captured flows",
            )
        return True, ""

    async def tls_passthru_blocked(self, ref: FlowBatchRef, target: str | None = None) -> bool:
        """True when the target's MITM is blocked (cert-pinned/QUIC ``tls-passthru``).

        Scoped to ``target``'s host when given so an incidental pinned/CDN passthru flow to
        an unrelated third party in the same workspace does not falsely block a captured
        finding; falls back to the whole workspace when no target host is available.
        """
        host = None
        if target:
            from a2pwn.scope import host_of

            host = host_of(target)
        res = await self.client.req_list(
            workspace_id=ref.workspace_id, protocol="tls-passthru", host=host
        )
        return bool(res.get("flows"))

    @staticmethod
    def strip_nul(evidence: str) -> str:
        return evidence.replace("\x00", "")
