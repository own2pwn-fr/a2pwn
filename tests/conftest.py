"""Shared pytest fixtures for a2pwn.

``fake_client`` is an in-memory stand-in for :class:`a2pwn.burpwn.BurpwnClient`
covering the whole async surface other modules drive; it records calls and
returns programmable values (set ``.execs`` inputs, ``.flows_by_ws``, ``.stats``,
``.exec_return``, ``.workspaces`` in a test). No real burpwn process is spawned.
"""

from __future__ import annotations

from typing import Any

import pytest

from a2pwn.models import Finding, FlowBatchRef


class FakeBurpwnClient:
    """Records calls and returns programmable values, matching BurpwnClient."""

    def __init__(self) -> None:
        # ---- recorded calls ----
        self.execs: list[dict] = []
        self.req_list_calls: list[dict] = []
        self.req_show_calls: list[dict] = []
        self.req_search_calls: list[str] = []
        self.replays: list[dict] = []
        self.fuzzes: list[dict] = []
        self.tags: list[dict] = []
        self.notes: list[dict] = []
        self.workspaces_created: list[str] = []
        self.compares: list[dict] = []
        self.intercept_forwards: list[dict] = []
        self.closed = False
        # ---- programmable return values ----
        self.exec_return: dict = {"exit_code": 0, "captured_request_ids": [], "exec_id": "exec-0"}
        self.flows_by_ws: dict[int, list[dict]] = {}
        self.all_flows: list[dict] = []
        self.stats: dict = {
            "total_execs": 0,
            "network_execs": 0,
            "network_zero_flow_execs": 0,
            "escaped_execs": [],
        }
        self.workspaces: list[dict] = [{"id": 1, "name": "default"}]
        self.search_results: list[int] = []
        self.replay_return: dict = {"status": 200, "response": ""}
        self.fuzz_return: dict = {"attack_id": 1}
        self.fuzz_results_return: dict = {"results": []}
        self.compare_return: dict = {"reflected": False}
        self.intercept_return: dict = {"pending": False}
        self.encode_return: dict = {"result": ""}
        self._ws_seq = max((w["id"] for w in self.workspaces), default=0)

    async def close(self) -> None:
        self.closed = True

    async def exec(
        self, argv: list[str], workspace: str | None = None, timeout_secs: int | None = None
    ) -> dict:
        self.execs.append({"argv": argv, "workspace": workspace, "timeout_secs": timeout_secs})
        return self.exec_return

    async def req_list(
        self,
        workspace_id: int | None = None,
        host: str | None = None,
        protocol: str | None = None,
        status: int | None = None,
        method: str | None = None,
        limit: int | None = None,
    ) -> dict:
        self.req_list_calls.append(
            {
                "workspace_id": workspace_id,
                "host": host,
                "protocol": protocol,
                "status": status,
                "method": method,
                "limit": limit,
            }
        )
        if workspace_id is not None:
            flows = list(self.flows_by_ws.get(workspace_id, []))
        else:
            flows = list(self.all_flows)
        if protocol is not None:
            flows = [f for f in flows if f.get("protocol") == protocol]
        if status is not None:
            flows = [f for f in flows if f.get("status") == status]
        if method is not None:
            flows = [f for f in flows if f.get("method") == method]
        if host is not None:
            flows = [f for f in flows if host in (f.get("authority") or f.get("sni") or "")]
        if limit is not None:
            flows = flows[:limit]
        return {"flows": flows, "count": len(flows)}

    async def req_show(self, id: int, raw: bool = False) -> dict:
        self.req_show_calls.append({"id": id, "raw": raw})
        for f in self.all_flows:
            if f.get("id") == id:
                return f
        return {"id": id}

    async def req_search(self, query: str) -> list[int]:
        self.req_search_calls.append(query)
        return list(self.search_results)

    async def req_replay(
        self,
        id: int,
        set_headers: list[dict] | None = None,
        set_body: str | None = None,
        method: str | None = None,
    ) -> dict:
        self.replays.append(
            {"id": id, "set_headers": set_headers or [], "set_body": set_body, "method": method}
        )
        return self.replay_return

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
        self.fuzzes.append(
            {"flow": flow, "positions": positions, "payloads": payloads, "mode": mode}
        )
        return self.fuzz_return

    async def fuzz_results(self, attack_id: int, sort: str = "anomaly", limit: int | None = None) -> dict:
        return self.fuzz_results_return

    async def compare(self, flow_a: int, flow_b: int, what: str = "all") -> dict:
        self.compares.append({"flow_a": flow_a, "flow_b": flow_b, "what": what})
        return self.compare_return

    async def tag_add(self, flow_id: int, name: str, color: str | None = None) -> dict:
        self.tags.append({"flow_id": flow_id, "name": name, "color": color})
        return {"tag_id": len(self.tags)}

    async def note_add(self, flow_id: int, body: str) -> dict:
        self.notes.append({"flow_id": flow_id, "body": body})
        return {"note_id": len(self.notes)}

    async def workspace_new(self, name: str) -> int:
        self.workspaces_created.append(name)
        for w in self.workspaces:
            if w["name"] == name:
                return int(w["id"])
        self._ws_seq += 1
        self.workspaces.append({"id": self._ws_seq, "name": name})
        return self._ws_seq

    async def workspace_id_of(self, name: str) -> int:
        for w in self.workspaces:
            if w["name"] == name:
                return int(w["id"])
        raise KeyError(f"workspace {name!r} not found")

    async def session_stats(self) -> dict:
        return self.stats

    async def intercept_enable(self) -> dict:
        return {"ok": True}

    async def await_intercept(self, timeout_secs: int | None = None) -> dict:
        return self.intercept_return

    async def intercept_forward(self, id: int, **kw: Any) -> dict:
        self.intercept_forwards.append({"id": id, **kw})
        return {"ok": True}

    async def intercept_scope(self, **kw: Any) -> dict:
        return {"ok": True}

    async def encode(self, scheme: str, value: str) -> dict:
        return self.encode_return

    async def decode(self, scheme: str, value: str) -> dict:
        return self.encode_return


@pytest.fixture
def fake_client() -> FakeBurpwnClient:
    return FakeBurpwnClient()


@pytest.fixture
async def tmp_saver(tmp_path):
    # Async saver: the graphs are driven with ainvoke/astream (sub-agent tools are async-only).
    from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

    async with AsyncSqliteSaver.from_conn_string(str(tmp_path / "runs.db")) as saver:
        yield saver


@pytest.fixture
def sample_finding() -> Finding:
    target = "https://app.example.com/search"
    return Finding(
        key=Finding.make_key("xss", target, "q"),
        vuln_class="xss",
        sub_variant="reflected",
        severity="medium",
        target=target,
        param="q",
        evidence="payload <svg/onload=alert(1)> reflected unencoded in response body",
        confirmed=True,
        independently_verified=False,
        oracle_kind="differential",
        flow_batch=FlowBatchRef(
            workspace="xss-poc",
            workspace_id=2,
            tag="xss",
            color="red",
            flow_ids=[101, 102],
            key_flow=101,
            note="reflected XSS on q",
        ),
    )
