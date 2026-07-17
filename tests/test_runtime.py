"""Runtime wiring + teardown coverage — ``runtime.py`` had no tests despite owning bootstrap,
the cleanup-in-finally teardown, and the checkpointer selection.

``bootstrap`` is exercised with every heavy dependency faked so we can assert the wiring contract
(preflight ran, scope was narrowed on the client per in-scope host, the master graph got the live
client + checkpointer). ``run_engagement`` is driven over a fake graph to prove the finally block
always closes the client AND the checkpointer, even when report assembly explodes. ``_make_checkpointer``
is checked for both the sqlite-default and the postgres-uri branch.
"""

from __future__ import annotations

import sys
import types

import pytest

from _graphkit import make_cfg
from a2pwn import runtime
from a2pwn.budget import STOP
from a2pwn.report import Report


# --------------------------------------------------------------------------- #
# bootstrap wiring
# --------------------------------------------------------------------------- #
class _FakeBurpwnClient:
    """Stand-in for the class runtime.bootstrap constructs and calls class methods on."""

    made: _FakeBurpwnClient | None = None

    def __init__(self, session: str) -> None:
        self.session = session
        self.scopes: list[dict] = []
        self.closed = False
        type(self).made = self

    @staticmethod
    def cli_doctor() -> dict:
        return {"ok": True}

    @staticmethod
    def cli_session_new(name: str) -> dict:
        return {"ok": True}

    async def intercept_scope(self, **kw) -> dict:
        self.scopes.append(kw)
        return {"ok": True}

    async def close(self) -> None:
        self.closed = True


async def test_bootstrap_wires_graphs_and_enforces_scope(monkeypatch):
    cfg = make_cfg(targets=["https://app.example.com"])
    calls: dict = {}

    monkeypatch.setattr(runtime, "ensure_burpwn_available", lambda: calls.setdefault("ensure", True))
    monkeypatch.setattr(runtime, "BurpwnClient", _FakeBurpwnClient)

    sentinel_ck = object()

    async def _fake_ck(_cfg):
        return sentinel_ck

    monkeypatch.setattr(runtime, "_make_checkpointer", _fake_ck)
    monkeypatch.setattr(runtime, "_seed_skills", lambda _cfg: [])
    monkeypatch.setattr(runtime, "Collaborator", lambda *a, **k: "collab")
    monkeypatch.setattr(runtime, "MasterFork", lambda *a, **k: "fork")
    monkeypatch.setattr(runtime, "as_langchain_tools", lambda *a, **k: [])
    monkeypatch.setattr(runtime, "burpwn_tools", lambda *a, **k: [])
    monkeypatch.setattr(runtime, "oracle_tools", lambda *a, **k: [])
    monkeypatch.setattr(runtime, "finding_tools", lambda *a, **k: [])
    monkeypatch.setattr(runtime, "build_subagent_graph", lambda *a, **k: "SUBGRAPH")

    captured: dict = {}

    def _fake_master(cfg_, sub, client, ck):
        captured["args"] = (cfg_, sub, client, ck)
        return "MASTERGRAPH"

    monkeypatch.setattr(runtime, "build_master_graph", _fake_master)

    client, graph, checkpointer = await runtime.bootstrap(cfg)

    assert calls.get("ensure") is True  # preflight ran before anything expensive
    assert graph == "MASTERGRAPH"
    assert checkpointer is sentinel_ck
    assert isinstance(client, _FakeBurpwnClient)
    # scope enforcement was pushed to burpwn itself, one call per parsed in-scope host.
    assert client.scopes == [{"host": "app.example.com"}]
    # the master graph was threaded the child subgraph, the LIVE client, and the checkpointer.
    _cfg, sub, gclient, gck = captured["args"]
    assert sub == "SUBGRAPH"
    assert gclient is client
    assert gck is sentinel_ck


async def test_bootstrap_survives_doctor_and_session_new_failures(monkeypatch):
    # doctor + session-new are best-effort preflights: their failures must not abort bootstrap.
    cfg = make_cfg(targets=["https://app.example.com"])

    class _CrankyClient(_FakeBurpwnClient):
        @staticmethod
        def cli_doctor() -> dict:
            raise RuntimeError("doctor unavailable")

        @staticmethod
        def cli_session_new(name: str) -> dict:
            raise RuntimeError("session already exists")

    monkeypatch.setattr(runtime, "ensure_burpwn_available", lambda: None)
    monkeypatch.setattr(runtime, "BurpwnClient", _CrankyClient)

    async def _fake_ck(_cfg):
        return object()

    monkeypatch.setattr(runtime, "_make_checkpointer", _fake_ck)
    monkeypatch.setattr(runtime, "_seed_skills", lambda _cfg: [])
    monkeypatch.setattr(runtime, "Collaborator", lambda *a, **k: "collab")
    monkeypatch.setattr(runtime, "MasterFork", lambda *a, **k: "fork")
    monkeypatch.setattr(runtime, "as_langchain_tools", lambda *a, **k: [])
    monkeypatch.setattr(runtime, "burpwn_tools", lambda *a, **k: [])
    monkeypatch.setattr(runtime, "oracle_tools", lambda *a, **k: [])
    monkeypatch.setattr(runtime, "finding_tools", lambda *a, **k: [])
    monkeypatch.setattr(runtime, "build_subagent_graph", lambda *a, **k: "SUBGRAPH")
    monkeypatch.setattr(runtime, "build_master_graph", lambda *a, **k: "MASTERGRAPH")

    client, graph, _ck = await runtime.bootstrap(cfg)
    assert graph == "MASTERGRAPH"
    assert isinstance(client, _CrankyClient)


# --------------------------------------------------------------------------- #
# run_engagement cleanup-in-finally
# --------------------------------------------------------------------------- #
class _FakeSnap:
    def __init__(self, next_=(), values=None) -> None:
        self.next = next_
        self.values = values or {}
        self.tasks = ()


class _FakeGraph:
    """Minimal astream/aget_state surface: one empty pass, then a terminal (no ``next``) state."""

    def __init__(self, values: dict) -> None:
        self._values = values
        self.astream_calls = 0

    async def astream(self, *a, **k):
        self.astream_calls += 1
        for _ in ():  # empty async generator
            yield _

    async def aget_state(self, config):
        return _FakeSnap(next_=(), values=self._values)


class _FakeConn:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class _FakeCheckpointer:
    def __init__(self) -> None:
        self.conn = _FakeConn()


def _install_fake_run(monkeypatch, tmp_path, fake_client, build_report):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    STOP.clear()
    cfg = make_cfg()
    fake_graph = _FakeGraph({"engagement": cfg.engagement, "findings": []})
    fake_ck = _FakeCheckpointer()

    async def _fake_bootstrap(_cfg):
        return fake_client, fake_graph, fake_ck

    monkeypatch.setattr(runtime, "bootstrap", _fake_bootstrap)
    monkeypatch.setattr(runtime, "build_report", build_report)
    return cfg, fake_graph, fake_ck


async def test_run_engagement_closes_client_and_checkpointer(monkeypatch, tmp_path, fake_client):
    async def _fake_report(final, client, out_dir, **kw):
        return Report(engagement="eng")

    cfg, fake_graph, fake_ck = _install_fake_run(monkeypatch, tmp_path, fake_client, _fake_report)

    report = await runtime.run_engagement(cfg, "objective", "thread-cleanup")

    assert isinstance(report, Report)
    assert fake_graph.astream_calls == 1  # one pass, no interrupt -> loop broke on empty next
    # both subsystems were torn down in the finally block.
    assert fake_client.closed is True
    assert fake_ck.conn.closed is True


async def test_run_engagement_cleans_up_even_when_report_fails(monkeypatch, tmp_path, fake_client):
    async def _boom(final, client, out_dir, **kw):
        raise RuntimeError("report exploded")

    cfg, _fake_graph, fake_ck = _install_fake_run(monkeypatch, tmp_path, fake_client, _boom)

    with pytest.raises(RuntimeError, match="report exploded"):
        await runtime.run_engagement(cfg, "objective", "thread-err")

    # teardown still ran despite the mid-run error (finally block, independent closes).
    assert fake_client.closed is True
    assert fake_ck.conn.closed is True


def test_list_runs_reads_report_metadata(monkeypatch, tmp_path):
    import json

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    base = tmp_path / "a2pwn" / "runs"
    # a run with a report.json …
    (base / "acme").mkdir(parents=True)
    (base / "acme" / "report.json").write_text(
        json.dumps(
            {
                "findings": [{"vuln_class": "xss"}, {"vuln_class": "ssrf"}],
                "confirmed_findings": [{"vuln_class": "sqli"}],
                "stats": {"by_severity": {"high": 2}},
                "objective": "audit",
                "targets": ["https://app.example.com"],
            }
        )
    )
    # … and a bare run directory without a report yet.
    (base / "pending").mkdir(parents=True)

    runs = {r["thread_id"]: r for r in runtime.list_runs()}
    assert runs["acme"]["has_report"] is True
    assert runs["acme"]["verified"] == 2
    assert runs["acme"]["confirmed"] == 1
    assert runs["acme"]["targets"] == ["https://app.example.com"]
    assert runs["pending"]["has_report"] is False


def test_list_runs_empty_when_no_base(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert runtime.list_runs() == []


async def test_close_checkpointer_handles_missing_conn():
    # A checkpointer with no ``conn`` (or no ``close``) must be a silent no-op, never raise.
    class _NoConn:
        pass

    await runtime._close_checkpointer(_NoConn())  # must not raise


# --------------------------------------------------------------------------- #
# _make_checkpointer selection
# --------------------------------------------------------------------------- #
async def test_make_checkpointer_sqlite_default(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    cfg = make_cfg()  # checkpoint_uri defaults to None -> sqlite single-box path
    saver = await runtime._make_checkpointer(cfg)
    try:
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

        assert isinstance(saver, AsyncSqliteSaver)
        assert (tmp_path / "a2pwn" / "runs.db").exists()  # the box was created under XDG_DATA_HOME
    finally:
        conn = getattr(saver, "conn", None)
        if conn is not None:
            await conn.close()


async def test_make_checkpointer_postgres_uri(monkeypatch):
    created: dict = {}

    class _FakePGSaver:
        def __init__(self) -> None:
            self.setup_called = False

        async def setup(self) -> None:
            self.setup_called = True

    class _CtxMgr:
        def __init__(self, saver) -> None:
            self._saver = saver

        async def __aenter__(self):
            return self._saver

        async def __aexit__(self, *a):
            return False

    class _AsyncPostgresSaver:
        @staticmethod
        def from_conn_string(uri: str) -> _CtxMgr:
            created["uri"] = uri
            saver = _FakePGSaver()
            created["saver"] = saver
            return _CtxMgr(saver)

    fake_mod = types.ModuleType("langgraph.checkpoint.postgres.aio")
    fake_mod.AsyncPostgresSaver = _AsyncPostgresSaver
    # Inject only the leaf module: a cached fully-dotted name short-circuits parent imports, so
    # this works even though the postgres extra is not installed in the test env.
    monkeypatch.setitem(sys.modules, "langgraph.checkpoint.postgres.aio", fake_mod)

    cfg = make_cfg().model_copy(update={"checkpoint_uri": "postgresql://u:p@h/db"})
    saver = await runtime._make_checkpointer(cfg)

    assert saver is created["saver"]
    assert saver.setup_called is True  # setup() was awaited on the entered saver
    assert created["uri"] == "postgresql://u:p@h/db"
