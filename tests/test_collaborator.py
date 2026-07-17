"""Tests for the OOB collaborator: in-sandbox flow correlation and external HTTP polling."""

from __future__ import annotations

import asyncio

import pytest

from a2pwn import collaborator as collab_mod
from a2pwn._oob_listener import build_dns_response, parse_qname
from a2pwn.collaborator import Collaborator, OOBHit, _extract_interactions


class FakeClient:
    """Duck-typed stand-in for BurpwnClient covering the surface the collaborator touches."""

    def __init__(self, flows_by_proto: dict[str, list[dict]], search_ids: list[int]) -> None:
        self._flows = flows_by_proto
        self._search_ids = search_ids
        self.exec_calls: list[tuple[list[str], str | None, int | None]] = []
        self.exec_started = asyncio.Event()

    async def req_search(self, query: str) -> list[int]:
        return list(self._search_ids)

    async def req_list(
        self,
        workspace_id=None,
        host=None,
        protocol=None,
        status=None,
        method=None,
        limit=None,
    ) -> dict:
        flows = self._flows.get(protocol, [])
        return {"flows": flows, "count": len(flows)}

    async def exec(self, argv, workspace=None, timeout_secs=None) -> dict:
        # The launch exec is a *backgrounding* shell that returns immediately (the listener
        # is detached), so it must NOT block — blocking here is the deadlock we fixed.
        self.exec_calls.append((argv, workspace, timeout_secs))
        self.exec_started.set()
        return {"exit_code": 0}


# --------------------------------------------------------------------------- in-sandbox


async def test_poll_in_sandbox_finds_dns_and_rawtcp_flows():
    fc = FakeClient(flows_by_proto={}, search_ids=[])
    collab = Collaborator(fc)
    cid = collab.new_correlation()

    fc._flows = {
        "dns": [{"id": 42, "protocol": "dns", "sni": f"{cid}.oob.local", "client_addr": "10.0.0.5:5353"}],
        "rawtcp": [{"id": 43, "protocol": "rawtcp", "authority": "", "client_addr": "10.0.0.5:9000"}],
    }
    fc._search_ids = [42, 43]

    hits = await collab.poll(cid, timeout_secs=2, protocols=("dns", "rawtcp"))

    assert {h.flow_id for h in hits} == {42, 43}
    assert {h.protocol for h in hits} == {"dns", "rawtcp"}
    assert all(h.correlation_id == cid for h in hits)
    dns_hit = next(h for h in hits if h.protocol == "dns")
    assert dns_hit.source_ip == "10.0.0.5:5353"
    assert cid in dns_hit.raw


async def test_poll_in_sandbox_maps_http_to_h1_h2():
    fc = FakeClient(flows_by_proto={}, search_ids=[7])
    collab = Collaborator(fc)
    cid = collab.new_correlation()
    fc._flows = {"h1": [{"id": 7, "protocol": "h1", "authority": "svc", "path": f"/{cid}"}]}

    hits = await collab.poll(cid, timeout_secs=2, protocols=("http",))

    assert len(hits) == 1
    assert hits[0].protocol == "http"
    assert hits[0].flow_id == 7


async def test_poll_in_sandbox_times_out_empty():
    fc = FakeClient(flows_by_proto={"dns": []}, search_ids=[])
    collab = Collaborator(fc)
    hits = await collab.poll("deadbeef", timeout_secs=0, protocols=("dns",))
    assert hits == []


async def test_row_content_match_without_search_hit():
    # FTS misses but the correlation id is visible in the flow metadata -> still a hit.
    fc = FakeClient(flows_by_proto={}, search_ids=[])
    collab = Collaborator(fc)
    cid = collab.new_correlation()
    fc._flows = {"dns": [{"id": 99, "protocol": "dns", "sni": f"{cid}.evil.test"}]}
    hits = await collab.poll(cid, timeout_secs=2, protocols=("dns",))
    assert [h.flow_id for h in hits] == [99]


def test_payload_url_embeds_correlation():
    collab = Collaborator(FakeClient({}, []), external_base="oob.example.com")
    cid = "cafebabecafebabe"
    assert collab.payload_url(cid, scheme="http") == f"http://{cid}.oob.example.com/{cid}"
    assert collab.payload_url(cid, scheme="dns") == f"{cid}.oob.example.com"


def test_new_correlation_is_16_hex():
    collab = Collaborator(FakeClient({}, []))
    cid = collab.new_correlation()
    assert len(cid) == 16
    int(cid, 16)  # valid hex


# --------------------------------------------------------------------------- lifecycle


async def test_start_in_sandbox_launches_detached_and_stop():
    fc = FakeClient({}, [])
    collab = Collaborator(fc)
    await asyncio.wait_for(collab.start_in_sandbox(protocols=("dns", "http", "rawtcp")), timeout=1.0)
    assert fc.exec_started.is_set()

    argv, workspace, timeout_secs = fc.exec_calls[0]
    # Launched through a throwaway backgrounding shell — NOT a foreground exec that would
    # hold the request lock for the listener's whole TTL and starve poll().
    assert argv[0] == "sh" and argv[1] == "-c"
    wrapper = argv[2]
    assert "a2pwn._oob_listener" in wrapper
    assert "--protocols" in wrapper
    assert "&" in wrapper  # backgrounded so the exec returns immediately
    assert collab_mod._LAUNCH_TOKEN in wrapper
    # launch timeout is short and independent of the (up to an hour) listener TTL
    assert timeout_secs is not None and timeout_secs <= 60

    # idempotent: a second start does not relaunch the sink
    await collab.start_in_sandbox()
    assert len(fc.exec_calls) == 1

    await collab.stop()
    assert collab._started is False
    # stop issues a best-effort pkill of the listener
    assert any("pkill" in str(call[0]) for call in fc.exec_calls)


class _LockedFakeClient:
    """Models BurpwnClient's single request lock. A *foreground* exec would hold the lock
    for its child's whole life; req_search/req_list need the same lock. So a listener run in
    the foreground starves poll(). A backgrounding launch exec must return at once instead."""

    def __init__(self, flows_by_proto: dict[str, list[dict]], search_ids: list[int]) -> None:
        self._flows = flows_by_proto
        self._search_ids = search_ids
        self._lock = asyncio.Lock()
        self.listener_running = False

    async def exec(self, argv, workspace=None, timeout_secs=None) -> dict:
        joined = " ".join(str(a) for a in argv)
        if "&" in joined or "setsid" in joined:  # backgrounded -> returns without holding the lock
            self.listener_running = True
            return {"exit_code": 0}
        async with self._lock:  # a foreground long-lived listener pins the lock forever
            await asyncio.Event().wait()
        return {}

    async def req_search(self, query: str) -> list[int]:
        async with self._lock:
            return list(self._search_ids)

    async def req_list(self, protocol=None, **kwargs) -> dict:
        async with self._lock:
            flows = self._flows.get(protocol, [])
            return {"flows": flows, "count": len(flows)}


async def test_poll_runs_concurrently_with_live_listener():
    # Regression for the deadlock: poll() must reach req_search/req_list while the listener
    # is alive. With the old foreground-exec design this times out on the request lock.
    cid = "deadbeefdeadbeef"
    fc = _LockedFakeClient(
        flows_by_proto={"dns": [{"id": 5, "protocol": "dns", "sni": f"{cid}.oob.test"}]},
        search_ids=[5],
    )
    collab = Collaborator(fc)
    await asyncio.wait_for(collab.start_in_sandbox(protocols=("dns",)), timeout=1.0)
    assert fc.listener_running is True

    hits = await asyncio.wait_for(
        collab.poll(cid, timeout_secs=2, protocols=("dns",)), timeout=5.0
    )
    assert [h.flow_id for h in hits] == [5]


# --------------------------------------------------------------------------- external


class _FakeResponse:
    def __init__(self, payload) -> None:
        self._payload = payload

    def json(self):
        return self._payload


class _FakeAsyncClient:
    payload: object = []
    seen_params: list[dict] = []

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, params=None):
        type(self).seen_params.append(params or {})
        return _FakeResponse(type(self).payload)


async def test_poll_external_via_monkeypatched_httpx(monkeypatch):
    _FakeAsyncClient.seen_params = []
    _FakeAsyncClient.payload = [
        {
            "protocol": "http",
            "remote-address": "203.0.113.9",
            "raw-request": "GET /x HTTP/1.1",
            "unique-id": "abc",
        },
        {"protocol": "dns", "remote_address": "203.0.113.10", "raw": "A? abc.oob"},
    ]
    monkeypatch.setattr(collab_mod.httpx, "AsyncClient", _FakeAsyncClient)

    collab = Collaborator(FakeClient({}, []), external_base="oob.example.com")
    hits = await collab.poll("abc", timeout_secs=2)

    assert {h.protocol for h in hits} == {"http", "dns"}
    http_hit = next(h for h in hits if h.protocol == "http")
    assert http_hit.source_ip == "203.0.113.9"
    assert http_hit.raw == "GET /x HTTP/1.1"
    assert http_hit.correlation_id == "abc"
    assert _FakeAsyncClient.seen_params[0]["id"] == "abc"


async def test_poll_external_prepends_scheme(monkeypatch):
    _FakeAsyncClient.seen_params = []
    _FakeAsyncClient.payload = {"interactions": [{"protocol": "smtp", "source_ip": "198.51.100.4"}]}
    monkeypatch.setattr(collab_mod.httpx, "AsyncClient", _FakeAsyncClient)

    collab = Collaborator(FakeClient({}, []), external_base="oob.example.com")
    hits = await collab.poll("zzz", timeout_secs=2)
    assert len(hits) == 1
    assert hits[0].protocol == "smtp"


# --------------------------------------------------------------------------- parsing helpers


def test_extract_interactions_shapes():
    assert _extract_interactions(None, "x") == []
    assert _extract_interactions([], "x") == []
    wrapped = _extract_interactions({"data": [{"protocol": "http"}]}, "x")
    assert len(wrapped) == 1 and wrapped[0].protocol == "http"
    unknown = _extract_interactions([{"protocol": "ldap"}], "x")
    assert unknown[0].protocol == "http"  # unknown protocol falls back to http


def test_oob_hit_defaults():
    hit = OOBHit(correlation_id="c", protocol="dns")
    assert hit.source_ip is None and hit.raw == "" and hit.flow_id is None


# --------------------------------------------------------------------------- listener wire format


def test_dns_parse_and_response_roundtrip():
    # query for "abcd.oob" (labels: 4 'abcd', 3 'oob')
    header = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"\x04abcd\x03oob\x00"
    qtail = b"\x00\x01\x00\x01"  # type A, class IN
    query = header + qname + qtail

    name, offset = parse_qname(query)
    assert name == "abcd.oob"
    assert query[offset : offset + 4] == qtail

    resp = build_dns_response(query, ip="127.0.0.1")
    assert resp[0:2] == b"\x12\x34"  # echoed transaction id
    assert resp[2:4] == b"\x81\x80"  # response flags
    assert resp[6:8] == b"\x00\x01"  # one answer
    assert resp.endswith(b"\x7f\x00\x00\x01")  # 127.0.0.1 A record


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
