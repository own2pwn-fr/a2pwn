"""WebSocket support: RFC 6455 framing, the in-sandbox driver, and the two engagement-gated tools.

The framing half runs for real — against an in-process echo server and a socketpair — because that
is where the bugs hide and a mock would only assert that our own encoder agrees with our own decoder
on the happy path. Masking, all three payload-length forms, fragmentation and the closing handshake
each get a test: a client that forgets to mask is closed by every conforming server, and a client
that mis-sizes a 16-bit length silently desynchronises the stream instead of failing loudly.

The burpwn half is faked (no sandbox, no network): what matters there is that the transcript survives
the round trip through a file — ``exec`` returns no stdout — and that the flow ids come back attached,
since a WebSocket finding with no captured flow is exactly what the oracles exist to reject.
"""

from __future__ import annotations

import json
import socket
import socketserver
import struct
import threading

import pytest

from a2pwn._ws_client import (
    OP_BINARY,
    OP_CLOSE,
    OP_CONT,
    OP_PING,
    OP_PONG,
    OP_TEXT,
    FrameReader,
    WSError,
    accept_token,
    build_frame,
    build_handshake,
    fragment,
    mask_payload,
    parse_frame,
    parse_handshake_response,
    parse_ws_url,
    run_session,
)
from a2pwn.config import EngagementSpec, IdentitySpec
from a2pwn.identity import IdentityStore
from a2pwn.scope import ScopeGuard
from a2pwn.throttle import Throttle
from a2pwn.tools.websocket_tools import build_ws_tool_specs, websocket_tools
from a2pwn.websocket import (
    client_argv,
    flow_ws_url,
    parse_header_block,
    replayable_headers,
    run_ws_client,
    transcript_dir,
)

# --------------------------------------------------------------------------- a real echo server


class _EchoHandler(socketserver.BaseRequestHandler):
    """Minimal conforming server: completes the upgrade, echoes data messages, answers pings."""

    def handle(self) -> None:
        sock = self.request
        sock.settimeout(10)
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = sock.recv(4096)
            if not chunk:
                return
            raw += chunk
        head, _, rest = raw.partition(b"\r\n\r\n")
        _, headers = parse_handshake_response(head)
        self.server.seen_headers = headers  # type: ignore[attr-defined]
        sock.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_token(headers.get('sec-websocket-key', ''))}\r\n\r\n"
            ).encode()
        )
        reader = FrameReader()
        pending: list[bytes] = []
        op = OP_TEXT
        data = rest
        while True:
            for frame in reader.feed(data):
                if not frame.masked and frame.opcode in (OP_TEXT, OP_BINARY, OP_CONT):
                    # A conforming server rejects an unmasked client data frame outright (§5.1);
                    # surfacing it as a 1002 close is what makes the masking test meaningful.
                    sock.sendall(build_frame(OP_CLOSE, struct.pack("!H", 1002), mask=False))
                    return
                if frame.opcode in (OP_TEXT, OP_BINARY):
                    pending, op = [frame.payload], frame.opcode
                elif frame.opcode == OP_CONT:
                    pending.append(frame.payload)
                elif frame.opcode == OP_PING:
                    sock.sendall(build_frame(OP_PONG, frame.payload, mask=False))
                    continue
                elif frame.opcode == OP_CLOSE:
                    sock.sendall(build_frame(OP_CLOSE, frame.payload[:2], mask=False))
                    return
                else:
                    continue
                if frame.fin:
                    sock.sendall(build_frame(op, b"echo:" + b"".join(pending), mask=False))
                    pending = []
            try:
                data = sock.recv(65536)
            except OSError:
                return
            if not data:
                return

    def log_message(self, *_: object) -> None:
        return


class _EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@pytest.fixture
def echo_url():
    """A live ``ws://127.0.0.1:<port>/`` echo endpoint for the duration of one test."""
    srv = _EchoServer(("127.0.0.1", 0), _EchoHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    host, port = srv.server_address[:2]
    try:
        yield f"ws://{host}:{port}/chat"
    finally:
        srv.shutdown()
        srv.server_close()


# --------------------------------------------------------------------------- framing


def test_mask_is_involutive_so_the_same_routine_encodes_and_decodes():
    """XOR masking must round-trip: one routine serves both directions, so a bug would be silent."""
    payload = bytes(range(256)) * 3
    key = b"\x01\x9f\x00\xff"
    assert mask_payload(mask_payload(payload, key), key) == payload


def test_client_frames_are_masked_because_the_rfc_requires_it():
    """RFC 6455 §5.3: every client-to-server frame is masked. An unmasked one is closed with 1002,
    which is the single most common failure of a hand-rolled client."""
    raw = build_frame(OP_TEXT, b"hello")
    assert raw[1] & 0x80, "MASK bit must be set on a client frame"
    assert b"hello" not in raw, "the payload must be masked on the wire, not sent in the clear"
    frame, consumed = parse_frame(raw)
    assert consumed == len(raw)
    assert frame.payload == b"hello"
    assert frame.masked is True


def test_masking_uses_a_fresh_key_per_frame():
    """A reused key makes two identical messages identical on the wire — the RFC requires a new,
    unpredictable key per frame precisely to stop that."""
    keys = {build_frame(OP_TEXT, b"x" * 8)[2:6] for _ in range(20)}
    assert len(keys) > 1


@pytest.mark.parametrize(
    ("size", "expected_len_byte", "header_len"),
    [(5, 5, 2), (125, 125, 2), (126, 126, 4), (4096, 126, 4), (0xFFFF, 126, 4), (0x10000, 127, 10)],
)
def test_every_payload_length_form_round_trips(size, expected_len_byte, header_len):
    """The 7-bit / 16-bit / 64-bit length forms (§5.2), each in the SHORTEST encoding that fits.

    Over-long encoding is what a server validating minimal length rejects, and a boundary off by one
    at 125/126 or 65535/65536 desynchronises the whole stream rather than failing on that frame.
    """
    payload = b"A" * size
    raw = build_frame(OP_BINARY, payload, mask=False)
    assert raw[1] & 0x7F == expected_len_byte
    assert len(raw) == header_len + size
    frame, consumed = parse_frame(raw)
    assert consumed == len(raw)
    assert frame.payload == payload


def test_a_frame_split_across_reads_is_buffered_until_complete():
    """A stream socket splits frames anywhere. Decoding must buffer, not assume recv() is aligned —
    otherwise the client "works locally" and loses frames against a real target."""
    raw = build_frame(OP_TEXT, b"z" * 300)
    reader = FrameReader()
    for i in range(len(raw) - 1):
        assert reader.feed(raw[i : i + 1]) == [], "no frame may be emitted before the last byte"
    frames = reader.feed(raw[-1:])
    assert [f.payload for f in frames] == [b"z" * 300]
    assert reader.pending == 0


def test_several_frames_in_one_read_are_all_decoded():
    """The reverse case: a server may pipeline frames into one TCP segment."""
    raw = build_frame(OP_TEXT, b"a") + build_frame(OP_TEXT, b"b") + build_frame(OP_PING, b"")
    frames = FrameReader().feed(raw)
    assert [(f.opcode, f.payload) for f in frames] == [(OP_TEXT, b"a"), (OP_TEXT, b"b"), (OP_PING, b"")]


def test_an_incomplete_frame_returns_none_rather_than_raising():
    """A short buffer is the normal case on a socket, never an error."""
    assert parse_frame(b"\x81") is None
    assert parse_frame(build_frame(OP_TEXT, b"abcdef")[:-2]) is None


def test_an_absurd_announced_length_is_refused_before_allocating():
    """A hostile peer can announce a 64-bit length; refusing beats OOM-ing the sandbox."""
    with pytest.raises(WSError):
        parse_frame(b"\x82\x7f" + struct.pack("!Q", 1 << 40))


def test_fragmentation_puts_the_opcode_first_and_fin_last():
    """§5.4: only the first fragment carries the data opcode, only the last sets FIN. Getting this
    wrong makes the server treat each fragment as a separate message."""
    parts = fragment(b"abcdefg", OP_TEXT, 3)
    assert parts == [(OP_TEXT, b"abc", False), (OP_CONT, b"def", False), (OP_CONT, b"g", True)]
    assert fragment(b"abc", OP_TEXT, 0) == [(OP_TEXT, b"abc", True)], "0 disables fragmentation"
    assert fragment(b"ab", OP_TEXT, 9) == [(OP_TEXT, b"ab", True)], "no split when it already fits"


def test_accept_token_matches_the_rfc_worked_example():
    """The §1.3 worked example. If this drifts, every handshake silently reports accept_ok=False."""
    assert accept_token("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


@pytest.mark.parametrize(
    ("url", "host", "port", "resource", "secure"),
    [
        ("ws://h.tld/chat", "h.tld", 80, "/chat", False),
        ("wss://h.tld/s?t=1", "h.tld", 443, "/s?t=1", True),
        ("ws://h.tld:8080", "h.tld", 8080, "/", False),
        ("https://h.tld/live", "h.tld", 443, "/live", True),
    ],
)
def test_ws_url_parsing(url, host, port, resource, secure):
    """http(s) is accepted as an alias: that is the scheme a captured upgrade flow carries, and
    refusing it would only make the agent guess at the rewrite."""
    target = parse_ws_url(url)
    assert (target.host, target.port, target.resource, target.secure) == (host, port, resource, secure)


def test_an_unsupported_scheme_is_refused():
    with pytest.raises(WSError):
        parse_ws_url("ftp://h.tld/x")


def test_the_handshake_carries_custom_headers_but_never_a_caller_supplied_key():
    """Origin and Cookie must be overridable — an origin swap IS the CSWSH test — while the key and
    version stay ours, since the Accept check we then run is only meaningful against our own key."""
    target = parse_ws_url("wss://h.tld/live")
    raw = build_handshake(
        target,
        "KEY==",
        {"Origin": "https://attacker.tld", "Cookie": "s=1", "Sec-WebSocket-Key": "attacker"},
    ).decode()
    assert "Origin: https://attacker.tld" in raw
    assert "Cookie: s=1" in raw
    assert "Sec-WebSocket-Key: KEY==" in raw
    assert "attacker" not in raw.split("Origin:")[0] + raw.split("\r\n")[-1]
    assert raw.startswith("GET /live HTTP/1.1\r\n")
    assert "Host: h.tld\r\n" in raw, "the default port is omitted from Host, as browsers do"


# --------------------------------------------------------------------------- real round trips


def test_round_trip_against_a_real_server(echo_url):
    """The whole client, end to end over a socket: handshake, masked text frame, echo, close."""
    result = run_session(echo_url, {"Origin": "https://attacker.tld"}, ["ping-me"], wait_secs=1.0)
    assert result["error"] is None
    assert result["handshake"]["status"] == 101
    assert result["handshake"]["accept_ok"] is True
    assert [m["data"] for m in result["messages"]] == ["echo:ping-me"]
    sent = [f for f in result["frames"] if f["dir"] == "sent" and f["opcode"] == "text"]
    assert [f["data"] for f in sent] == ["ping-me"]


def test_a_fragmented_message_is_reassembled_by_the_server(echo_url):
    """Fragmenting is a filter-bypass primitive: the server must still see ONE message, so the split
    has to be invisible above the framing layer."""
    result = run_session(echo_url, None, ["abcdefghij"], wait_secs=1.0, fragment_size=3)
    assert [m["data"] for m in result["messages"]] == ["echo:abcdefghij"]
    kinds = [(f["opcode"], f["fin"]) for f in result["frames"] if f["dir"] == "sent"]
    assert kinds[:4] == [("text", False), ("cont", False), ("cont", False), ("cont", True)]


def test_the_closing_handshake_terminates_instead_of_ping_ponging(echo_url):
    """§5.5.1: the side that opens the close must NOT answer the mirror. When it does, the two peers
    echo closes at each other and the connection never ends."""
    result = run_session(echo_url, None, ["x"], wait_secs=0.2)
    closes = [f for f in result["frames"] if f["opcode"] == "close"]
    assert [f["dir"] for f in closes] == ["sent", "recv"]
    assert result["closed"]["initiator"] == "client"
    assert result["closed"]["code"] == 1000
    assert closes[0]["code"] == 1000, "a close code is decoded, not left as opaque bytes"


def test_a_refused_handshake_is_a_result_not_an_exception():
    """A server that declines the upgrade is an OBSERVATION the agent must see; raising here would
    lose it and read to the model as a broken tool."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def _refuse() -> None:
        conn, _ = srv.accept()
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        conn.close()

    threading.Thread(target=_refuse, daemon=True).start()
    host, port = srv.getsockname()
    result = run_session(f"ws://{host}:{port}/x", None, ["hi"], wait_secs=0.2)
    srv.close()
    assert result["handshake"]["status"] == 403
    assert "403" in result["error"]
    assert result["frames"] == []


def test_a_server_ping_is_answered_with_a_pong():
    """Keepalive-driven servers drop a client that ignores pings, which would silently truncate a
    long-running message-level test."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got: list[bytes] = []

    def _ping_once() -> None:
        conn, _ = srv.accept()
        raw = b""
        while b"\r\n\r\n" not in raw:
            raw += conn.recv(4096)
        _, headers = parse_handshake_response(raw.split(b"\r\n\r\n")[0])
        conn.sendall(
            (
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_token(headers.get('sec-websocket-key', ''))}\r\n\r\n"
            ).encode()
        )
        conn.sendall(build_frame(OP_PING, b"are-you-there", mask=False))
        reader = FrameReader()
        while True:
            data = conn.recv(4096)
            if not data:
                break
            for frame in reader.feed(data):
                if frame.opcode == OP_PONG:
                    got.append(frame.payload)
                    conn.close()
                    return

    threading.Thread(target=_ping_once, daemon=True).start()
    host, port = srv.getsockname()
    run_session(f"ws://{host}:{port}/x", None, [], wait_secs=1.0)
    srv.close()
    assert got == [b"are-you-there"]


# --------------------------------------------------------------------------- the host driver


class _WSFakeClient:
    """burpwn stand-in that plays the part ``exec`` plays: it writes the transcript file itself."""

    def __init__(self, transcript: dict | None = None, flow_ids: list[int] | None = None) -> None:
        self.transcript = transcript
        self.flow_ids = list([7] if flow_ids is None else flow_ids)
        self.execs: list[dict] = []
        self.flows: dict[int, dict] = {}
        self.shown: list[int] = []

    async def exec(self, argv, workspace=None, timeout_secs=None) -> dict:
        self.execs.append({"argv": argv, "workspace": workspace, "timeout_secs": timeout_secs})
        if self.transcript is not None:
            out = argv[argv.index("--out") + 1]
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(self.transcript, fh)
        return {"exit_code": 0, "captured_request_ids": list(self.flow_ids), "exec_id": "exec-1"}

    async def req_show(self, id: int, raw: bool = False) -> dict:
        self.shown.append(id)
        return self.flows.get(id, {"id": id})


@pytest.fixture
def ws_dir(tmp_path, monkeypatch):
    """Redirect the transcript directory: the real one is the cwd, which tests must not write to."""
    monkeypatch.setenv("A2PWN_WS_DIR", str(tmp_path / "ws"))
    return tmp_path / "ws"


def _transcript(**over) -> dict:
    base = {
        "url": "ws://app.example.com/chat",
        "handshake": {"status": 101, "accept_ok": True},
        "frames": [{"dir": "recv", "opcode": "text", "data": "hi", "fin": True, "size": 2, "t": 0.1}],
        "messages": [{"opcode": "text", "data": "hi", "size": 2, "t": 0.1}],
        "closed": {"code": 1000},
        "error": None,
    }
    base.update(over)
    return base


def test_the_transcript_travels_through_a_file_because_exec_has_no_stdout(ws_dir):
    """``burpwn exec`` returns only ``{exit_code, captured_request_ids, exec_id}``. Everything the
    client observed has to come back off the shared filesystem or it is simply lost."""
    client = _WSFakeClient(_transcript(), flow_ids=[11, 12])
    import asyncio

    result = asyncio.run(
        run_ws_client(client, "ws://app.example.com/chat", messages=["hi"], wait_secs=1.0)
    )
    assert result["messages"] == [{"opcode": "text", "data": "hi", "size": 2, "t": 0.1}]
    assert result["captured_request_ids"] == [11, 12]
    assert result["exec_id"] == "exec-1"
    assert "capture_warning" not in result


def test_the_transcript_file_is_removed_after_it_is_read(ws_dir):
    """The transcript lives in the engagement's working directory; leaving one per connection there
    would litter the operator's repo."""
    client = _WSFakeClient(_transcript())
    import asyncio

    asyncio.run(run_ws_client(client, "ws://app.example.com/chat", messages=["hi"]))
    assert list(ws_dir.glob("*.json")) == []


def test_zero_captured_flows_raises_a_capture_warning(ws_dir):
    """Frames exchanged but nothing captured means the traffic escaped the MITM. Silence here would
    hand an oracle a finding with no evidence behind it."""
    client = _WSFakeClient(_transcript(), flow_ids=[])
    import asyncio

    result = asyncio.run(run_ws_client(client, "ws://app.example.com/chat", messages=["hi"]))
    assert "ZERO burpwn flows" in result["capture_warning"]


def test_a_missing_transcript_is_an_error_not_a_crash(ws_dir):
    """The in-sandbox client failing to start (wrong interpreter, missing module) must surface as a
    readable error — this exact case was hit live and produced no transcript at all."""
    client = _WSFakeClient(transcript=None)
    import asyncio

    result = asyncio.run(run_ws_client(client, "ws://app.example.com/chat", messages=["hi"]))
    assert "no transcript" in result["error"]
    assert result["captured_request_ids"] == [7]


def test_a_burpwn_transport_failure_is_returned_not_raised(ws_dir):
    """A dead MCP transport must not blow up the executor's tool loop."""

    class _Broken(_WSFakeClient):
        async def exec(self, argv, workspace=None, timeout_secs=None):
            raise RuntimeError("transport died")

    import asyncio

    result = asyncio.run(run_ws_client(_Broken(), "ws://app.example.com/chat"))
    assert "transport died" in result["error"]
    assert result["captured_request_ids"] == []


def test_the_client_is_launched_with_this_interpreter(ws_dir):
    """A bare ``python`` is not necessarily the interpreter that can import a2pwn (uvx, wrapper
    venvs); using sys.executable is what makes the in-sandbox launch reliable."""
    import sys

    argv = client_argv("ws://h/x", ws_dir / "t.json", headers={"Origin": "https://a.tld"}, messages=["m"])
    assert argv[:3] == [sys.executable, "-m", "a2pwn._ws_client"]
    assert "--header" in argv and "Origin: https://a.tld" in argv
    assert argv[argv.index("--message") + 1] == "m"


def test_transcript_dir_defaults_under_the_working_directory(monkeypatch, tmp_path):
    """The sandbox mounts only the cwd read-write (verified on burpwn 0.4.0): a transcript written
    anywhere else either fails read-only or lands in the sandbox's private /tmp."""
    monkeypatch.delenv("A2PWN_WS_DIR", raising=False)
    monkeypatch.chdir(tmp_path)
    assert transcript_dir() == tmp_path / ".a2pwn-ws"


# --------------------------------------------------------------------------- captured-flow reuse


def test_header_block_parsing_keeps_credentials_and_drops_per_connection_headers():
    """Replaying Sec-WebSocket-Key would make our own Accept check fail; dropping Cookie would turn
    an authenticated replay into an anonymous one, i.e. a false "access control held"."""
    raw = (
        "host: app.example.com\r\nupgrade: websocket\r\nconnection: Upgrade\r\n"
        "sec-websocket-version: 13\r\nsec-websocket-key: AAAA\r\n"
        "cookie: session=abc\r\nauthorization: Bearer t\r\norigin: https://app.example.com\r\n"
    )
    kept = replayable_headers(parse_header_block(raw))
    assert set(kept) == {"cookie", "authorization", "origin"}
    assert kept["cookie"] == "session=abc"


def test_header_block_parsing_tolerates_the_other_shapes_burpwn_has_used():
    """A silently-empty header dict is a false negative that reads exactly like enforcement."""
    assert parse_header_block({"Cookie": "a=1"}) == {"Cookie": "a=1"}
    assert parse_header_block([{"name": "Cookie", "value": "a=1"}]) == {"Cookie": "a=1"}
    assert parse_header_block(None) == {}


@pytest.mark.parametrize(
    ("flow", "expected"),
    [
        (
            {"scheme": "http", "dst_port": 8777, "request": {"authority": "h.tld", "path": "/chat"}},
            "ws://h.tld:8777/chat",
        ),
        (
            {"scheme": "https", "dst_port": 443, "request": {"authority": "h.tld", "path": "/live"}},
            "wss://h.tld/live",
        ),
        ({"scheme": "http", "dst_port": 80, "request": {"authority": "h.tld", "path": "/"}}, "ws://h.tld/"),
        ({"scheme": "https", "request": {"authority": "h.tld:9443", "path": "/s"}}, "wss://h.tld:9443/s"),
    ],
)
def test_a_captured_upgrade_flow_rebuilds_its_ws_url(flow, expected):
    """burpwn records an upgraded flow as http/https with the port only in dst_port, so the ws URL
    has to be reassembled rather than read off — getting the port wrong replays against :80."""
    assert flow_ws_url(flow) == expected


def test_a_flow_with_no_host_yields_no_url():
    assert flow_ws_url({"scheme": "http"}) is None
    assert flow_ws_url("nonsense") is None


# --------------------------------------------------------------------------- the tools


def _engagement(identities=None) -> EngagementSpec:
    return EngagementSpec(
        name="t",
        targets=["https://app.example.com/"],
        in_scope=["app.example.com"],
        identities=list(identities or []),
        session="t",
    )


def _specs(client, engagement=None, throttle=None, identities=None) -> dict:
    return {
        s.name: s
        for s in build_ws_tool_specs(
            client,
            guard=ScopeGuard.from_engagement(engagement),
            throttle=throttle,
            identities=identities,
        )
    }


def test_both_tools_are_marked_active_so_the_authorisation_gate_can_block_them():
    """These originate real traffic; a passive engagement must be able to hard-refuse them the way
    it refuses burpwn_exec and burpwn_fuzz."""
    specs = _specs(_WSFakeClient())
    assert set(specs) == {"ws_connect", "ws_replay"}
    assert all(s.active for s in specs.values())


async def test_ws_connect_refuses_an_out_of_scope_url_with_the_shared_envelope(ws_dir):
    """The refusal must be byte-identical to every other tool's: containment that varies per tool is
    containment the operator cannot reason about."""
    client = _WSFakeClient(_transcript())
    specs = _specs(client, _engagement())
    result = await specs["ws_connect"].fn(url="ws://attacker.tld/x", messages=["x"])
    guard = ScopeGuard.from_engagement(_engagement())
    assert result == guard.refusal(["attacker.tld"], "ws_connect url")
    assert client.execs == [], "nothing may run when the destination is refused"


async def test_ws_connect_refuses_a_path_carved_out_of_scope(ws_dir):
    """An `exclude` carve-out is path-level; the host alone cannot express it."""
    engagement = _engagement()
    engagement.exclude = ["app.example.com/admin"]
    client = _WSFakeClient(_transcript())
    specs = _specs(client, engagement)
    result = await specs["ws_connect"].fn(url="ws://app.example.com/admin/socket", messages=["x"])
    assert result["refused"] is True
    assert client.execs == []


async def test_a_tripped_circuit_breaker_refuses_before_sending_a_frame(ws_dir):
    """A blocked run that keeps probing produces a misleading clean report — the breaker exists to
    stop that, and a tool that ignores it reopens the hole."""
    throttle = Throttle(block_threshold=1)
    throttle.tripped = True
    throttle.trip_reason = "blocked"
    client = _WSFakeClient(_transcript())
    specs = _specs(client, _engagement(), throttle=throttle)
    result = await specs["ws_connect"].fn(url="ws://app.example.com/chat", messages=["x"])
    assert result["error"] == "target-blocking"
    assert client.execs == []


async def test_ws_connect_sends_the_messages_and_returns_the_capture_ids(ws_dir):
    client = _WSFakeClient(_transcript(), flow_ids=[42])
    specs = _specs(client, _engagement())
    result = await specs["ws_connect"].fn(
        url="ws://app.example.com/chat",
        headers=[{"name": "Origin", "value": "https://attacker.tld"}],
        messages=["a", "b"],
        wait_secs=2,
    )
    assert result["captured_request_ids"] == [42]
    argv = client.execs[0]["argv"]
    assert argv.count("--message") == 2
    assert "Origin: https://attacker.tld" in argv
    assert client.execs[0]["workspace"] == "websocket"


async def test_ws_replay_reuses_the_captured_credentials_and_regenerates_the_handshake(ws_dir):
    """The point of the tool: re-open an AUTHENTICATED channel with tampered content. Losing the
    cookie makes it an anonymous probe; replaying the stale key breaks the upgrade."""
    client = _WSFakeClient(_transcript(), flow_ids=[9])
    client.flows[5] = {
        "id": 5,
        "protocol": "ws",
        "scheme": "http",
        "dst_port": 8777,
        "request": {
            "authority": "app.example.com",
            "path": "/chat",
            "headers": (
                "host: app.example.com:8777\r\nupgrade: websocket\r\nsec-websocket-key: OLD\r\n"
                "cookie: session=victim\r\norigin: https://app.example.com\r\n"
            ),
        },
    }
    specs = _specs(client, _engagement())
    result = await specs["ws_replay"].fn(flow_id=5, message='{"action":"admin"}')
    argv = client.execs[0]["argv"]
    assert "cookie: session=victim" in argv
    assert not any("OLD" in a for a in argv), "the per-connection key must never be replayed"
    assert argv[argv.index("--url") + 1] == "ws://app.example.com:8777/chat"
    assert result["replayed_from_flow"] == 5
    assert result["captured_request_ids"] == [9]


async def test_ws_replay_lets_an_explicit_header_override_the_captured_one(ws_dir):
    """The CSWSH test is exactly "same cookie, foreign Origin"; the override has to win."""
    client = _WSFakeClient(_transcript())
    client.flows[5] = {
        "id": 5,
        "scheme": "http",
        "dst_port": 80,
        "request": {
            "authority": "app.example.com",
            "path": "/chat",
            "headers": "cookie: session=victim\r\norigin: https://app.example.com\r\n",
        },
    }
    specs = _specs(client, _engagement())
    await specs["ws_replay"].fn(
        flow_id=5,
        message="x",
        extra_headers=[{"name": "origin", "value": "https://attacker.tld"}],
    )
    argv = client.execs[0]["argv"]
    assert "origin: https://attacker.tld" in argv
    assert "origin: https://app.example.com" not in argv


async def test_ws_replay_refuses_a_captured_flow_that_is_out_of_scope(ws_dir):
    """Captured traffic includes third-party sockets (analytics, chat widgets). Replaying one
    because it happens to be in the history would send real traffic off-scope."""
    client = _WSFakeClient(_transcript())
    client.flows[5] = {
        "id": 5,
        "scheme": "https",
        "dst_port": 443,
        "request": {"authority": "widget.thirdparty.tld", "path": "/ws", "headers": ""},
    }
    specs = _specs(client, _engagement())
    result = await specs["ws_replay"].fn(flow_id=5, message="x")
    assert result["off_scope_hosts"] == ["widget.thirdparty.tld"]
    assert client.execs == []


async def test_ws_replay_on_a_non_websocket_flow_explains_itself(ws_dir):
    client = _WSFakeClient(_transcript())
    client.flows[5] = {"id": 5}
    specs = _specs(client, _engagement())
    result = await specs["ws_replay"].fn(flow_id=5, message="x")
    assert result["error"] == "not-a-websocket-flow"
    assert client.execs == []


async def test_as_identity_without_declared_identities_is_refused(ws_dir):
    """Same envelope the other tools return, so the model gets one consistent story."""
    specs = _specs(_WSFakeClient(_transcript()), _engagement())
    result = await specs["ws_connect"].fn(
        url="ws://app.example.com/chat", messages=["x"], as_identity="victim"
    )
    assert result["error"] == "no-identities"


async def test_an_identity_attaches_its_credentials_to_the_handshake(ws_dir):
    """Authorization at the handshake is the whole WebSocket access-control question; without this
    the two_identity oracle can never be reached over a socket."""
    spec = IdentitySpec(name="victim", headers={"Cookie": "session=victim"})
    identities = IdentityStore(_WSFakeClient(), [spec])
    client = _WSFakeClient(_transcript())
    specs = _specs(client, _engagement([spec]), identities=identities)
    await specs["ws_connect"].fn(
        url="ws://app.example.com/chat", messages=["x"], as_identity="victim"
    )
    assert "Cookie: session=victim" in client.execs[0]["argv"]


def test_the_langchain_adapter_exposes_both_tools_with_their_descriptions():
    """Same thin-adapter shape as tools.burpwn_tools, so one definition serves both executor paths."""
    tools = websocket_tools(_WSFakeClient(), _engagement())
    assert [t.name for t in tools] == ["ws_connect", "ws_replay"]
    assert all(len(t.description) > 200 for t in tools)
