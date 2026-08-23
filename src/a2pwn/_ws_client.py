"""Stdlib-only RFC 6455 WebSocket client, runnable as ``python -m a2pwn._ws_client``.

Hosted inside the burpwn sandbox via ``burpwn exec`` (same pattern as :mod:`a2pwn._oob_listener`) so
the upgrade handshake and every frame ride through the MITM and land as a ``ws`` flow in the session.
That is the whole point: a2pwn could already *see* WebSocket traffic the browser made, but had no way
to *originate* a frame, which made the ``websocket`` vulnerability class untestable — CSWSH, IDOR on
a subscription topic and message-level injection all require sending a message we chose.

No third-party dependency (no ``websockets``, no ``websocat``): the sandbox's tool inventory is not
guaranteed, and adding a runtime dep for one class is a worse trade than 300 lines of framing. The
handshake, masking, the three payload-length forms, fragmentation and the close handshake are all
implemented here and unit-tested directly, because framing is where the bugs hide.

``burpwn exec`` returns only ``{exit_code, captured_request_ids, exec_id}`` — **no stdout**. So the
result is written as JSON to ``--out``, a path on the shared filesystem the host driver
(:mod:`a2pwn.websocket`) then reads back.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

# RFC 6455 §1.3 — the magic GUID concatenated with the client key to derive Sec-WebSocket-Accept.
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

OPCODE_NAMES = {
    OP_CONT: "cont",
    OP_TEXT: "text",
    OP_BINARY: "binary",
    OP_CLOSE: "close",
    OP_PING: "ping",
    OP_PONG: "pong",
}

# A hostile or buggy peer can announce a 64-bit length; refuse to allocate for it rather than let one
# frame OOM the sandbox. 64 MiB matches the ceiling burpwn's own stdio transport is sized for.
MAX_FRAME_BYTES = 64 * 1024 * 1024
# Per-frame cap on what goes into the JSON transcript. The transcript is read back by a model, so a
# multi-megabyte data frame must be truncated rather than blown into the context window.
DEFAULT_MAX_RECORD_BYTES = 64 * 1024
DEFAULT_CONNECT_TIMEOUT = 15.0
DEFAULT_WAIT_SECS = 5.0


class WSError(RuntimeError):
    """Handshake or protocol failure. Carried into the transcript rather than raised to the caller.

    ``transcript`` is set when the failure happened *after* the response was parsed (a refused
    upgrade), so the status and headers that explain the refusal survive instead of collapsing into
    a bare error string — "the server answered 403 to a cookie-less handshake" is an observation the
    agent needs, not noise.
    """

    def __init__(self, message: str, transcript: Transcript | None = None) -> None:
        super().__init__(message)
        self.transcript = transcript


# --------------------------------------------------------------------------- framing


@dataclass
class Frame:
    """One decoded WebSocket frame, exactly as it appeared on the wire."""

    fin: bool
    opcode: int
    payload: bytes
    masked: bool = False

    @property
    def name(self) -> str:
        return OPCODE_NAMES.get(self.opcode, f"opcode-{self.opcode}")


def mask_payload(payload: bytes, key: bytes) -> bytes:
    """XOR ``payload`` with the 4-byte ``key``. Involutive, so it both masks and unmasks."""
    if not key:
        return payload
    return bytes(b ^ key[i % 4] for i, b in enumerate(payload))


def build_frame(
    opcode: int,
    payload: bytes = b"",
    *,
    fin: bool = True,
    mask: bool = True,
    mask_key: bytes | None = None,
) -> bytes:
    """Serialise one frame.

    ``mask=True`` by default because RFC 6455 §5.3 *requires* every client-to-server frame to be
    masked with a fresh key, and a conforming server closes the connection on an unmasked one — this
    is the single most common reason a hand-rolled client silently gets a 1002 instead of a reply.
    """
    if mask and mask_key is None:
        mask_key = os.urandom(4)
    if not mask:
        mask_key = None

    head = bytearray()
    head.append((0x80 if fin else 0x00) | (opcode & 0x0F))
    length = len(payload)
    mask_bit = 0x80 if mask_key else 0x00
    # The three length forms of §5.2: 7-bit inline, 7+16-bit, 7+64-bit. A conforming client must use
    # the SHORTEST form that fits, so a server validating minimal encoding does not reject us.
    if length < 126:
        head.append(mask_bit | length)
    elif length <= 0xFFFF:
        head.append(mask_bit | 126)
        head += struct.pack("!H", length)
    else:
        head.append(mask_bit | 127)
        head += struct.pack("!Q", length)
    if mask_key:
        head += mask_key
        return bytes(head) + mask_payload(payload, mask_key)
    return bytes(head) + payload


def parse_frame(buf: bytes) -> tuple[Frame, int] | None:
    """Decode the first frame in ``buf``.

    Returns ``(frame, bytes_consumed)``, or ``None`` when ``buf`` does not yet hold a whole frame —
    the caller keeps reading. Never raises on a short buffer; a partial read is the normal case on a
    stream socket, not an error.
    """
    if len(buf) < 2:
        return None
    b0, b1 = buf[0], buf[1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    idx = 2
    if length == 126:
        if len(buf) < idx + 2:
            return None
        length = struct.unpack("!H", buf[idx : idx + 2])[0]
        idx += 2
    elif length == 127:
        if len(buf) < idx + 8:
            return None
        length = struct.unpack("!Q", buf[idx : idx + 8])[0]
        idx += 8
    if length > MAX_FRAME_BYTES:
        raise WSError(f"frame announces {length} bytes, over the {MAX_FRAME_BYTES}-byte cap")
    key = b""
    if masked:
        if len(buf) < idx + 4:
            return None
        key = buf[idx : idx + 4]
        idx += 4
    if len(buf) < idx + length:
        return None
    payload = buf[idx : idx + length]
    if masked:
        payload = mask_payload(payload, key)
    return Frame(fin=fin, opcode=opcode, payload=payload, masked=masked), idx + length


class FrameReader:
    """Incremental frame decoder over a byte stream.

    Separate from the socket so the framing can be exercised in tests without one, and so a frame
    split across TCP segments (routine, and the classic source of "works locally, fails on a real
    target") is handled by buffering rather than by hoping each ``recv`` is frame-aligned.
    """

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[Frame]:
        """Append ``data`` and return every complete frame it made available."""
        self._buf += data
        out: list[Frame] = []
        while True:
            parsed = parse_frame(bytes(self._buf))
            if parsed is None:
                return out
            frame, consumed = parsed
            del self._buf[:consumed]
            out.append(frame)

    @property
    def pending(self) -> int:
        """Bytes buffered but not yet a complete frame (non-zero at close = a truncated frame)."""
        return len(self._buf)


def fragment(payload: bytes, opcode: int, size: int) -> list[tuple[int, bytes, bool]]:
    """Split ``payload`` into ``(opcode, chunk, fin)`` triples per RFC 6455 §5.4.

    Only the first fragment carries the data opcode; the rest are continuation frames and only the
    last sets FIN. Beyond conformance this is an attack primitive: a message inspector that reads one
    frame at a time never sees the reassembled payload, so splitting a payload mid-token is a real
    WAF/filter bypass worth being able to send deliberately.
    """
    if size <= 0 or len(payload) <= size:
        return [(opcode, payload, True)]
    chunks = [payload[i : i + size] for i in range(0, len(payload), size)]
    out: list[tuple[int, bytes, bool]] = [(opcode, chunks[0], False)]
    out += [(OP_CONT, c, False) for c in chunks[1:-1]]
    out.append((OP_CONT, chunks[-1], True))
    return out


# --------------------------------------------------------------------------- handshake


def accept_token(key: str) -> str:
    """The ``Sec-WebSocket-Accept`` value a conforming server must return for ``key`` (§4.2.2)."""
    digest = hashlib.sha1((key + WS_GUID).encode("ascii")).digest()  # noqa: S324 - protocol-mandated
    return base64.b64encode(digest).decode("ascii")


def new_key() -> str:
    """A fresh 16-byte base64 ``Sec-WebSocket-Key`` (§4.1: must be random per connection)."""
    return base64.b64encode(os.urandom(16)).decode("ascii")


@dataclass
class Target:
    """Where a ``ws://``/``wss://`` URL actually points."""

    host: str
    port: int
    resource: str
    secure: bool


def parse_ws_url(url: str) -> Target:
    """Split a WebSocket URL into connection target + request-URI.

    ``http(s)://`` is accepted as an alias for ``ws(s)://`` because that is how the scheme shows up
    in a captured handshake flow and in JS bundles, and refusing it would only make the model guess.
    """
    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    secure = scheme in ("wss", "https")
    if scheme not in ("ws", "wss", "http", "https"):
        raise WSError(f"unsupported scheme {scheme!r}: expected ws/wss (http/https accepted)")
    if not parsed.hostname:
        raise WSError(f"no host in {url!r}")
    port = parsed.port or (443 if secure else 80)
    resource = parsed.path or "/"
    if parsed.query:
        resource += "?" + parsed.query
    return Target(host=parsed.hostname, port=port, resource=resource, secure=secure)


def build_handshake(target: Target, key: str, headers: dict[str, str] | None = None) -> bytes:
    """Serialise the HTTP/1.1 Upgrade request.

    Caller-supplied headers override the defaults (Host, Origin and Cookie all legitimately need
    overriding — an origin swap *is* the CSWSH test) but never the Key/Version, which would break
    the handshake we are about to validate.
    """
    default_host = target.host if target.port in (80, 443) else f"{target.host}:{target.port}"
    lines = {
        "Host": default_host,
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Version": "13",
    }
    for name, value in (headers or {}).items():
        if name.lower() in ("sec-websocket-key", "sec-websocket-version"):
            continue
        lines[name] = value
    lines["Sec-WebSocket-Key"] = key
    req = [f"GET {target.resource} HTTP/1.1"]
    req += [f"{k}: {v}" for k, v in lines.items()]
    return ("\r\n".join(req) + "\r\n\r\n").encode("utf-8")


def parse_handshake_response(raw: bytes) -> tuple[int, dict[str, str]]:
    """Parse the status line + headers of the upgrade response (header names lowercased)."""
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    lines = head.split("\r\n")
    status = 0
    parts = lines[0].split(" ", 2) if lines else []
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return status, headers


# --------------------------------------------------------------------------- connection


@dataclass
class Record:
    """One transcript entry. ``data`` is text; binary payloads go to ``data_b64`` instead."""

    direction: str
    opcode: str
    fin: bool
    size: int
    t: float
    data: str | None = None
    data_b64: str | None = None
    truncated: bool = False
    code: int | None = None
    reason: str | None = None

    def as_dict(self) -> dict:
        out = {
            "dir": self.direction,
            "opcode": self.opcode,
            "fin": self.fin,
            "size": self.size,
            "t": round(self.t, 4),
        }
        if self.code is not None:
            out["code"] = self.code
        if self.reason:
            out["reason"] = self.reason
        if self.data is not None:
            out["data"] = self.data
        if self.data_b64 is not None:
            out["data_b64"] = self.data_b64
        if self.truncated:
            out["truncated"] = True
        return out


@dataclass
class Transcript:
    """Everything one session produced — the artifact the host driver reads back."""

    url: str
    handshake: dict = field(default_factory=dict)
    frames: list[Record] = field(default_factory=list)
    messages: list[dict] = field(default_factory=list)
    error: str | None = None
    closed: dict | None = None

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "handshake": self.handshake,
            "frames": [f.as_dict() for f in self.frames],
            "messages": self.messages,
            "closed": self.closed,
            "error": self.error,
        }


def _record(
    direction: str, opcode: int, payload: bytes, fin: bool, started: float, max_bytes: int
) -> Record:
    """Build a transcript entry, decoding text as UTF-8 and base64-ing anything that is not."""
    shown = payload[:max_bytes] if max_bytes > 0 else payload
    rec = Record(
        direction=direction,
        opcode=OPCODE_NAMES.get(opcode, f"opcode-{opcode}"),
        fin=fin,
        size=len(payload),
        t=time.monotonic() - started,
        truncated=len(shown) < len(payload),
    )
    if opcode == OP_CLOSE:
        # A close payload is a big-endian u16 status + UTF-8 reason, not text: base64-ing it would
        # hide the very thing that matters (1008 policy-violation vs 1000 normal tells you whether
        # the server rejected the message or just hung up).
        rec.code, rec.reason = _close_payload(payload)
        return rec
    if opcode in (OP_TEXT, OP_CONT) or _is_text(shown):
        try:
            rec.data = shown.decode("utf-8")
            return rec
        except UnicodeDecodeError:
            pass  # a "text" frame that is not valid UTF-8 is itself worth seeing verbatim
    rec.data_b64 = base64.b64encode(shown).decode("ascii")
    return rec


def _is_text(payload: bytes) -> bool:
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


class WSConnection:
    """A connected, handshaken WebSocket. Built by :func:`connect`; never constructed directly."""

    def __init__(self, sock: socket.socket, target: Target, transcript: Transcript, started: float,
                 max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES) -> None:
        self._sock = sock
        self._target = target
        self._reader = FrameReader()
        self._pending: list[bytes] = []  # fragments of the message currently being reassembled
        self._pending_opcode: int | None = None
        self.transcript = transcript
        self._started = started
        self._max_record = max_record_bytes
        self._close_sent = False
        self.closed = False

    # ---- sending ---------------------------------------------------------------------

    def send(self, payload: bytes, opcode: int = OP_TEXT, fragment_size: int = 0) -> None:
        """Send one application message, fragmented into ``fragment_size`` chunks when asked."""
        for op, chunk, fin in fragment(payload, opcode, fragment_size):
            self._sock.sendall(build_frame(op, chunk, fin=fin, mask=True))
            self.transcript.frames.append(
                _record("sent", op, chunk, fin, self._started, self._max_record)
            )

    def send_control(self, opcode: int, payload: bytes = b"") -> None:
        """Send a control frame (ping/pong/close). Control frames are never fragmented (§5.5)."""
        self._sock.sendall(build_frame(opcode, payload, fin=True, mask=True))
        if opcode == OP_CLOSE:
            self._close_sent = True
        self.transcript.frames.append(
            _record("sent", opcode, payload, True, self._started, self._max_record)
        )

    # ---- receiving -------------------------------------------------------------------

    def pump(self, deadline: float) -> None:
        """Read frames until ``deadline`` (monotonic) or the peer closes.

        Answers pings with pongs so a keepalive-driven server does not drop us mid-test, and returns
        early on a close frame — waiting out the full timeout after the peer has hung up only makes
        every negative result slower.
        """
        while not self.closed:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            self._sock.settimeout(min(remaining, 1.0))
            try:
                data = self._sock.recv(65536)
            except TimeoutError:
                continue
            except OSError as exc:
                self.transcript.error = self.transcript.error or f"read failed: {exc}"
                self.closed = True
                return
            if not data:
                self.closed = True  # peer closed the TCP connection without a close frame
                return
            for frame in self._reader.feed(data):
                self._on_frame(frame)
                if self.closed:
                    return

    def _on_frame(self, frame: Frame) -> None:
        self.transcript.frames.append(
            _record("recv", frame.opcode, frame.payload, frame.fin, self._started, self._max_record)
        )
        if frame.opcode == OP_PING:
            self.send_control(OP_PONG, frame.payload)
            return
        if frame.opcode == OP_PONG:
            return
        if frame.opcode == OP_CLOSE:
            code, reason = _close_payload(frame.payload)
            # Only the peer that opens the closing handshake echoes; §5.5.1 says the side that
            # *initiated* must NOT answer the mirror, or the exchange never terminates.
            if not self._close_sent:
                self.transcript.closed = {"code": code, "reason": reason, "initiator": "server"}
                try:
                    self.send_control(OP_CLOSE, frame.payload[:2])
                except OSError:
                    pass
            else:
                self.transcript.closed = {**(self.transcript.closed or {}), "peer_code": code}
            self.closed = True
            return
        # data frame: accumulate until FIN so the transcript also carries whole messages
        if frame.opcode in (OP_TEXT, OP_BINARY):
            self._pending_opcode = frame.opcode
            self._pending = [frame.payload]
        elif frame.opcode == OP_CONT:
            self._pending.append(frame.payload)
        if frame.fin and self._pending_opcode is not None:
            self._finish_message()

    def _finish_message(self) -> None:
        payload = b"".join(self._pending)
        rec = _record("recv", self._pending_opcode or OP_TEXT, payload, True, self._started, self._max_record)
        entry = rec.as_dict()
        entry.pop("dir", None)
        entry.pop("fin", None)
        self.transcript.messages.append(entry)
        self._pending = []
        self._pending_opcode = None

    # ---- teardown --------------------------------------------------------------------

    def close(self, code: int = 1000, reason: str = "") -> None:
        """Send a close frame and wait briefly for the peer's mirror, then drop the socket."""
        if not self.closed:
            try:
                self.send_control(OP_CLOSE, struct.pack("!H", code) + reason.encode("utf-8"))
                self.transcript.closed = self.transcript.closed or {
                    "code": code,
                    "reason": reason,
                    "initiator": "client",
                }
                self.pump(time.monotonic() + 2.0)
            except OSError:
                pass
        try:
            self._sock.close()
        except OSError:
            pass
        self.closed = True


def _close_payload(payload: bytes) -> tuple[int | None, str]:
    """Decode a close frame's optional status code + reason (§5.5.1)."""
    if len(payload) < 2:
        return None, ""
    code = struct.unpack("!H", payload[:2])[0]
    return code, payload[2:].decode("utf-8", "replace")


def connect(
    url: str,
    headers: dict[str, str] | None = None,
    *,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
    insecure: bool = False,
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
) -> WSConnection:
    """Open a TCP/TLS connection and complete the RFC 6455 upgrade handshake.

    The ``Sec-WebSocket-Accept`` value is verified against the key we sent. A mismatch does not abort
    — it is recorded — because a server that answers 101 with a wrong accept is itself a finding-shaped
    observation, and aborting would hide it.
    """
    target = parse_ws_url(url)
    transcript = Transcript(url=url)
    started = time.monotonic()
    sock = socket.create_connection((target.host, target.port), timeout=timeout)
    if target.secure:
        # burpwn exports its MITM CA through SSL_CERT_FILE, which create_default_context() honours,
        # so verification normally SUCCEEDS through the sandbox. --insecure exists for targets whose
        # own chain is genuinely broken, which is common enough on an engagement to need an opt-out.
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=target.host)

    key = new_key()
    request = build_handshake(target, key, headers)
    sock.sendall(request)

    raw = bytearray()
    sock.settimeout(timeout)
    while b"\r\n\r\n" not in raw:
        chunk = sock.recv(4096)
        if not chunk:
            sock.close()
            raise WSError("connection closed during handshake")
        raw += chunk
        if len(raw) > 256 * 1024:
            sock.close()
            raise WSError("handshake response headers exceeded 256 KiB")

    head, _, rest = bytes(raw).partition(b"\r\n\r\n")
    status, resp_headers = parse_handshake_response(head)
    expected = accept_token(key)
    transcript.handshake = {
        "status": status,
        "request": request.decode("latin-1"),
        "response_headers": resp_headers,
        "sec_websocket_key": key,
        "accept_expected": expected,
        "accept_ok": resp_headers.get("sec-websocket-accept") == expected,
        "subprotocol": resp_headers.get("sec-websocket-protocol"),
    }
    if status != 101:
        sock.close()
        raise WSError(f"handshake refused: HTTP {status}", transcript)

    conn = WSConnection(sock, target, transcript, started, max_record_bytes)
    if rest:  # a server may pipeline its first frame into the same segment as the 101
        for frame in conn._reader.feed(rest):
            conn._on_frame(frame)
    return conn


def run_session(
    url: str,
    headers: dict[str, str] | None = None,
    messages: list[str] | None = None,
    *,
    wait_secs: float = DEFAULT_WAIT_SECS,
    binary: bool = False,
    fragment_size: int = 0,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
    insecure: bool = False,
    max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
) -> dict:
    """Connect, send every message, collect replies for ``wait_secs``, close, return the transcript.

    Never raises: a refused handshake or a dropped connection is a *result* the driver must be able
    to show the model, not an exception that loses the frames already exchanged.
    """
    try:
        conn = connect(
            url, headers, timeout=timeout, insecure=insecure, max_record_bytes=max_record_bytes
        )
    except (WSError, OSError, ssl.SSLError) as exc:
        failed = getattr(exc, "transcript", None) or Transcript(url=url)
        failed.error = f"{type(exc).__name__}: {exc}"
        return failed.as_dict()

    try:
        opcode = OP_BINARY if binary else OP_TEXT
        for msg in messages or []:
            conn.send(msg.encode("utf-8"), opcode=opcode, fragment_size=fragment_size)
        conn.pump(time.monotonic() + wait_secs)
    except OSError as exc:
        conn.transcript.error = conn.transcript.error or f"{type(exc).__name__}: {exc}"
    finally:
        conn.close()
    return conn.transcript.as_dict()


# --------------------------------------------------------------------------- CLI


def _parse_header(raw: str) -> tuple[str, str]:
    name, _, value = raw.partition(":")
    return name.strip(), value.strip()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="a2pwn._ws_client")
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", required=True, help="JSON transcript path (exec has no stdout)")
    parser.add_argument("--header", action="append", default=[], help='"Name: value", repeatable')
    parser.add_argument("--message", action="append", default=[], help="text frame to send, repeatable")
    parser.add_argument("--wait-secs", type=float, default=DEFAULT_WAIT_SECS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_CONNECT_TIMEOUT)
    parser.add_argument("--binary", action="store_true")
    parser.add_argument("--fragment-size", type=int, default=0)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--max-record-bytes", type=int, default=DEFAULT_MAX_RECORD_BYTES)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    headers = dict(_parse_header(h) for h in args.header if ":" in h)
    result = run_session(
        args.url,
        headers,
        list(args.message),
        wait_secs=args.wait_secs,
        binary=args.binary,
        fragment_size=args.fragment_size,
        timeout=args.timeout,
        insecure=args.insecure,
        max_record_bytes=args.max_record_bytes,
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result), encoding="utf-8")
    # Echoed for the human reading `burpwn exec` output; the driver reads --out, not this.
    sys.stdout.write(f"[ws] {args.url} frames={len(result['frames'])} error={result['error']}\n")
    sys.stdout.flush()
    return 1 if result["error"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
