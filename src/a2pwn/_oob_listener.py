"""Stdlib-only OOB sink: DNS + HTTP + raw-TCP listeners runnable as ``python -m a2pwn._oob_listener``.

Hosted inside the burpwn sandbox via ``burpwn exec`` so a target's out-of-band callback (blind SSRF /
XXE / deserialization / SQLi exfil) lands as a ``dns`` / ``rawtcp`` / ``h1`` flow in the same session and
becomes searchable through ``req_search``. Each incoming callback is also echoed to stdout so the
correlation id (carried in the queried name / request path) is visible in the captured child output.

No third-party dependencies: only the standard library. Binds ``0.0.0.0`` on the chosen ports; a bind
failure for one protocol (e.g. privileged port) is logged and skipped rather than aborting the sink.
"""

from __future__ import annotations

import argparse
import signal
import socket
import socketserver
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_DNS_PORT = 53
DEFAULT_HTTP_PORT = 80
DEFAULT_TCP_PORT = 8000


def _log(kind: str, message: str) -> None:
    """Emit a single flushed line so the correlation id shows up in the captured exec output."""
    sys.stdout.write(f"[oob][{kind}] {message}\n")
    sys.stdout.flush()


# --------------------------------------------------------------------------- DNS


def parse_qname(data: bytes) -> tuple[str, int]:
    """Parse the QNAME of a DNS query. Returns ``(name, offset_after_qname)``."""
    idx = 12  # skip the 12-byte header
    labels: list[str] = []
    while idx < len(data):
        length = data[idx]
        if length == 0:
            idx += 1
            break
        labels.append(data[idx + 1 : idx + 1 + length].decode("ascii", "replace"))
        idx += length + 1
    return ".".join(labels), idx


def build_dns_response(query: bytes, ip: str = "127.0.0.1") -> bytes:
    """Build a minimal DNS answer echoing the question with a single A record."""
    _, qend = parse_qname(query)
    question = query[12:qend]  # labels + terminating zero
    qtype_qclass = query[qend : qend + 4]
    header = bytearray(12)
    header[0:2] = query[0:2]  # transaction id
    header[2:4] = b"\x81\x80"  # standard query response, no error
    header[4:6] = b"\x00\x01"  # QDCOUNT
    header[6:8] = b"\x00\x01"  # ANCOUNT
    # NSCOUNT / ARCOUNT stay zero
    answer = (
        b"\xc0\x0c"  # name pointer to the question
        + b"\x00\x01"  # type A
        + b"\x00\x01"  # class IN
        + b"\x00\x00\x00\x3c"  # TTL 60s
        + b"\x00\x04"  # RDLENGTH
        + bytes(int(o) for o in ip.split("."))
    )
    return bytes(header) + question + qtype_qclass + answer


def _serve_dns(port: int, stop: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError as exc:
        _log("dns", f"WARN bind :{port} failed ({exc}); dns disabled")
        sock.close()
        return
    sock.settimeout(0.5)
    _log("dns", f"listening on 0.0.0.0:{port}")
    while not stop.is_set():
        try:
            data, addr = sock.recvfrom(4096)
        except TimeoutError:
            continue
        except OSError:
            break
        try:
            name, _ = parse_qname(data)
        except (IndexError, ValueError):
            name = "<malformed>"
        _log("dns", f"{name} from {addr[0]}")
        try:
            sock.sendto(build_dns_response(data), addr)
        except OSError:
            pass
    sock.close()


# --------------------------------------------------------------------------- HTTP


class _HTTPSink(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _handle(self) -> None:
        host = self.headers.get("Host", "")
        _log("http", f"{self.command} {self.path} Host:{host} from {self.client_address[0]}")
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    do_GET = _handle
    do_POST = _handle
    do_HEAD = _handle
    do_PUT = _handle

    def log_message(self, *args: object) -> None:  # silence default stderr logging
        return


def _make_http(port: int) -> ThreadingHTTPServer | None:
    try:
        srv = ThreadingHTTPServer(("0.0.0.0", port), _HTTPSink)
    except OSError as exc:
        _log("http", f"WARN bind :{port} failed ({exc}); http disabled")
        return None
    _log("http", f"listening on 0.0.0.0:{port}")
    return srv


# --------------------------------------------------------------------------- raw TCP


class _TCPSink(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            data = self.request.recv(4096)
        except OSError:
            data = b""
        _log("tcp", f"{len(data)} bytes from {self.client_address[0]}: {data[:120]!r}")
        try:
            self.request.sendall(b"220 oob-sink\r\n")
        except OSError:
            pass


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _make_tcp(port: int) -> _ThreadingTCPServer | None:
    try:
        srv = _ThreadingTCPServer(("0.0.0.0", port), _TCPSink)
    except OSError as exc:
        _log("tcp", f"WARN bind :{port} failed ({exc}); rawtcp disabled")
        return None
    _log("tcp", f"listening on 0.0.0.0:{port}")
    return srv


# --------------------------------------------------------------------------- runner


def run(
    protocols: set[str],
    dns_port: int = DEFAULT_DNS_PORT,
    http_port: int = DEFAULT_HTTP_PORT,
    tcp_port: int = DEFAULT_TCP_PORT,
    duration: float | None = None,
) -> None:
    """Start the requested sinks, block until ``duration`` elapses or a termination signal arrives."""
    stop = threading.Event()
    servers: list[socketserver.BaseServer] = []
    threads: list[threading.Thread] = []

    if "dns" in protocols:
        t = threading.Thread(target=_serve_dns, args=(dns_port, stop), daemon=True)
        t.start()
        threads.append(t)
    if "http" in protocols:
        srv = _make_http(http_port)
        if srv is not None:
            servers.append(srv)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
    if protocols & {"rawtcp", "smtp"}:
        srv = _make_tcp(tcp_port)
        if srv is not None:
            servers.append(srv)
            threading.Thread(target=srv.serve_forever, daemon=True).start()

    def _on_signal(*_: object) -> None:
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _on_signal)
        except (ValueError, OSError):
            pass  # not the main thread / unsupported platform

    deadline = None if duration is None else time.monotonic() + duration
    while not stop.is_set():
        if deadline is not None and time.monotonic() >= deadline:
            break
        time.sleep(0.25)

    stop.set()
    for srv in servers:
        srv.shutdown()
        srv.server_close()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="a2pwn._oob_listener")
    parser.add_argument("--protocols", default="dns,http,rawtcp")
    parser.add_argument("--dns-port", type=int, default=DEFAULT_DNS_PORT)
    parser.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT)
    parser.add_argument("--tcp-port", type=int, default=DEFAULT_TCP_PORT)
    parser.add_argument("--duration", type=float, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = _parse_args(argv)
    protocols = {p.strip() for p in args.protocols.split(",") if p.strip()}
    run(
        protocols,
        dns_port=args.dns_port,
        http_port=args.http_port,
        tcp_port=args.tcp_port,
        duration=args.duration,
    )


if __name__ == "__main__":
    main()
