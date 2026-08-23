"""Live capture preflight — does this burpwn actually capture what a run will send?

`burpwn doctor` answers "can the sandbox start": namespaces, nftables, bubblewrap. It does not
answer the question a pentest depends on, which is whether traffic that goes through the sandbox
comes back out as a captured flow. Those are different failures, and the second one is far more
dangerous because it is SILENT in exactly the wrong direction: every probe still runs, every oracle
legitimately fails to re-derive, every candidate is rejected for an empty flow batch, and the run
produces a clean report about a target nobody successfully tested.

This was not hypothetical. burpwn 0.4.0 panics on every downstream HTTP/1.1 connection
(`header_read_timeout` set on hyper's h1 builder with no timer installed), so cleartext-HTTP targets
capture ZERO flows while HTTPS/h2 works normally — which is why it can go unnoticed. A cheap probe
against a loopback listener catches it in seconds, before the authorization gate and before any
model spend.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

_log = logging.getLogger("a2pwn")

_PROBE_TIMEOUT = 25


class _Quiet(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's naming
        body = b"a2pwn-capture-probe"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # noqa: D102 - silence the stdlib access log
        return


def _local_address() -> str:
    """The address the sandbox can reach us on.

    Not 127.0.0.1: the sandbox has its own network namespace, so its loopback is not ours and a
    probe against it would fail for a reason that has nothing to do with capture.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))  # no packet is sent; this just resolves the outbound route
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


async def probe_cleartext_capture(client) -> dict:
    """Fetch a local HTTP/1.1 page through the sandbox and report whether it was captured.

    Returns ``{"ok", "detail"}``. Any failure to run the probe itself returns ``ok=None`` — unknown,
    not broken — because refusing to start a run over a probe that could not execute would be worse
    than the bug it looks for.
    """
    host = _local_address()
    server = HTTPServer((host, 0), _Quiet)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://{host}:{port}/"
        result = await asyncio.wait_for(
            client.exec(["curl", "-s", "-o", "/dev/null", "--max-time", "8", url], workspace=None),
            timeout=_PROBE_TIMEOUT,
        )
    except Exception as exc:  # noqa: BLE001 - an unrunnable probe is unknown, never a hard failure
        return {"ok": None, "detail": f"capture probe could not run: {exc}"}
    finally:
        server.shutdown()
        server.server_close()

    captured = list((result or {}).get("captured_request_ids") or [])
    if captured:
        return {"ok": True, "detail": f"cleartext HTTP captured ({len(captured)} flow(s))"}
    exit_code = (result or {}).get("exit_code")
    return {
        "ok": False,
        "detail": (
            f"cleartext HTTP/1.1 through the sandbox captured ZERO flows (curl exit {exit_code}). "
            "Every http:// target will produce empty flow batches, so every candidate finding will "
            "be rejected and the run will report a clean bill of health for a target it never "
            "actually tested. Known cause: burpwn's h1 server sets header_read_timeout without "
            "installing a hyper timer, which panics per connection. https:// targets are unaffected."
        ),
    }
