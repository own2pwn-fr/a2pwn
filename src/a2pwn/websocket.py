"""Host-side driver for the in-sandbox WebSocket client.

Launches :mod:`a2pwn._ws_client` through ``BurpwnClient.exec`` so every frame is MITM'd and lands as
a ``ws`` flow, reads the JSON transcript back off the shared filesystem, and returns it together with
the ``captured_request_ids`` burpwn attributed to that exec — so a frame exchange is *evidence*, not
a claim. Without the flow ids a WebSocket "finding" would rest on the agent's own narration, which is
exactly what :mod:`a2pwn.oracles` refuses to accept.

Two constraints from burpwn shape this module and are easy to get wrong:

* ``exec`` returns ``{exit_code, captured_request_ids, exec_id}`` and **no stdout**, so the result
  has to travel through a file rather than a pipe.
* the sandbox has its own ``/tmp`` (a fresh tmpfs) but shares ``$HOME`` and the cwd, so that file
  must live under the a2pwn data dir, not in ``tempfile.gettempdir()`` — a transcript written to
  ``/tmp`` inside the sandbox is simply not there when the host looks for it.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import uuid
from pathlib import Path
from typing import Any

_log = logging.getLogger("a2pwn.websocket")

#: Default workspace for frames we originate, so a WebSocket probe's flows group on their own.
DEFAULT_WORKSPACE = "websocket"
#: Margin (seconds) added to ``wait_secs`` for the sandbox exec bound: connect + TLS + close.
EXEC_TIMEOUT_MARGIN = 30
#: Handshake headers regenerated per connection; replaying them would produce a broken upgrade
#: (a stale Sec-WebSocket-Key makes the Accept check fail) or a duplicated hop-by-hop header.
_HANDSHAKE_HEADERS = frozenset(
    {
        "host",
        "upgrade",
        "connection",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-accept",
        "sec-websocket-extensions",
        "content-length",
        "transfer-encoding",
    }
)


def transcript_dir() -> Path:
    """Directory the transcript file is written to — must be writable from INSIDE the sandbox.

    The burpwn sandbox bind-mounts the **current working directory** read-write and everything else
    read-only, with its own ``/tmp`` tmpfs. Verified live on burpwn 0.4.0: a write to
    ``~/.local/share/a2pwn/ws`` fails with ``Read-only file system`` and a write to ``/tmp`` lands in
    a tmpfs the host cannot see, so neither the usual data-dir convention nor ``tempfile`` works
    here. ``A2PWN_WS_DIR`` overrides it for a deployment that mounts something else read-write.
    """
    base = Path(os.environ.get("A2PWN_WS_DIR") or (Path.cwd() / ".a2pwn-ws"))
    base.mkdir(parents=True, exist_ok=True)
    return base


def client_argv(
    url: str,
    out: Path,
    *,
    headers: dict[str, str] | None = None,
    messages: list[str] | None = None,
    wait_secs: float = 5.0,
    binary: bool = False,
    fragment_size: int = 0,
    insecure: bool = False,
) -> list[str]:
    """The argv handed to ``burpwn exec``.

    Uses ``sys.executable`` rather than a bare ``python``: the sandbox inherits the caller's PATH,
    and a2pwn is frequently launched by ``uvx`` or a wrapper whose venv is not on the PATH the child
    sees — a bare ``python -m a2pwn._ws_client`` then exits 1 with ModuleNotFoundError and writes no
    transcript at all (observed live). The interpreter running a2pwn can always import a2pwn.
    """
    argv = [sys.executable, "-m", "a2pwn._ws_client", "--url", url, "--out", str(out)]
    for name, value in (headers or {}).items():
        argv += ["--header", f"{name}: {value}"]
    for msg in messages or []:
        argv += ["--message", msg]
    argv += ["--wait-secs", str(wait_secs)]
    if binary:
        argv.append("--binary")
    if fragment_size > 0:
        argv += ["--fragment-size", str(fragment_size)]
    if insecure:
        argv.append("--insecure")
    return argv


async def run_ws_client(
    client: Any,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    messages: list[str] | None = None,
    wait_secs: float = 5.0,
    binary: bool = False,
    fragment_size: int = 0,
    insecure: bool = False,
    workspace: str | None = DEFAULT_WORKSPACE,
) -> dict:
    """Run one WebSocket session inside the sandbox and return transcript + capture evidence.

    Never raises for a protocol-level failure: a refused handshake, a 502 from the proxy or a dropped
    connection all come back as ``error`` in the transcript, because the model has to be able to tell
    "the server rejected my Origin" (a result) apart from "the tool broke" (not a result).
    """
    out = transcript_dir() / f"ws-{uuid.uuid4().hex[:12]}.json"
    argv = client_argv(
        url,
        out,
        headers=headers,
        messages=messages,
        wait_secs=wait_secs,
        binary=binary,
        fragment_size=fragment_size,
        insecure=insecure,
    )
    exec_result: dict = {}
    try:
        exec_result = await client.exec(
            argv, workspace=workspace, timeout_secs=int(wait_secs + EXEC_TIMEOUT_MARGIN)
        )
    except Exception as exc:  # noqa: BLE001 - a burpwn transport failure is a tool result, not a crash
        _log.warning("ws exec failed for %s: %s", url, exc)
        _cleanup(out)
        return {"url": url, "error": f"burpwn exec failed: {exc}", "captured_request_ids": []}

    transcript = _read_transcript(out, url)
    _cleanup(out)

    exec_result = exec_result if isinstance(exec_result, dict) else {}
    flow_ids = list(exec_result.get("captured_request_ids") or [])
    result = {
        **transcript,
        "captured_request_ids": flow_ids,
        "exec_id": exec_result.get("exec_id"),
        "exit_code": exec_result.get("exit_code"),
    }
    if not flow_ids and not transcript.get("error"):
        # Frames exchanged but nothing captured means the traffic escaped the MITM; an oracle would
        # otherwise be handed a finding with no evidence behind it.
        result["capture_warning"] = (
            "the exchange captured ZERO burpwn flows — the frames are NOT usable as evidence; "
            "check that the sandbox is intercepting before reporting anything from this session"
        )
    return result


def _read_transcript(out: Path, url: str) -> dict:
    if not out.exists():
        return {
            "url": url,
            "frames": [],
            "messages": [],
            "error": (
                "the in-sandbox client wrote no transcript — it could not start "
                "(check that the sandbox can run this interpreter)"
            ),
        }
    try:
        return json.loads(out.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"url": url, "frames": [], "messages": [], "error": f"unreadable transcript: {exc}"}


def _cleanup(out: Path) -> None:
    try:
        out.unlink(missing_ok=True)
    except OSError as exc:  # noqa: BLE001 - a leftover transcript is untidy, never fatal
        _log.debug("could not remove %s: %s", out, exc)


# --------------------------------------------------------------------------- captured-flow reuse


def parse_header_block(raw: Any) -> dict[str, str]:
    """Parse burpwn's ``request.headers`` blob (``"name: value\\r\\n"`` lines) into a dict.

    Accepts a dict or a list of ``{name, value}`` too, because burpwn's shape has moved between
    versions and a replay silently losing the victim's Cookie is a false negative that reads exactly
    like "access control held".
    """
    if isinstance(raw, dict):
        return {str(k): str(v) for k, v in raw.items()}
    if isinstance(raw, list):
        out: dict[str, str] = {}
        for item in raw:
            if isinstance(item, dict) and item.get("name"):
                out[str(item["name"])] = str(item.get("value", ""))
        return out
    if not isinstance(raw, str):
        return {}
    headers: dict[str, str] = {}
    for line in raw.replace("\r\n", "\n").split("\n"):
        name, sep, value = line.partition(":")
        if sep and name.strip():
            headers[name.strip()] = value.strip()
    return headers


def replayable_headers(headers: dict[str, str]) -> dict[str, str]:
    """Drop the per-connection handshake headers, keep the credentials (Cookie/Authorization/Origin)."""
    return {k: v for k, v in headers.items() if k.lower() not in _HANDSHAKE_HEADERS}


def flow_ws_url(flow: dict) -> str | None:
    """Rebuild the ``ws(s)://`` URL of a captured WebSocket flow from ``req_show`` output.

    burpwn records an upgraded flow with ``scheme`` ``http``/``https`` (it *was* an HTTP request) and
    keeps the port only in ``dst_port``, so the URL has to be reassembled rather than read off.
    """
    if not isinstance(flow, dict):
        return None
    request = flow.get("request") if isinstance(flow.get("request"), dict) else {}
    authority = str(request.get("authority") or flow.get("authority") or flow.get("sni") or "")
    if not authority:
        return None
    path = str(request.get("path") or flow.get("path") or "/") or "/"
    secure = str(flow.get("scheme") or "").lower() in ("https", "wss")
    scheme = "wss" if secure else "ws"
    host = authority
    if ":" not in authority:
        port = flow.get("dst_port")
        default = 443 if secure else 80
        if isinstance(port, int) and port != default:
            host = f"{authority}:{port}"
    return f"{scheme}://{host}{path}"
