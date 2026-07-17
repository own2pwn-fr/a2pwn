"""OOB collaborator (must-fix): in-sandbox listener + external Interactsh-style client.

Two backends host the callback sink that turns a *blind* vulnerability into evidence:

* **in_sandbox** — start ``python -m a2pwn._oob_listener`` through ``burpwn exec`` on a reachable
  interface so the target's callback lands as a ``dns`` / ``rawtcp`` / ``h1`` flow in the same burpwn
  session; poll it with ``req_search`` (FTS over decrypted history) + ``req_list(protocol=..)``.
* **external** — an Interactsh-style HTTP polling client for callbacks that never reach the sandbox host.

Wired into the oracles (``oracles.oob``) for blind SSRF / XXE / deserialization / SQLi exfil.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import socket
import time
import uuid
from typing import TYPE_CHECKING

import httpx
from pydantic import BaseModel

if TYPE_CHECKING:  # avoid a hard runtime coupling to a sibling module built in parallel
    from a2pwn.burpwn import BurpwnClient

# logical OOB protocol -> real burpwn flow ``protocol`` values (h1/h2/ws/dns/rawtcp/tls-passthru)
_LOGICAL_TO_REAL: dict[str, tuple[str, ...]] = {
    "dns": ("dns",),
    "http": ("h1", "h2"),
    "rawtcp": ("rawtcp",),
    "smtp": ("rawtcp",),
}
# real burpwn flow ``protocol`` -> the OOBHit logical label
_REAL_TO_LOGICAL: dict[str, str] = {
    "dns": "dns",
    "h1": "http",
    "h2": "http",
    "ws": "http",
    "rawtcp": "rawtcp",
    "tls-passthru": "rawtcp",
}
_MATCH_FIELDS = ("authority", "path", "sni", "host")
_POLL_INTERVAL = 1.0
# marker echoed by the backgrounding shell so the launch exec has observable output
_LAUNCH_TOKEN = "oob-listener-launched"  # noqa: S105 - not a secret, a log sentinel
# the backgrounding launch exec returns at once; keep its timeout short and independent of the TTL
_LAUNCH_TIMEOUT_SECS = 15


def _detect_local_ip() -> str:
    """Best-effort reachable IPv4 of this host (no packet is actually sent by a UDP connect)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def _row_matches(row: dict, correlation_id: str) -> bool:
    needle = correlation_id.lower()
    return any(needle in str(row.get(field, "") or "").lower() for field in _MATCH_FIELDS)


def _row_raw(row: dict) -> str:
    authority = str(row.get("authority") or row.get("sni") or "")
    path = str(row.get("path") or "")
    return (authority + path).strip()


class OOBHit(BaseModel):
    """A single observed out-of-band callback correlated to an emitted payload."""

    correlation_id: str
    protocol: str  # 'dns'|'http'|'rawtcp'|'smtp'
    source_ip: str | None = None
    raw: str = ""
    flow_id: int | None = None


class Collaborator:
    """Two backends. (1) in_sandbox: host a listener via ``burpwn exec`` on a reachable iface so the
    target callback lands as a dns/rawtcp flow in-session. (2) external: an Interactsh client / user
    listener for callbacks that never reach the sandbox host."""

    def __init__(self, client: BurpwnClient, external_base: str | None = None) -> None:
        self._client = client
        self._external_base = external_base or None
        self._host_cache: str | None = None
        self._started = False
        self._workspace = os.environ.get("A2PWN_OOB_WORKSPACE", "oob") or None
        self._dns_port = int(os.environ.get("A2PWN_OOB_DNS_PORT", "53"))
        self._http_port = int(os.environ.get("A2PWN_OOB_HTTP_PORT", "80"))
        self._tcp_port = int(os.environ.get("A2PWN_OOB_TCP_PORT", "8000"))
        self._ttl = int(os.environ.get("A2PWN_OOB_TTL", "3600"))

    # ------------------------------------------------------------------ helpers

    def new_correlation(self) -> str:
        return uuid.uuid4().hex[:16]

    def _resolve_host(self) -> str:
        if self._host_cache is None:
            self._host_cache = self._external_base or os.environ.get("A2PWN_OOB_HOST") or _detect_local_ip()
        return self._host_cache

    def payload_url(self, correlation_id: str, scheme: str = "http") -> str:
        """Host/URL to embed in the exploit; the correlation id rides in the label AND the path so any
        callback protocol (DNS resolution, HTTP request) carries it into the captured flow / FTS."""
        host = f"{correlation_id}.{self._resolve_host()}"
        if scheme == "dns":
            return host
        if scheme in ("http", "https"):
            return f"{scheme}://{host}/{correlation_id}"
        return f"{scheme}://{host}"

    # ------------------------------------------------------------------ lifecycle

    def _listener_argv(self, protocols) -> list[str]:
        return [
            "python",
            "-m",
            "a2pwn._oob_listener",
            "--protocols",
            ",".join(protocols),
            "--dns-port",
            str(self._dns_port),
            "--http-port",
            str(self._http_port),
            "--tcp-port",
            str(self._tcp_port),
            "--duration",
            str(self._ttl),
        ]

    async def start_in_sandbox(self, protocols=("dns", "rawtcp", "http")) -> None:
        """Launch the stdlib sink inside the sandbox as a **detached background** process.

        DEADLOCK FIX: the previous design ran the listener as a foreground ``exec`` for its
        whole TTL (up to an hour). ``BurpwnClient.exec`` holds the client's single request
        lock until the child exits, so every ``poll()`` (``req_search``/``req_list``) blocked
        behind the listener and no blind-OOB callback could ever be observed. Here the listener
        is ``setsid``-detached and backgrounded (``&``) by a throwaway shell, so the launch
        ``exec`` returns immediately, releasing the lock; the listener keeps running and its
        callbacks are captured by the MITM independently of the launcher process. ``poll`` then
        runs concurrently against the live listener.
        """
        if self._started:
            return
        inner = shlex.join(self._listener_argv(protocols))
        # setsid -> new session survives the launcher shell exiting; & -> shell returns at once.
        wrapper = f"setsid {inner} >/dev/null 2>&1 & echo {_LAUNCH_TOKEN}"
        argv = ["sh", "-c", wrapper]
        await self._client.exec(argv, workspace=self._workspace, timeout_secs=_LAUNCH_TIMEOUT_SECS)
        self._started = True

    async def stop(self) -> None:
        """Best-effort teardown. The listener also self-terminates after ``--duration``."""
        if not self._started:
            return
        try:
            await self._client.exec(
                ["pkill", "-f", "a2pwn._oob_listener"],
                workspace=self._workspace,
                timeout_secs=_LAUNCH_TIMEOUT_SECS,
            )
        except Exception:  # noqa: BLE001 - stopping is best-effort; the sink self-expires anyway
            pass
        self._started = False

    # ------------------------------------------------------------------ polling

    async def poll(
        self,
        correlation_id: str,
        timeout_secs: int = 30,
        protocols=("dns", "http", "rawtcp"),
    ) -> list[OOBHit]:
        """Return every observed callback for ``correlation_id`` (empty until timeout if none)."""
        if self._external_base:
            return await self._poll_external(correlation_id, timeout_secs)
        return await self._poll_in_sandbox(correlation_id, timeout_secs, protocols)

    async def _poll_in_sandbox(
        self, correlation_id: str, timeout_secs: int, protocols
    ) -> list[OOBHit]:
        deadline = time.monotonic() + timeout_secs
        seen: dict[int, OOBHit] = {}
        while True:
            try:
                search_ids = set(await self._client.req_search(correlation_id))
            except Exception:  # noqa: BLE001 - a transient MCP hiccup must not abort the oracle
                search_ids = set()
            for logical in protocols:
                for real in _LOGICAL_TO_REAL.get(logical, (logical,)):
                    try:
                        resp = await self._client.req_list(protocol=real)
                    except Exception:  # noqa: BLE001
                        continue
                    for row in resp.get("flows", []) or []:
                        fid = row.get("id")
                        if fid in seen:
                            continue
                        if fid in search_ids or _row_matches(row, correlation_id):
                            seen[fid] = OOBHit(
                                correlation_id=correlation_id,
                                protocol=_REAL_TO_LOGICAL.get(real, logical),
                                source_ip=row.get("client_addr") or row.get("dst_ip"),
                                raw=_row_raw(row),
                                flow_id=fid,
                            )
            if seen or time.monotonic() >= deadline:
                break
            await asyncio.sleep(_POLL_INTERVAL)
        return list(seen.values())

    async def _poll_external(self, correlation_id: str, timeout_secs: int) -> list[OOBHit]:
        base = self._external_base or ""
        if not base.startswith(("http://", "https://")):
            base = "http://" + base
        url = base.rstrip("/") + "/poll"
        deadline = time.monotonic() + timeout_secs
        hits: list[OOBHit] = []
        async with httpx.AsyncClient(timeout=10.0) as client:
            while True:
                data = None
                try:
                    params = {"id": correlation_id, "correlation_id": correlation_id}
                    resp = await client.get(url, params=params)
                    data = resp.json()
                except Exception:  # noqa: BLE001 - poll again on any transport/parse error
                    data = None
                hits = _extract_interactions(data, correlation_id)
                if hits or time.monotonic() >= deadline:
                    break
                await asyncio.sleep(_POLL_INTERVAL)
        return hits


def _extract_interactions(data, correlation_id: str) -> list[OOBHit]:
    """Normalise an Interactsh-style poll response (list or wrapper dict) into ``OOBHit`` objects."""
    if data is None:
        return []
    items: list = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("hits", "interactions", "data", "results"):
            value = data.get(key)
            if isinstance(value, list):
                items = value
                break
        else:
            items = [data] if ("protocol" in data or "proto" in data) else []
    hits: list[OOBHit] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        proto = str(item.get("protocol") or item.get("proto") or "http").lower()
        if proto not in ("dns", "http", "rawtcp", "smtp"):
            proto = "http"
        src = (
            item.get("source_ip")
            or item.get("remote-address")
            or item.get("remote_address")
            or item.get("remoteAddress")
        )
        raw = (
            item.get("raw")
            or item.get("raw-request")
            or item.get("raw_request")
            or item.get("rawRequest")
            or ""
        )
        hits.append(
            OOBHit(correlation_id=correlation_id, protocol=proto, source_ip=src, raw=str(raw))
        )
    return hits
