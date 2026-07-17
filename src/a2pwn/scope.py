"""Deterministic engagement-scope enforcement.

The engagement declares ``targets`` (and an optional broader ``in_scope`` allow-list).
Prompt text alone cannot be trusted to keep an actively-attacking agent inside scope —
a hallucinated URL, a mis-parsed redirect, or a prompt-injected ``fetch http://attacker/``
must be refused *deterministically* before any target-facing command runs.

``host_of`` extracts a destination host from a URL / bare host / ``host:port`` / argv token
(returning ``None`` for non-host tokens like flags or SQL payloads), and ``in_scope`` decides
whether that host is an allowed host or a subdomain of one. The cloud-metadata address
``169.254.169.254`` and any unlisted third party are rejected fail-closed.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# host[:port] with dotted labels or an IP — deliberately strict so flag tokens
# ("-H", "GET", "User-Agent") and payloads ("1' OR '1'='1") do NOT parse as hosts.
_HOSTPORT_RE = re.compile(r"^(?P<host>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)(?::\d+)?$")


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def host_of(target: str) -> str | None:
    """Parse the destination host from a URL, bare host, ``host:port`` or argv token.

    Returns the lowercased hostname, or ``None`` when the token is not host-like (a flag,
    a verb, an inline payload, …). Handles ``--url=http://h/…`` and scheme-relative ``//h``.
    """
    if not target or not isinstance(target, str):
        return None
    token = target.strip()
    if not token:
        return None
    # value after the last '=' when it embeds a URL (e.g. --url=http://host/…)
    if "=" in token and "://" in token.split("=", 1)[1]:
        token = token.split("=", 1)[1].strip()
    if "://" in token:
        host = urlparse(token).hostname
        return host.lower() if host else None
    if token.startswith("//"):
        host = urlparse("http:" + token).hostname
        return host.lower() if host else None
    # strip any path/query so "host/path" and "host?x" still resolve
    hostport = re.split(r"[/?#]", token, maxsplit=1)[0]
    m = _HOSTPORT_RE.match(hostport)
    if not m:
        return None
    host = m.group("host")
    if _is_ip(host) or "." in host:
        return host.lower()
    return None


def in_scope(host: str, targets: list[str], in_scope: list[str]) -> bool:
    """True iff ``host`` is an allowed host or a subdomain of one.

    The allow-list is ``in_scope`` if non-empty, else ``targets``. Fail-closed: an empty
    allow-list, an unparseable host, or a host outside every allowed host returns ``False``.
    """
    if not host:
        return False
    host = host.strip().lower().rstrip(".")
    if not host:
        return False
    allow = list(in_scope) if in_scope else list(targets or [])
    allowed: set[str] = set()
    for entry in allow:
        parsed = host_of(entry)
        if parsed is None and isinstance(entry, str):
            parsed = entry.strip().lower().rstrip(".") or None
        if parsed:
            allowed.add(parsed.lower().rstrip("."))
    if not allowed:
        return False
    for a in allowed:
        if host == a or host.endswith("." + a):
            return True
    return False


def argv_hosts(argv: list[str]) -> list[str]:
    """Every host-like destination parsed out of a command ``argv`` (deduped, in order)."""
    seen: list[str] = []
    for token in argv or []:
        host = host_of(token)
        if host and host not in seen:
            seen.append(host)
    return seen
