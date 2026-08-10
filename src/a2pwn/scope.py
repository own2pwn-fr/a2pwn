"""Deterministic engagement-scope enforcement.

The engagement declares ``targets`` (and an optional broader ``in_scope`` allow-list).
Prompt text alone cannot be trusted to keep an actively-attacking agent inside scope —
a hallucinated URL, a mis-parsed redirect, or a prompt-injected ``fetch http://attacker/``
must be refused *deterministically* before any target-facing command runs.

``host_of`` extracts a destination host from a URL / bare host / ``host:port`` / argv token
(returning ``None`` for non-host tokens like flags or SQL payloads), and ``in_scope`` decides
whether that host is an allowed host or a subdomain of one. The cloud-metadata address
``169.254.169.254`` and any unlisted third party are rejected fail-closed.

The allow-list alone is not enough for a real engagement: scopes are routinely stated as
"``*.example.com`` **except** ``legacy.example.com`` and ``/admin/billing``". :class:`ScopeGuard`
carries the allow-list AND that exclusion list, and is the single object both executor paths
(LangChain tool wrappers and the native SDK wrappers) share so a host/path can never be in scope on
one path and out on the other.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from typing import Any
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


def path_of(target: str) -> str:
    """Request path parsed out of a URL-ish token (``"/"`` when the token carries no path).

    Used for path-level scope exclusions (``https://app.example.com/admin/billing``): a bare host
    token has no path to exclude on, so it maps to ``"/"``.
    """
    if not target or not isinstance(target, str):
        return "/"
    token = target.strip()
    if "=" in token and "://" in token.split("=", 1)[1]:
        token = token.split("=", 1)[1].strip()
    if "://" in token:
        return urlparse(token).path or "/"
    if token.startswith("//"):
        return urlparse("http:" + token).path or "/"
    if token.startswith("/"):
        return re.split(r"[?#]", token, maxsplit=1)[0] or "/"
    # "host/path" — only treat the remainder as a path when the head really is a host
    head, sep, rest = token.partition("/")
    if sep and _HOSTPORT_RE.match(re.split(r"[?#]", head, maxsplit=1)[0]):
        return "/" + re.split(r"[?#]", rest, maxsplit=1)[0]
    return "/"


def _match_host(host: str, pattern: str) -> bool:
    """``host`` matches an exclusion ``pattern`` (exact, glob, or parent-domain suffix)."""
    host = host.strip().lower().rstrip(".")
    pattern = pattern.strip().lower().rstrip(".")
    if not host or not pattern:
        return False
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(host, pattern)
    return host == pattern or host.endswith("." + pattern)


def _match_path(path: str, pattern: str) -> bool:
    """``path`` matches an exclusion ``pattern``: a glob, or a prefix ending at a path boundary.

    ``/admin`` excludes ``/admin`` and ``/admin/billing`` but NOT ``/administration``.
    """
    path = path or "/"
    pattern = pattern or "/"
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(path, pattern)
    if not pattern.startswith("/"):
        pattern = "/" + pattern
    pattern = pattern.rstrip("/") or "/"
    if pattern == "/":
        return True
    return path == pattern or path.startswith(pattern + "/")


def is_excluded(host: str, path: str, exclude: list[str] | None) -> bool:
    """True iff ``host``/``path`` is carved OUT of scope by an ``exclude`` entry.

    An entry is one of:

    * a host or host glob — ``legacy.example.com`` (also excludes its subdomains),
      ``*.internal.example.com``;
    * a URL with a path — ``https://app.example.com/admin`` (that host, that path subtree only);
    * a bare path or path glob — ``/admin/billing``, ``/*.bak`` (every in-scope host).

    Exclusions are checked AFTER the allow-list and always win: a host that is both allowed and
    excluded is out of scope.
    """
    if not exclude:
        return False
    host = (host or "").strip().lower().rstrip(".")
    path = path or "/"
    for raw in exclude:
        entry = str(raw or "").strip()
        if not entry:
            continue
        if entry.startswith("/"):  # bare path/glob — applies to every host
            if _match_path(path, entry):
                return True
            continue
        ehost = host_of(entry)
        epath = path_of(entry)
        if ehost is None:
            # not host-like and not path-like: treat as a host glob (e.g. "*.internal")
            if _match_host(host, entry):
                return True
            continue
        if not _match_host(host, ehost):
            continue
        if epath in ("", "/"):  # whole host excluded
            return True
        if _match_path(path, epath):
            return True
    return False


class ScopeGuard:
    """The deterministic scope decision, shared by BOTH executor paths.

    Built once per engagement and handed to the LangChain tool wrappers *and* the native-SDK tool
    wrappers, so a token refused on one executor path is refused identically on the other — the two
    paths previously carried independent copies of this logic (and the SDK path carried none at all,
    which meant the documented client-side refusal was off on the DEFAULT backend).

    ``enforce`` is False only when no allow-list at all was supplied, in which case nothing is
    refused client-side (burpwn's own sandbox containment still applies).
    """

    def __init__(
        self,
        targets: list[str] | None = None,
        allow: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> None:
        self.targets = list(targets or [])
        self.allow = list(allow or [])
        self.exclude = list(exclude or [])
        self.enforce = bool(self.targets or self.allow)

    @classmethod
    def from_engagement(cls, engagement: Any) -> ScopeGuard:
        """Build from an ``EngagementSpec`` (or any object exposing the same attributes).

        ``engagement=None`` yields a non-enforcing guard, preserving the "no engagement passed =>
        no client-side refusal" behaviour the tool builders had before.
        """
        if engagement is None:
            return cls()
        return cls(
            targets=list(getattr(engagement, "targets", None) or []),
            allow=list(getattr(engagement, "in_scope", None) or []),
            exclude=list(getattr(engagement, "exclude", None) or []),
        )

    def allows(self, host: str, path: str = "/") -> bool:
        """True iff ``host``/``path`` is inside the allow-list and not carved out by an exclusion."""
        if not self.enforce:
            return True
        if not in_scope(host, self.targets, self.allow):
            return False
        return not is_excluded(host, path, self.exclude)

    def off_scope(self, hosts: list[str]) -> list[str]:
        """Hosts from ``hosts`` that are out of scope (order-preserving, deduped)."""
        bad: list[str] = []
        for h in hosts or []:
            if h and not self.allows(h) and h not in bad:
                bad.append(h)
        return bad

    def off_scope_tokens(self, tokens: list[str]) -> list[str]:
        """Refused destinations parsed from raw tokens (argv, payloads, URLs).

        Unlike :meth:`off_scope` this keeps each token's PATH, so a path-level exclusion
        (``/admin/billing``) is enforced — the host alone cannot express it.

        The refused label is the bare HOST when the host itself is out of scope, and
        ``host/path`` only when the host is allowed and it is the path that was carved out. Naming
        the path in the first case would be misleading: no path on that host is reachable.
        """
        bad: list[str] = []
        for token in tokens or []:
            host = host_of(token)
            if not host:
                continue
            path = path_of(token)
            if self.allows(host, path):
                continue
            # The carve-out is path-specific only when the host's ROOT is still reachable;
            # otherwise the whole host is out and naming a path would wrongly imply some other
            # path on it is fair game.
            path_specific = path not in ("", "/") and self.allows(host, "/")
            label = f"{host}{path}" if path_specific else host
            if label not in bad:
                bad.append(label)
        return bad

    def refusal(self, refused: list[str], where: str) -> dict:
        """The uniform refusal envelope both executor paths return to the model."""
        return {
            "error": "out-of-scope",
            "refused": True,
            "off_scope_hosts": refused,
            "message": (
                f"REFUSED: {where} targets out-of-scope destination(s) {refused}; only "
                f"{self.allow or self.targets} (and their subdomains) are in scope"
                + (f", EXCLUDING {self.exclude}" if self.exclude else "")
                + ". Nothing was run."
            ),
        }


def is_apex_host(host: str) -> bool:
    """True for a bare/near-bare registrable-looking domain (``example.com``, <=2 labels) where
    subdomain enumeration is likely to surface real additional scope — used to seed a recon pass
    BEFORE the first planning phase so the planner starts with real host visibility instead of only
    ever seeing whatever single hostname the operator typed.

    A naive heuristic (no public-suffix-list dependency): a host under a multi-part suffix like
    ``example.co.uk`` is misclassified as non-apex (3 labels). Acceptable for a default nudge — the
    executor can always run subfinder again mid-engagement if it judges it useful — not a hard gate.
    """
    if not host or _is_ip(host):
        return False
    return host.count(".") <= 1
