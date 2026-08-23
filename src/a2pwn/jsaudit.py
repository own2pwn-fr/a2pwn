"""Deterministic static analysis of JavaScript pulled from the target.

Auditing a front-end bundle used to mean handing a three-megabyte minified blob to a language model
and hoping. That fails twice: the blob evicts the engagement context, and a model skimming minified
code is a bad grep. Everything worth extracting from a bundle — the routes it calls, the credentials
its authors left in it, the libraries it ships and their versions — is a pattern match, so it is done
here, in code, and the model receives a structured digest instead of the bytes.

The extractors are deliberately conservative about what they *claim*. A hit here is a LEAD, never a
finding: `SECRET_KEY=...` in a bundle proves the string is there, not that it is live. The oracle
kernel is still what turns a lead into a finding, and `jsaudit` output carries no `confirmed` flag
for exactly that reason.
"""

from __future__ import annotations

import base64
import math
import re
from collections import Counter

_MAX_ITEMS = 60
_MIN_ENTROPY = 3.6
_MIN_SECRET_LEN = 16

# Endpoints: quoted absolute URLs and root-relative paths. Path matching demands a leading slash and
# at least one more segment character, since `"/"` and `"//"` are noise in every bundle ever built.
_URL_RE = re.compile(r"""['"`](https?://[^'"`\s\\]{6,300})['"`]""")
_PATH_RE = re.compile(r"""['"`](/(?:api|v\d|graphql|rest|auth|admin|internal|_next|wp-json)[^'"`\s\\]{0,200})['"`]""", re.I)
_ANYPATH_RE = re.compile(r"""['"`](/[a-z0-9][\w\-./{}$:]{3,120})['"`]""", re.I)

# Sourcemaps are the single highest-value artefact in a bundle: they reconstruct the original
# sources, comments and internal paths that minification was supposed to remove.
_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*(\S+)")

# Library fingerprints. Version strings in minified code are near-universally emitted as a bare
# assignment next to the library name, which is what lets a bundle be diffed against OSV at all.
_LIB_RE = re.compile(
    r"""(?:^|[^\w])(?P<name>[a-z][\w.-]{2,30})\s*[:=]\s*['"]v?(?P<version>\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)['"]""",
    re.I,
)
_VERSION_COMMENT_RE = re.compile(
    r"""(?:@license|@version|/\*!)\s*(?P<name>[A-Za-z][\w.\-]{2,30})[\sv]*(?P<version>\d+\.\d+(?:\.\d+)?)""",
)

# Credential-shaped literals. Prefixed vendor tokens are matched exactly because they are
# unambiguous; the generic assignment form is entropy-gated so a bundle's own identifiers do not
# drown the real hits.
_TOKEN_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws-access-key", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("google-api-key", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("slack-token", re.compile(r"\b(xox[abposr]-[0-9A-Za-z-]{10,})")),
    ("github-token", re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{20,})\b")),
    ("stripe-key", re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,})\b")),
    ("private-key-block", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)")),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b")),
    ("firebase-config", re.compile(r"(?:apiKey|databaseURL)\s*:\s*['\"]([^'\"]{12,})['\"]")),
]
# The identifier prefix is OPTIONAL. Requiring one meant the keyword could never start at offset 0,
# so `apiKey`, `api_key`, `secret`, `token` and `password` — by far the most common spellings in a
# real bundle — matched nothing, and only decorated names like `myApiKey` were ever found.
_ASSIGN_SECRET_RE = re.compile(
    r"""(?P<name>(?:[A-Za-z_][\w.]{0,40})?(?:secret|token|passwd|password|api[_-]?key|apikey|credential|auth)[\w.]{0,20})"""
    rf"""\s*[:=]\s*['"](?P<value>[A-Za-z0-9+/=_.\-]{{{_MIN_SECRET_LEN},200}})['"]""",
    re.I,
)
# Values that look secret-shaped but are structurally public or inert. This is load-bearing because
# the value class above admits `.`: real secrets contain dots (JWTs, dotted keys), and so do the
# build-time indirections (`process.env.API_KEY`) that are the single most common false positive in
# a bundle — the name says "secret" and the value is a reference to one, not a secret.
# Only EXPLICIT code roots are denied. A generic "looks like a dotted identifier chain" rule was
# tried and rejected: base64 segments are valid identifiers, so it ate real dotted secrets
# (`aK9x.Lm2Qp7Tv4Bn8…`) to catch a class this shorter list already covers.
_SECRET_DENY = re.compile(
    r"^(?:undefined|null|true|false|xxx+|\.{3,}|<[^>]+>"
    r"|(?:process\.env|import\.meta|window|globalThis|self|this|module\.exports)\b.*)$",
    re.I,
)

# DOM sinks worth a manual look: where attacker-controlled input becomes code or markup.
_SINK_RE = re.compile(
    r"\b(innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval|setTimeout|setInterval|"
    r"Function\s*\(|dangerouslySetInnerHTML|postMessage|localStorage|sessionStorage|"
    r"location\.(?:href|hash|search)|document\.cookie)\b"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _dedupe(items: list[str], limit: int = _MAX_ITEMS) -> list[str]:
    return list(dict.fromkeys(items))[:limit]


def extract_endpoints(text: str) -> dict[str, list[str]]:
    """URLs and API-shaped paths the bundle references.

    This is the reason to read a bundle at all: a front-end names every endpoint it calls, including
    the admin and internal ones no crawl will ever link to.
    """
    urls = _dedupe([m.group(1) for m in _URL_RE.finditer(text)])
    paths = _dedupe([m.group(1) for m in _PATH_RE.finditer(text)])
    if len(paths) < 10:
        # Only fall back to the loose pattern when the targeted one found little: on a large bundle
        # it matches thousands of asset paths and buries the interesting handful.
        paths = _dedupe(paths + [m.group(1) for m in _ANYPATH_RE.finditer(text)])
    return {"urls": urls, "paths": paths}


def extract_sourcemaps(text: str) -> list[str]:
    return _dedupe([m.group(1) for m in _SOURCEMAP_RE.finditer(text)])


def extract_dependencies(text: str) -> list[dict]:
    """Library name/version pairs, for an OSV lookup.

    Matches are heuristic — a minified bundle has no manifest — so treat each as a candidate to be
    confirmed by behaviour, not as an inventory.
    """
    found: dict[tuple[str, str], dict] = {}
    for rx, source in ((_VERSION_COMMENT_RE, "banner"), (_LIB_RE, "assignment")):
        for m in rx.finditer(text):
            name = m.group("name").strip().lower()
            version = m.group("version")
            if name in {"version", "v", "value", "default", "type", "id", "key", "name"}:
                continue
            found.setdefault((name, version), {"name": name, "version": version, "source": source})
    return list(found.values())[:_MAX_ITEMS]


def extract_secrets(text: str) -> list[dict]:
    """Credential-shaped literals. A hit is a LEAD: the string is present, not proven live."""
    out: list[dict] = []
    seen: set[str] = set()
    for kind, rx in _TOKEN_PATTERNS:
        for m in rx.finditer(text):
            value = m.group(1)
            if value in seen:
                continue
            seen.add(value)
            out.append({"kind": kind, "value": _redact(value), "at": m.start()})
    for m in _ASSIGN_SECRET_RE.finditer(text):
        value = m.group("value")
        if value in seen or _SECRET_DENY.match(value):
            continue
        if shannon_entropy(value) < _MIN_ENTROPY:
            continue
        seen.add(value)
        out.append(
            {"kind": "high-entropy-assignment", "name": m.group("name"), "value": _redact(value), "at": m.start()}
        )
    return out[:_MAX_ITEMS]


def extract_sinks(text: str) -> list[dict]:
    counts = Counter(m.group(1) for m in _SINK_RE.finditer(text))
    return [{"sink": name, "count": n} for name, n in counts.most_common(20)]


def _redact(value: str) -> str:
    """Keep enough to recognise and re-find the value, not enough to be a credential leak in a log.

    The full string is in the artifact store and in the captured flow; the digest is what gets
    logged, pasted into reports and shown in a TUI someone may be screen-sharing.
    """
    if len(value) <= 12:
        return value[:4] + "…"
    return f"{value[:6]}…{value[-4:]} (len {len(value)})"


def decode_jwt_claims(token: str) -> dict:
    """Best-effort JWT payload decode — an unsigned peek, never a validation."""
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    try:
        raw = parts[1] + "=" * (-len(parts[1]) % 4)
        import json

        return json.loads(base64.urlsafe_b64decode(raw))
    except Exception:  # noqa: BLE001 - a malformed token is a non-result, not an error
        return {}


def analyse(text: str) -> dict:
    """Full digest of one JavaScript asset — what the model gets instead of the bytes."""
    endpoints = extract_endpoints(text)
    return {
        "size": len(text),
        "endpoints": endpoints,
        "sourcemaps": extract_sourcemaps(text),
        "dependencies": extract_dependencies(text),
        "secrets": extract_secrets(text),
        "dom_sinks": extract_sinks(text),
    }
