"""Host side of the headless-browser capability: launch the driver in the sandbox, read the digest.

Everything a2pwn can currently prove happens at the wire. That leaves an entire vulnerability class
structurally out of reach: a DOM XSS whose sink is `location.hash` never sends a request, so no
captured flow can contain it and no oracle built on flows can fire on it. The same blindness covers
`postMessage` handlers that trust any origin, a CSP that looks strict in a header and is defeated in
practice, and a token that only exists in `localStorage` after a JS login. This module opens that
half of the application by driving a real browser — and does it under the same rule as everything
else: **the browser runs inside `burpwn exec`**, so its traffic is captured and the
"burpwn is the only egress" invariant survives contact with a JS engine.

The split mirrors `collaborator` / `_oob_listener`: :mod:`a2pwn._browser_driver` is the process that
runs in the sandbox, this module is the host-side client that launches it and interprets what comes
back. Three things about that boundary drive the design and are easy to get wrong:

* **`burpwn exec` returns no stdout** — just `{exit_code, captured_request_ids, exec_id}`. The digest
  therefore travels through a FILE whose path the host picks and the driver writes.
* **`/tmp` inside the sandbox is a private tmpfs, and `~/.cache` / `~/.local/share` are mounted
  READ-ONLY.** A digest path under any of those is silently lost — the first is invisible to the
  host, the second two the driver cannot write at all. `work_dir` must be a directory that is both
  visible to the host and writable from inside, which in practice means somewhere under the project
  / working directory. This is also why a2pwn's own run directory (`~/.local/share/a2pwn/runs/...`)
  is NOT a valid `work_dir`.
* **The exec's `captured_request_ids` are returned alongside the digest**, because that list is what
  makes a browser observation admissible: a rendered page with an empty capture list did not prove
  anything about the target, it proved something about a cache.

Playwright is optional (`a2pwn[browser]` + `playwright install firefox`) and is never imported here
— only inside the sandboxed driver. A host without it gets a `browser-unavailable` result dict, not
an exception: a missing optional dependency must degrade a dispatch, never abort one.

Firefox rather than Chromium is not a preference. Chromium is killed inside the sandbox by a silent
SIGTRAP (exit 133, no stderr) because its own namespace layer cannot nest inside bubblewrap;
headless Firefox starts and its traffic is captured. :mod:`a2pwn.identity` records that history.

This file is part of a2pwn and is distributed under the GNU Affero General Public License v3.0
or later; see the repository ``LICENSE`` for the full text.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Any

from a2pwn._browser_driver import MARKER_PLACEHOLDER, build_probe_url, marker_js, substitute_marker
from a2pwn.scope import ScopeGuard
from a2pwn.throttle import Throttle

__all__ = [
    "MARKER_PLACEHOLDER",
    "DEFAULT_XSS_PAYLOAD",
    "BrowserDriver",
    "build_probe_url",
    "build_driver_argv",
    "classify_dom_xss",
    "marker_js",
    "new_marker",
    "parse_digest",
    "substitute_marker",
]

_log = logging.getLogger("a2pwn.browser")

# Wall-clock ceilings (ms) for one navigation and for the network-idle settle that follows it.
DEFAULT_NAV_TIMEOUT_MS = 30_000
DEFAULT_IDLE_TIMEOUT_MS = 5_000
# Slack (seconds) between the driver's own budget and the exec timeout, so a browser that overruns
# is killed by ITS timeout — which still writes a digest — rather than by burpwn's, which cannot.
_EXEC_MARGIN_SECS = 45

# Default carrier for the DOM-XSS probe. `onerror` on an `<img>` is the payload of choice for an
# `innerHTML` sink specifically because `<script>` written through `innerHTML` does NOT execute
# while an event handler on an injected element does — so a payload that fires here fired for the
# same reason a real one would.
DEFAULT_XSS_PAYLOAD = f'<img src=x onerror="{MARKER_PLACEHOLDER}">'


def new_marker() -> str:
    """A fresh, unguessable execution marker.

    Unguessable matters: the whole probe rests on "this exact string is in this exact global", and a
    predictable token could be planted by the page (or left behind by a previous probe on the same
    origin) and read back as a hit.
    """
    return "a2pwnXSS" + secrets.token_hex(8)


def parse_digest(raw: str) -> dict[str, Any]:
    """Turn the driver's output file into a result dict, without ever raising.

    An empty file is the specific, diagnosable failure of a `work_dir` the sandbox could not write
    to (the host pre-creates the file, so "exists but empty" cannot mean "never ran"). Anything else
    unparseable means the driver died mid-write, which is worth saying plainly rather than crashing
    the tool call that asked for it.
    """
    text = (raw or "").strip()
    if not text:
        return {
            "ok": False,
            "error": "browser-unavailable",
            "detail": (
                "the in-sandbox driver wrote no digest; the work_dir is most likely not writable "
                "from inside burpwn (/tmp is a private tmpfs there, ~/.cache and ~/.local/share are "
                "read-only) or the interpreter could not start"
            ),
        }
    try:
        digest = json.loads(text)
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": "browser-error", "detail": f"unparseable digest: {exc}"}
    if not isinstance(digest, dict):
        return {"ok": False, "error": "browser-error", "detail": "digest was not a JSON object"}
    return digest


def classify_dom_xss(digest: dict[str, Any]) -> dict[str, Any]:
    """Attach the execution-vs-reflection verdict to a probe digest.

    This is the whole point of the probe, so it is stated once, here: **a payload appearing in the
    response or in the DOM is REFLECTION, and reflection is not a vulnerability.** Automated
    scanners report it as one constantly. The only evidence accepted as execution is that the
    marker's assignment RAN — i.e. the marker token is the value of a page global that nothing but
    the executing payload could have set. A payload that is echoed into a text node, into an
    attribute of an element that never fires, or into a comment is `reflected-not-executed`, and
    that verdict is a lead to keep probing, never a finding to report.

    `no-marker` is returned when the payload carried no placeholder: the probe then had nothing that
    could ever prove execution, and saying so is better than a `False` that reads like a negative
    result.
    """
    out = dict(digest)
    if not digest.get("ok"):
        out["verdict"] = "probe-failed"
        return out
    if not digest.get("marker"):
        out["verdict"] = "no-marker"
        return out
    executed = bool(digest.get("marker_executed"))
    reflected = bool(digest.get("marker_reflected"))
    if executed:
        out["verdict"] = "executed"
        out["dom_xss"] = True
    elif reflected:
        out["verdict"] = "reflected-not-executed"
        out["dom_xss"] = False
    else:
        out["verdict"] = "not-reflected"
        out["dom_xss"] = False
    return out


def build_driver_argv(
    *,
    python: str,
    url: str,
    out_path: str,
    action: str = "render",
    expression: str = "",
    marker: str = "",
    profile: str = "",
    timeout_ms: int = DEFAULT_NAV_TIMEOUT_MS,
    idle_ms: int = DEFAULT_IDLE_TIMEOUT_MS,
) -> list[str]:
    """Argv for one in-sandbox driver run.

    The interpreter is passed as an absolute path rather than a bare ``python``: inside the sandbox
    ``PATH`` resolves to the host's system interpreter, which has neither a2pwn nor playwright
    installed, so a bare name would reliably produce an ImportError instead of a browser.
    """
    argv = [
        python,
        "-m",
        "a2pwn._browser_driver",
        "--url",
        url,
        "--out",
        out_path,
        "--action",
        action,
        "--timeout-ms",
        str(int(timeout_ms)),
        "--idle-ms",
        str(int(idle_ms)),
    ]
    if expression:
        argv += ["--expression", expression]
    if marker:
        argv += ["--marker", marker]
    if profile:
        argv += ["--profile", profile]
    return argv


class BrowserDriver:
    """Runs the headless browser inside the sandbox and returns structured digests.

    Every method returns a dict and never raises: these are model-facing tools, and an exception
    thrown out of one aborts a whole dispatch, losing the exploit context that produced the call.

    ``guard`` and ``throttle`` are the same engagement policy the wire tools enforce
    (:mod:`a2pwn.toolcore`). They are applied HERE rather than left to the caller because a browser
    is the easiest way to leave scope by accident: one navigation pulls in every third-party script,
    beacon and CDN the page references. The guard checks the URL a2pwn is asked to open — the
    sandbox and burpwn's own scope registration remain what contains the subresources.
    """

    def __init__(
        self,
        client: Any,
        *,
        work_dir: Path | str | None = None,
        guard: ScopeGuard | None = None,
        throttle: Throttle | None = None,
        workspace: str | None = None,
        python: str | None = None,
    ) -> None:
        self._client = client
        self._guard = guard or ScopeGuard()
        self._throttle = throttle or Throttle()
        self._workspace = workspace or os.environ.get("A2PWN_BROWSER_WORKSPACE") or None
        # sys.executable is the interpreter a2pwn itself is running under, which is the one that has
        # a2pwn (and therefore playwright, when the extra is installed) importable.
        self._python = python or os.environ.get("A2PWN_BROWSER_PYTHON") or sys.executable
        self._work_dir = Path(work_dir or os.environ.get("A2PWN_BROWSER_WORKDIR") or Path.cwd() / ".a2pwn-browser")

    # ------------------------------------------------------------------ capabilities

    async def render(
        self,
        url: str,
        timeout_ms: int = DEFAULT_NAV_TIMEOUT_MS,
        idle_ms: int = DEFAULT_IDLE_TIMEOUT_MS,
    ) -> dict[str, Any]:
        """Load ``url`` in headless Firefox and return the page digest + the captured flow ids."""
        return await self._run("render", url, timeout_ms=timeout_ms, idle_ms=idle_ms)

    async def evaluate(self, url: str, expression: str, timeout_ms: int = DEFAULT_NAV_TIMEOUT_MS) -> dict[str, Any]:
        """Load ``url``, evaluate ``expression`` in page context, return its JSON-able result."""
        if not expression.strip():
            return {"ok": False, "error": "bad-request", "detail": "expression must not be empty"}
        return await self._run("eval", url, expression=expression, timeout_ms=timeout_ms)

    async def probe_dom_xss(
        self,
        url: str,
        param: str = "hash",
        payload: str = "",
        timeout_ms: int = DEFAULT_NAV_TIMEOUT_MS,
    ) -> dict[str, Any]:
        """Navigate with a marker-carrying payload and report EXECUTION separately from reflection.

        The payload should contain ``__A2PWN_MARKER__`` where its JavaScript body goes; that
        placeholder is replaced with an assignment of a fresh unguessable token to a page global,
        and the probe then asks the page whether the global holds it. Nothing else counts.
        """
        marker = new_marker()
        raw_payload = payload or DEFAULT_XSS_PAYLOAD
        final_payload = substitute_marker(raw_payload, marker)
        probe_url = build_probe_url(url, param, final_payload)
        digest = await self._run("probe-dom-xss", probe_url, marker=marker, timeout_ms=timeout_ms)
        digest.setdefault("payload", final_payload)
        digest.setdefault("param", param)
        digest.setdefault("requested_url", url)
        # Whether execution was even *provable* is decided here, not in the sandbox: the host is the
        # side that knows whether the operator's payload carried a placeholder. Without one the
        # marker never entered the page, so the driver's "not executed, not reflected" is an artefact
        # of the probe rather than a statement about the sink — and must not read as a clean negative.
        if MARKER_PLACEHOLDER in raw_payload:
            digest.setdefault("marker", marker)
        else:
            digest["marker"] = ""
            digest["marker_hint"] = (
                f"the payload carried no {MARKER_PLACEHOLDER} placeholder, so execution could not be "
                "proven — put the placeholder where the payload's JavaScript body goes"
            )
        return classify_dom_xss(digest)

    # ------------------------------------------------------------------ plumbing

    async def _gate(self, url: str) -> dict[str, Any] | None:
        """Scope guard, then circuit breaker, then rate limit. ``None`` means proceed."""
        bad = self._guard.off_scope_tokens([url])
        if bad:
            _log.warning("browser REFUSED: out-of-scope destination(s) %s", bad)
            return self._guard.refusal(bad, "browser")
        if self._throttle.tripped:
            return self._throttle.refusal("browser")
        await self._throttle.acquire()
        return None

    async def _run(self, action: str, url: str, **kwargs: Any) -> dict[str, Any]:
        refusal = await self._gate(url)
        if refusal is not None:
            return {"ok": False, **refusal}

        timeout_ms = int(kwargs.pop("timeout_ms", DEFAULT_NAV_TIMEOUT_MS))
        idle_ms = int(kwargs.pop("idle_ms", DEFAULT_IDLE_TIMEOUT_MS))
        try:
            self._work_dir.mkdir(parents=True, exist_ok=True)
            out_path = self._work_dir / f"digest-{secrets.token_hex(6)}.json"
            # Pre-created empty so that "file missing" and "file empty" are different diagnoses:
            # missing means the host could not even create it, empty means the sandbox could not
            # write it. Both are configuration errors, and they have different fixes.
            out_path.write_text("", encoding="utf-8")
        except OSError as exc:
            return {"ok": False, "error": "browser-unavailable", "detail": f"work_dir unusable: {exc}"}

        argv = build_driver_argv(
            python=self._python,
            url=url,
            out_path=str(out_path),
            action=action,
            timeout_ms=timeout_ms,
            idle_ms=idle_ms,
            **kwargs,
        )
        exec_timeout = int((timeout_ms + idle_ms) / 1000) + _EXEC_MARGIN_SECS
        try:
            result = await self._client.exec(argv, workspace=self._workspace, timeout_secs=exec_timeout)
        except Exception as exc:  # noqa: BLE001 - a sandbox failure is a tool result, not a crash
            out_path.unlink(missing_ok=True)
            return {"ok": False, "error": "browser-exec-failed", "detail": f"{type(exc).__name__}: {exc}"}

        try:
            raw = out_path.read_text(encoding="utf-8")
        except OSError as exc:
            raw = ""
            _log.debug("browser digest unreadable at %s: %s", out_path, exc)
        finally:
            out_path.unlink(missing_ok=True)

        digest = parse_digest(raw)
        ids = list((result or {}).get("captured_request_ids") or [])
        digest["captured_request_ids"] = ids
        # An observation with no captured traffic is not evidence: it means the page came from a
        # cache, the navigation never happened, or the browser found a way around the proxy. The
        # oracles must be able to see that without re-deriving it, so it is a field, not a comment.
        digest["capture_confirmed"] = bool(ids)
        digest["exec_id"] = (result or {}).get("exec_id")
        digest["exit_code"] = (result or {}).get("exit_code")
        return digest
