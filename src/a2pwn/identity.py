"""Named identities: static credentials, replay logins, and in-sandbox browser logins.

Access-control vulnerability classes — IDOR/BOLA, cross-tenant CRUD, privilege escalation, CSRF —
are only *provable* with more than one identity. The ``two_identity`` oracle is written around an
attacker **A** reaching owner **B**'s object, with an unauthenticated **C** as the negative control
that rules out "the object is simply public". Until this module existed there was no way to give
a2pwn a single credential, so that oracle (and the five skills built on it) could only fire if the
executor happened to self-register accounts mid-run.

Three credential sources, freely combinable per identity:

* **static** — ``headers`` / ``cookies`` the operator already holds;
* **replay login** (:class:`~a2pwn.config.LoginRecipe`) — one HTTP request issued through the
  sandbox, with regex capture off the response and a header template to inject;
* **browser login** (:class:`~a2pwn.config.BrowserLogin`) — a Playwright sequence for JS/SPA/OAuth
  flows that cannot be replayed as raw HTTP.

**The burpwn-is-the-only-egress invariant holds for all three.** The replay login is a ``curl`` run
via ``burpwn exec``; the browser login is a Playwright script *also* run via ``burpwn exec``, so
Chromium boots inside the sandbox network namespace and every request it makes is proxied and
captured like any other. Nothing here opens a socket from the a2pwn process itself.

Resolution is lazy and cached: an identity is only logged in the first time it is used, and
:meth:`IdentityStore.invalidate` drops the cache so the next use re-authenticates (the tool wrappers
call it on a 401/403, so session expiry mid-engagement self-heals instead of silently producing
"access control held" false negatives).

This file is part of a2pwn and is distributed under the GNU Affero General Public License v3.0
or later; see the repository ``LICENSE`` for the full text.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from a2pwn.config import BrowserLogin, BrowserStep, IdentitySpec, LoginRecipe

_log = logging.getLogger("a2pwn.identity")

# Wall-clock ceilings for the two login mechanisms (a hung login must not stall a dispatch).
_LOGIN_TIMEOUT_SECS = 60
_BROWSER_TIMEOUT_SECS = 180

# Headers a caller must never be able to override via an identity — they are properties of the
# connection/flow, not of who you are, and letting an identity set them would silently re-target a
# request at another host (bypassing the scope guard, which inspects Host overrides).
_FORBIDDEN_HEADERS = {"host", ":authority", "content-length", "transfer-encoding"}


@dataclass
class ResolvedIdentity:
    """A resolved identity's concrete credentials, ready to attach to a request."""

    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    note: str = ""
    anonymous: bool = False

    def all_headers(self) -> dict[str, str]:
        """Headers plus a synthesised ``Cookie`` header, with forbidden names dropped."""
        out = {k: v for k, v in self.headers.items() if k.lower() not in _FORBIDDEN_HEADERS}
        if self.cookies:
            jar = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            existing = next((k for k in out if k.lower() == "cookie"), None)
            out[existing or "Cookie"] = f"{out[existing]}; {jar}" if existing else jar
        return out

    def header_list(self) -> list[dict]:
        """``[{"name": ..., "value": ...}]`` — the shape ``req_replay``'s ``set_headers`` takes."""
        return [{"name": k, "value": v} for k, v in self.all_headers().items()]

    def curl_args(self) -> list[str]:
        """``-H`` flags for a curl argv."""
        args: list[str] = []
        for k, v in self.all_headers().items():
            args += ["-H", f"{k}: {v}"]
        return args

    def describe(self) -> str:
        if self.anonymous or not self.all_headers():
            return f"{self.name} (unauthenticated)"
        return f"{self.name} ({len(self.all_headers())} credential header(s))"


def _exec_stdout(result: Any) -> str:
    """Best-effort stdout from a burpwn ``exec`` result (shape-defensive across versions)."""
    if not isinstance(result, dict):
        return str(result or "")
    for key in ("stdout", "output", "stdout_text", "text"):
        value = result.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _parse_set_cookie(raw_headers: str) -> dict[str, str]:
    """Cookie name/value pairs from a raw response header block."""
    jar: dict[str, str] = {}
    for line in (raw_headers or "").split("\r\n"):
        if not line.lower().startswith("set-cookie:"):
            continue
        cookie = line.split(":", 1)[1].strip().split(";", 1)[0]
        if "=" in cookie:
            name, _, value = cookie.partition("=")
            if name.strip():
                jar[name.strip()] = value.strip()
    return jar


def _first_group(pattern: str, text: str) -> str | None:
    """First capture group of ``pattern`` in ``text`` (whole match if the regex has no group)."""
    if not pattern or not text:
        return None
    try:
        m = re.search(pattern, text, re.MULTILINE | re.DOTALL)
    except re.error as exc:
        _log.warning("invalid extraction regex %r: %s", pattern, exc)
        return None
    if m is None:
        return None
    return m.group(1) if m.groups() else m.group(0)


def _render(template: str, values: dict[str, str]) -> str | None:
    """``"Bearer {token}"`` -> the rendered header value, or ``None`` if a placeholder is missing."""
    out = template
    for name in re.findall(r"\{(\w+)\}", template):
        if name not in values:
            return None
        out = out.replace("{" + name + "}", values[name])
    return out


def _browser_steps(login: BrowserLogin) -> list[BrowserStep]:
    """Explicit steps, or a synthesised fill-fill-submit sequence from the shorthand fields."""
    if login.steps:
        return list(login.steps)
    steps: list[BrowserStep] = []
    if login.username is not None:
        steps.append(BrowserStep(fill=login.username_selector, value=login.username))
    if login.password is not None:
        steps.append(BrowserStep(fill=login.password_selector, value=login.password))
    if steps:
        steps.append(BrowserStep(click=login.submit_selector))
    return steps


def _browser_script(login: BrowserLogin) -> str:
    """A self-contained Playwright script, driven by a JSON step list passed on argv.

    Runs INSIDE ``burpwn exec`` (sandbox network namespace) so Chromium's traffic is proxied and
    captured like everything else. ``ignore_https_errors`` accepts burpwn's MITM CA without needing
    to install it into the browser's own trust store. The harvested cookies/storage are printed as a
    single JSON object on stdout, delimited so surrounding chatter cannot corrupt the parse.
    """
    payload = json.dumps(
        {
            "url": login.url,
            "steps": [s.model_dump() for s in _browser_steps(login)],
            "wait_after_ms": login.wait_after_ms,
            "capture_local_storage": login.capture_local_storage,
        }
    )
    return f"""
import asyncio, json, sys
CFG = json.loads({payload!r})

async def main():
    from playwright.async_api import async_playwright
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()
        await page.goto(CFG["url"], wait_until="domcontentloaded")
        for step in CFG["steps"]:
            t = step.get("timeout_ms") or 15000
            if step.get("fill"):
                await page.fill(step["fill"], step.get("value") or "", timeout=t)
            elif step.get("click"):
                await page.click(step["click"], timeout=t)
            elif step.get("wait_for"):
                await page.wait_for_selector(step["wait_for"], timeout=t)
            elif step.get("press"):
                await page.keyboard.press(step["press"])
        await page.wait_for_timeout(CFG["wait_after_ms"])
        cookies = {{c["name"]: c["value"] for c in await ctx.cookies()}}
        storage = {{}}
        if CFG["capture_local_storage"]:
            storage = await page.evaluate(
                "() => Object.assign({{}}, window.localStorage, window.sessionStorage)"
            )
        await browser.close()
        print("__A2PWN_IDENTITY__" + json.dumps({{"cookies": cookies, "storage": storage}}))

asyncio.run(main())
"""


class IdentityError(RuntimeError):
    """A declared identity could not be resolved (login failed / credentials unusable)."""


class IdentityStore:
    """Resolves and caches the engagement's declared identities.

    Every network round-trip a login needs goes through the bound :class:`~a2pwn.burpwn.BurpwnClient`
    — this class never opens a socket itself.
    """

    def __init__(self, client: Any, identities: list[IdentitySpec] | None = None) -> None:
        self._client = client
        self._specs: dict[str, IdentitySpec] = {i.name: i for i in (identities or [])}
        self._cache: dict[str, ResolvedIdentity] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    # ---- introspection ---------------------------------------------------------------
    def __bool__(self) -> bool:
        return bool(self._specs)

    def names(self) -> list[str]:
        return list(self._specs)

    def describe(self) -> list[dict]:
        """Display/tool-facing summary: what identities exist and how each authenticates."""
        out: list[dict] = []
        for spec in self._specs.values():
            if spec.anonymous or not spec.authenticated:
                how = "anonymous (no credentials — use as the two_identity negative control)"
            elif spec.browser_login is not None:
                how = "browser login (Playwright, run inside the burpwn sandbox)"
            elif spec.login is not None:
                how = "replay login (HTTP request through the sandbox)"
            else:
                how = "static credentials"
            out.append(
                {
                    "name": spec.name,
                    "description": spec.description,
                    "authenticates_via": how,
                    "resolved": spec.name in self._cache,
                }
            )
        return out

    # ---- resolution ------------------------------------------------------------------
    async def resolve(self, name: str) -> ResolvedIdentity:
        """Resolve ``name`` to concrete credentials, logging in on first use (cached).

        Concurrent dispatches asking for the same identity share one login (per-name lock), so a
        parallel fan-out never fires N simultaneous logins against the target.
        """
        spec = self._specs.get(name)
        if spec is None:
            raise IdentityError(
                f"unknown identity {name!r}; declared identities are {self.names() or 'none'}"
            )
        cached = self._cache.get(name)
        if cached is not None:
            return cached
        lock = self._locks.setdefault(name, asyncio.Lock())
        async with lock:
            if name in self._cache:  # another task resolved it while we waited
                return self._cache[name]
            resolved = await self._resolve_uncached(spec)
            self._cache[name] = resolved
            return resolved

    def invalidate(self, name: str) -> None:
        """Drop a cached identity so its next use re-authenticates (call on a 401/403)."""
        if self._cache.pop(name, None) is not None:
            _log.info("identity %s invalidated; it will re-authenticate on next use", name)

    async def _resolve_uncached(self, spec: IdentitySpec) -> ResolvedIdentity:
        resolved = ResolvedIdentity(
            name=spec.name,
            headers=dict(spec.headers),
            cookies=dict(spec.cookies),
            anonymous=spec.anonymous,
            note="static credentials" if spec.authenticated else "anonymous",
        )
        if spec.anonymous:
            # An explicitly anonymous identity carries no credentials by construction: it is the
            # negative control, and silently attaching a stray header would destroy its meaning.
            return ResolvedIdentity(name=spec.name, anonymous=True, note="anonymous (no credentials)")
        if spec.login is not None:
            await self._apply_replay_login(spec.login, resolved)
        if spec.browser_login is not None:
            await self._apply_browser_login(spec.browser_login, resolved)
        if not resolved.all_headers():
            raise IdentityError(
                f"identity {spec.name!r} resolved to no credentials — the login produced neither "
                "cookies nor an injectable token (check the extract regex / selectors)"
            )
        return resolved

    # ---- replay login ----------------------------------------------------------------
    async def _apply_replay_login(self, login: LoginRecipe, into: ResolvedIdentity) -> None:
        """Issue the login request through the sandbox and harvest cookies/tokens off the response."""
        argv = ["curl", "-s", "-i", "-X", login.method.upper()]
        for key, value in login.headers.items():
            argv += ["-H", f"{key}: {value}"]
        if login.body is not None:
            argv += ["--data-raw", login.body]
        argv.append(login.url)
        try:
            result = await asyncio.wait_for(
                self._client.exec(argv, workspace=f"login-{into.name}"), timeout=_LOGIN_TIMEOUT_SECS
            )
        except TimeoutError as exc:
            raise IdentityError(f"login for {into.name!r} timed out after {_LOGIN_TIMEOUT_SECS}s") from exc
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed identity failure
            raise IdentityError(f"login request for {into.name!r} failed: {exc}") from exc

        body, headers = await self._login_response(result)
        haystack = f"{headers}\n{body}"
        if login.harvest_cookies:
            into.cookies.update(_parse_set_cookie(headers))
        values: dict[str, str] = {}
        for placeholder, pattern in login.extract.items():
            found = _first_group(pattern, haystack)
            if found is None:
                raise IdentityError(
                    f"login for {into.name!r}: extraction {placeholder!r} did not match the response "
                    f"(pattern {pattern!r})"
                )
            values[placeholder] = found
        for header, template in login.inject.items():
            rendered = _render(template, values)
            if rendered is None:
                raise IdentityError(
                    f"login for {into.name!r}: header template {template!r} references a placeholder "
                    f"that was never extracted (have {sorted(values)})"
                )
            into.headers[header] = rendered
        into.note = f"replay login {login.method.upper()} {login.url}"

    async def _login_response(self, exec_result: Any) -> tuple[str, str]:
        """(body, raw response headers) for a login exec — from the captured flow when available.

        The captured flow is authoritative (decrypted by the proxy, same source the report's raw-HTTP
        reproductions use); curl's own stdout is the fallback when nothing was captured.
        """
        flow_ids = []
        if isinstance(exec_result, dict):
            flow_ids = list(exec_result.get("captured_request_ids") or [])
        if flow_ids:
            try:
                flow = await self._client.req_show(flow_ids[-1], raw=True)
            except Exception as exc:  # noqa: BLE001 - fall through to stdout
                _log.debug("login flow fetch failed, falling back to stdout: %s", exc)
            else:
                resp = (flow or {}).get("response") or {}
                return str(resp.get("body") or ""), str(resp.get("headers") or "")
        stdout = _exec_stdout(exec_result)
        head, _, body = stdout.partition("\r\n\r\n")
        if not body:
            head, _, body = stdout.partition("\n\n")
        return body, head.replace("\n", "\r\n")

    # ---- browser login ---------------------------------------------------------------
    async def _apply_browser_login(self, login: BrowserLogin, into: ResolvedIdentity) -> None:
        """Drive a headless Chromium inside the sandbox and harvest its cookies/storage."""
        script = _browser_script(login)
        try:
            result = await asyncio.wait_for(
                self._client.exec(
                    ["python3", "-c", script],
                    workspace=f"login-{into.name}",
                    timeout_secs=_BROWSER_TIMEOUT_SECS,
                ),
                timeout=_BROWSER_TIMEOUT_SECS + 30,
            )
        except TimeoutError as exc:
            raise IdentityError(
                f"browser login for {into.name!r} timed out after {_BROWSER_TIMEOUT_SECS}s"
            ) from exc
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed identity failure
            raise IdentityError(f"browser login for {into.name!r} failed to run: {exc}") from exc

        stdout = _exec_stdout(result)
        marker = "__A2PWN_IDENTITY__"
        if marker not in stdout:
            raise IdentityError(
                f"browser login for {into.name!r} produced no credentials. Playwright must be "
                "installed and usable inside the sandbox (`uv pip install playwright && playwright "
                f"install chromium`). Output tail: {stdout[-400:]!r}"
            )
        try:
            harvested = json.loads(stdout.split(marker, 1)[1].splitlines()[0])
        except (ValueError, IndexError) as exc:
            raise IdentityError(f"browser login for {into.name!r} returned unparseable output") from exc

        into.cookies.update({str(k): str(v) for k, v in (harvested.get("cookies") or {}).items()})
        storage = {str(k): str(v) for k, v in (harvested.get("storage") or {}).items()}
        for header, template in login.inject.items():
            rendered = _render(template, storage)
            if rendered is None:
                raise IdentityError(
                    f"browser login for {into.name!r}: header template {template!r} references a "
                    f"storage key that was not captured (have {sorted(storage)})"
                )
            into.headers[header] = rendered
        into.note = f"browser login {login.url}"


def apply_identity_to_argv(argv: list[str], identity: ResolvedIdentity) -> tuple[list[str], str | None]:
    """Inject ``identity``'s credentials into a curl-family ``argv``.

    Returns ``(argv, warning)``. Only curl is rewritten — it is the one tool whose header flag
    (``-H``) is unambiguous across every version. For anything else the argv is returned untouched
    with a warning the model can act on, rather than silently issuing an UNAUTHENTICATED request
    that would look like "access control held" and produce a false negative.
    """
    argv = list(argv or [])
    if not argv:
        return argv, "empty argv"
    headers = identity.curl_args()
    if not headers:
        return argv, None  # anonymous identity: nothing to inject, and that is intentional
    exe = argv[0].rsplit("/", 1)[-1]
    if exe != "curl":
        return argv, (
            f"identity {identity.name!r} was NOT applied: only curl argvs can be rewritten "
            f"automatically (got {exe!r}). Re-issue this as curl, or pass the credentials yourself: "
            + " ".join(shlex.quote(a) for a in headers)
        )
    return [argv[0], *headers, *argv[1:]], None


def merge_identity_headers(set_headers: list[dict] | None, identity: ResolvedIdentity) -> list[dict]:
    """Merge identity headers into a ``req_replay`` ``set_headers`` list.

    An explicit caller-supplied header of the same name WINS — the model deliberately overriding
    ``Authorization`` mid-exploit (e.g. testing a forged JWT as identity A) must not be silently
    reverted to the identity's real token.
    """
    explicit = {str(h.get("name", "")).lower() for h in (set_headers or [])}
    merged = list(set_headers or [])
    for header in identity.header_list():
        if header["name"].lower() not in explicit:
            merged.append(header)
    return merged
