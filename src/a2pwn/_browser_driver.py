"""Headless-Firefox driver runnable as ``python -m a2pwn._browser_driver`` **inside the sandbox**.

a2pwn has no eyes. Every tool it owns speaks HTTP at the wire, so the whole client-side half of a
modern application — the DOM-XSS sink a bundle reaches only after routing, the CSP that is or is
not actually enforced, the ``postMessage`` listener that trusts any origin, the token that only
exists in ``localStorage`` after a JS login — is invisible to it. This module is the eyes, and the
one hard constraint on having them is that the browser must run **inside ``burpwn exec``** so its
traffic is captured like everything else; a browser launched from the a2pwn process would be a
second, unlogged egress and would quietly break the invariant the whole design rests on.

Hosted the same way as :mod:`a2pwn._oob_listener`: a stdlib-shaped helper process started through
``BurpwnClient.exec``, whose flows land in the same session. Two sandbox facts shape everything here:

* **``burpwn exec`` returns no stdout** — only ``{exit_code, captured_request_ids, exec_id}``. So the
  digest is written to a ``--out`` file path chosen by the caller and read back host-side. The
  sandbox shares the filesystem, so that works; see :mod:`a2pwn.browser` for which directories are
  actually writable from inside (``/tmp`` is a *private* tmpfs, and ``~/.cache`` / ``~/.local/share``
  are mounted read-only — the digest must not go to either).
* **The digest file is written on every exit path**, including an import failure or a launch crash.
  With no stdout channel, a missing file is indistinguishable from a hung sandbox; a file that says
  ``browser-unavailable`` is a diagnosis.

Firefox, not Chromium, deliberately: Chromium dies inside the sandbox with a silent ``SIGTRAP``
(exit 133, zero stderr) because its own namespace/seccomp layer cannot nest inside bubblewrap, and
no combination of ``--no-sandbox`` / ``--no-zygote`` / ``--single-process`` helps. Headless Firefox
starts and its traffic is captured (verified against burpwn 0.4.0). See :mod:`a2pwn.identity` for
the full history.

Playwright is an OPTIONAL dependency (``a2pwn[browser]`` + ``playwright install firefox``). It is
imported inside the run function, never at module scope, so a base install degrades to a clean
"browser unavailable" digest instead of an ImportError that would kill a dispatch.

This file is part of a2pwn and is distributed under the GNU Affero General Public License v3.0
or later; see the repository ``LICENSE`` for the full text.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from typing import Any

# Placeholder the caller puts inside a DOM-XSS payload; substituted for the marker assignment.
# Kept identical to a2pwn.browser.MARKER_PLACEHOLDER (imported from there by the host side; spelled
# out here so the driver stays importable on its own inside the sandbox).
MARKER_PLACEHOLDER = "__A2PWN_MARKER__"
# Global the marker assignment writes. Namespaced so a page's own globals cannot collide with it.
MARKER_GLOBAL = "__a2pwn_xss_marker"

# Ceiling on how much of any single collected string reaches the transcript. A page can emit
# thousands of console lines and a bundle URL can be a kilometre long; the digest is meant to be
# read by a model, so every list is capped at the collection site rather than truncated later.
_MAX_ITEMS = 80
_MAX_STR = 500
_MAX_CONSOLE = 120

# Instrumentation installed BEFORE any page script runs, in every frame. It records the two things
# that are otherwise unobservable after the fact: which storage keys the page touched (a key read
# and then deleted leaves no trace in a final enumeration), and which `message` listeners were
# registered (a listener is not reflected anywhere in the DOM). Everything is defensive: a page that
# throws inside our wrapper would be a browser bug we caused, not a finding.
_INSTRUMENT_JS = r"""
(() => {
  const rec = { storage: [], listeners: [], onmessage: false };
  try { Object.defineProperty(window, '__a2pwn', { value: rec, enumerable: false }); } catch (e) { return; }
  try {
    const origAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type, fn, opts) {
      try {
        if (type === 'message') {
          rec.listeners.push({
            target: this === window ? 'window' : (this && this.constructor ? this.constructor.name : 'unknown'),
            handler: String(fn).slice(0, 400),
          });
        }
      } catch (e) { /* never let bookkeeping break the page */ }
      return origAdd.call(this, type, fn, opts);
    };
  } catch (e) { /* frozen prototype */ }
  // Patched on Storage.PROTOTYPE, not on the localStorage instance: a Storage object is exotic
  // (its own properties ARE the stored keys) and defining `setItem` on the instance is silently
  // ignored in Firefox, so instance-level wrapping recorded nothing at all.
  try {
    for (const op of ['getItem', 'setItem', 'removeItem']) {
      const orig = Storage.prototype[op];
      Storage.prototype[op] = function (key) {
        try {
          const which = (this === window.localStorage) ? 'localStorage' : 'sessionStorage';
          rec.storage.push(which + '.' + op + ':' + String(key).slice(0, 120));
        } catch (e) { /* never let bookkeeping break the page */ }
        return orig.apply(this, arguments);
      };
    }
  } catch (e) { /* storage blocked by policy for this origin */ }
})();
"""

# Runs AFTER load: reads out the static shape of the page plus whatever the instrumentation saw.
# One evaluate rather than a dozen so the digest is a single consistent snapshot of one moment.
_EXTRACT_JS = r"""
(limits) => {
  const cap = (s) => (s === null || s === undefined) ? '' : String(s).slice(0, limits.str);
  const rec = window.__a2pwn || { storage: [], listeners: [], onmessage: false };
  const forms = Array.from(document.forms).slice(0, limits.items).map((f) => ({
    action: cap(f.action),
    method: cap((f.method || 'get').toUpperCase()),
    inputs: Array.from(f.elements).slice(0, limits.items)
      .map((e) => cap(e.name || e.id || ''))
      .filter((n) => n),
  }));
  const links = Array.from(new Set(
    Array.from(document.querySelectorAll('a[href]')).map((a) => cap(a.href))
  )).slice(0, limits.items);
  const scripts = Array.from(new Set(
    Array.from(document.querySelectorAll('script[src]')).map((s) => cap(s.src))
  )).slice(0, limits.items);
  const keys = (store) => { try { return Object.keys(store).slice(0, limits.items); } catch (e) { return []; } };
  let cookies = [];
  try { cookies = document.cookie.split(';').map((c) => cap(c.split('=')[0].trim())).filter((c) => c); } catch (e) {}
  return {
    title: cap(document.title),
    forms: forms,
    links: links,
    scripts: scripts,
    storage: {
      local_keys: keys(window.localStorage),
      session_keys: keys(window.sessionStorage),
      cookie_names: cookies.slice(0, limits.items),
      touched: Array.from(new Set(rec.storage)).slice(0, limits.items),
    },
    postmessage_listeners: rec.listeners.slice(0, limits.items),
    onmessage_assigned: !!window.onmessage,
    html_len: (document.documentElement ? document.documentElement.outerHTML.length : 0),
  };
}
"""


def marker_js(token: str) -> str:
    """The JS statement a payload must execute for the probe to call it EXECUTION."""
    return f"window.{MARKER_GLOBAL}='{token}'"


def substitute_marker(payload: str, token: str) -> str:
    """Replace the caller's placeholder with the marker assignment.

    Returns the payload unchanged when the placeholder is absent — the caller then gets a probe that
    can prove reflection but can never prove execution, and :func:`a2pwn.browser.classify_dom_xss`
    says exactly that rather than guessing.
    """
    return payload.replace(MARKER_PLACEHOLDER, marker_js(token))


def build_probe_url(url: str, param: str, payload: str) -> str:
    """Place ``payload`` in the fragment or in a query parameter of ``url``.

    ``param`` of ``hash``/``fragment``/``#`` targets the fragment, which is where the DOM-only sinks
    live (``location.hash`` into ``innerHTML``): a fragment never reaches the server, so a hit there
    is DOM XSS by construction and nothing in the HTTP capture could have shown it. The payload goes
    in RAW — the browser percent-encodes what it must, and the sinks that matter run
    ``decodeURIComponent`` on the way out. Any other ``param`` is set as a query parameter, properly
    encoded, for sinks fed from ``location.search``.
    """
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

    if param.strip().lower() in {"hash", "fragment", "#"}:
        parts = urlsplit(url)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, payload))
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    query.append((param, payload))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _write(out_path: str, digest: dict[str, Any]) -> None:
    """Write the digest, and never raise: the file IS the only channel back to the host."""
    try:
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(digest, fh)
    except OSError as exc:  # nothing left to report through — say so on stderr and give up
        sys.stderr.write(f"[browser] cannot write digest to {out_path}: {exc}\n")


def run(args: argparse.Namespace) -> dict[str, Any]:
    """Drive one navigation and return the digest. Never raises; failures become a digest."""
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeout
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        return {
            "ok": False,
            "error": "browser-unavailable",
            "detail": f"playwright is not installed in the sandbox interpreter: {exc}",
            "remedy": "pip install 'a2pwn[browser]' && playwright install firefox",
        }

    console: list[dict[str, str]] = []
    page_errors: list[str] = []
    requests: list[str] = []
    failed: list[str] = []
    # Playwright creates its own throwaway profile per launch, but pinning it to an explicit temp
    # directory is what keeps this off the operator's real Firefox profile: a shared profile hits
    # the SingletonLock and the browser refuses to start at all (the failure mode that made the
    # first attempt at this look like "Firefox does not work in the sandbox").
    profile = args.profile or tempfile.mkdtemp(prefix="a2pwn-ff-")

    digest: dict[str, Any] = {
        "ok": False,
        "action": args.action,
        "url": args.url,
        "profile": profile,
    }
    try:
        with sync_playwright() as pw:
            context = pw.firefox.launch_persistent_context(
                user_data_dir=profile,
                headless=True,
                # burpwn MITMs with a leaf from its own CA. Firefox uses NSS and ignores the
                # SSL_CERT_FILE/NODE_EXTRA_CA_CERTS the sandbox exports, so without this EVERY
                # intercepted page would fail to load and the capability would be useless in the
                # only configuration it is ever used in.
                ignore_https_errors=True,
                bypass_csp=False,  # CSP must stay real: "does the CSP actually stop this" is a finding
            )
            try:
                context.add_init_script(_INSTRUMENT_JS)
                page = context.pages[0] if context.pages else context.new_page()
                page.on("console", lambda m: _record_console(console, m))
                page.on("pageerror", lambda e: page_errors.append(str(e)[:_MAX_STR]))
                page.on("request", lambda r: requests.append(f"{r.method} {r.url}"[:_MAX_STR]))
                page.on("requestfailed", lambda r: failed.append(f"{r.method} {r.url}"[:_MAX_STR]))

                response = page.goto(args.url, wait_until="load", timeout=args.timeout_ms)
                digest["status"] = response.status if response is not None else None

                # Network idle is a BEST EFFORT, deliberately: an app with a websocket, a poller or
                # an analytics beacon never reaches it, and treating that as a failure would make
                # the browser useless on exactly the JS-heavy apps it exists for.
                try:
                    page.wait_for_load_state("networkidle", timeout=args.idle_ms)
                    digest["network_idle"] = True
                except PlaywrightTimeout:
                    digest["network_idle"] = False

                digest["final_url"] = page.url
                extracted = page.evaluate(_EXTRACT_JS, {"items": _MAX_ITEMS, "str": _MAX_STR})
                digest.update(extracted)

                if args.action == "eval":
                    digest["result"] = _safe_eval(page, args.expression)
                elif args.action == "probe-dom-xss":
                    digest.update(_probe_result(page, args.marker))

                digest["ok"] = True
            finally:
                context.close()
    except (PlaywrightError, PlaywrightTimeout) as exc:
        # A launch failure (missing browser binary, sandbox refusal) and a navigation failure are
        # both "no digest to give you", but only the first means the capability is unavailable.
        unavailable = "executable doesn't exist" in str(exc).lower() or "browsertype.launch" in str(exc).lower()
        digest["error"] = "browser-unavailable" if unavailable else "browser-error"
        digest["detail"] = str(exc)[:1200]
        if unavailable:
            digest["remedy"] = "playwright install firefox"
    except Exception as exc:  # noqa: BLE001 - the digest is the only channel; nothing may escape
        digest["error"] = "browser-error"
        digest["detail"] = f"{type(exc).__name__}: {exc}"[:1200]

    digest["console"] = console[:_MAX_CONSOLE]
    digest["console_errors"] = [c["text"] for c in console if c["type"] == "error"][:_MAX_ITEMS]
    digest["page_errors"] = page_errors[:_MAX_ITEMS]
    digest["requests"] = requests[:_MAX_ITEMS]
    digest["requests_failed"] = failed[:_MAX_ITEMS]
    return digest


def _record_console(sink: list[dict[str, str]], message: Any) -> None:
    try:
        sink.append({"type": str(message.type), "text": str(message.text)[:_MAX_STR]})
    except Exception:  # noqa: BLE001 - a console handler must never abort the navigation
        pass


def _safe_eval(page: Any, expression: str) -> Any:
    """Evaluate ``expression`` in page context, degrading a non-serialisable result to its string."""
    try:
        value = page.evaluate(expression)
    except Exception as exc:  # noqa: BLE001 - a page-side throw is a RESULT here, not a driver failure
        return {"error": f"{type(exc).__name__}: {exc}"[:_MAX_STR]}
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)[:_MAX_STR]


def _probe_result(page: Any, marker: str) -> dict[str, Any]:
    """Decide execution vs reflection for ``marker``, across every frame.

    **Reflection is not execution.** The marker token appears in the serialised DOM whenever the
    payload was echoed anywhere — inside a text node, inside an attribute that never fired, inside
    a comment. It appears in ``window.__a2pwn_xss_marker`` only if the JavaScript carrying it
    actually RAN. Reporting the first as XSS is the single most common false positive in automated
    scanning, so the two are collected as separate booleans here and never collapsed.

    Frames are walked because a payload landing in an iframe (a sandboxed preview, an embedded
    widget) executes in that frame's global, not the top one.
    """
    executed = False
    frame = None
    for candidate in page.frames:
        try:
            if candidate.evaluate(f"() => window.{MARKER_GLOBAL} === {json.dumps(marker)}"):
                executed = True
                frame = candidate.url[:_MAX_STR]
                break
        except Exception:  # noqa: BLE001 - a detached/cross-origin frame is simply not evidence
            continue
    reflected = False
    for candidate in page.frames:
        try:
            html = candidate.evaluate("() => document.documentElement ? document.documentElement.outerHTML : ''")
        except Exception:  # noqa: BLE001
            continue
        if marker in (html or ""):
            reflected = True
            break
    return {"marker": marker, "marker_executed": executed, "marker_reflected": reflected, "marker_frame": frame}


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="a2pwn._browser_driver")
    parser.add_argument("--url", required=True)
    parser.add_argument("--out", required=True, help="path the JSON digest is written to")
    parser.add_argument("--action", default="render", choices=["render", "eval", "probe-dom-xss"])
    parser.add_argument("--expression", default="", help="JS to evaluate for --action eval")
    parser.add_argument("--marker", default="", help="unique token for --action probe-dom-xss")
    parser.add_argument("--profile", default="", help="Firefox profile dir (a temp dir when empty)")
    parser.add_argument("--timeout-ms", type=int, default=30000, dest="timeout_ms")
    parser.add_argument("--idle-ms", type=int, default=5000, dest="idle_ms")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    digest = run(args)
    _write(args.out, digest)
    # Exit 0 even on a browser failure: the digest carries the verdict, and a non-zero exit would
    # additionally trip burpwn's "command failed" reporting for something that is already reported.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
