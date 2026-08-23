"""Browser tools: render, evaluate and prove DOM XSS, shared by both executor paths.

These three tools are the only way the agent sees a page the way a victim does. Everything else it
owns reads bytes off the wire, which is why a DOM-only vulnerability — the sink fed from
`location.hash`, the `postMessage` listener with no origin check, the CSP that is bypassed in
practice — was previously unreachable no matter how many requests were replayed.

Like :mod:`a2pwn.tools.research_tools`, the descriptions and schemas are module constants so the
LangChain adapters below and the native-SDK wrappers in `sdk_agent` are one definition rather than
two hand-maintained copies. Every call goes through :class:`a2pwn.browser.BrowserDriver`, which runs
the browser inside `burpwn exec` — so a browser tool is exactly as contained as a curl.

This file is part of a2pwn and is distributed under the GNU Affero General Public License v3.0
or later; see the repository ``LICENSE`` for the full text.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import BaseTool, StructuredTool

from a2pwn.browser import DEFAULT_XSS_PAYLOAD, MARKER_PLACEHOLDER
from a2pwn.toolcore import active_refusal

BROWSER_RENDER_DESC = (
    "Load a URL in a real headless browser (Firefox, running INSIDE the burpwn sandbox so every "
    "request it makes is captured) and get back what only a browser can see: the final URL after "
    "client-side redirects, the title, console messages and page errors, every form with its "
    "action/method/input names, every link and script src the DOM ended up with, the storage keys "
    "the page touched, and the postMessage listeners it registered. Use it on any app where the "
    "HTML you fetched with burpwn is an empty shell, to enumerate routes and API calls a SPA only "
    "makes at runtime, and to find postMessage handlers worth attacking. The result carries "
    "captured_request_ids: those are the flows the page generated, and you can req_show them like "
    "any other traffic. Everything it returns is a LEAD, not a finding."
)

BROWSER_EVAL_DESC = (
    "Load a URL in the headless browser and evaluate a JavaScript expression in the page's own "
    "context, returning the result as JSON. Use it to read client-side state no request exposes: "
    "window config objects, a framework's router table, localStorage/sessionStorage contents, the "
    "effective CSP, whether a global is attacker-reachable. Pass an expression, e.g. "
    "\"() => Object.keys(window)\" or \"() => localStorage.getItem('token')\". A page-side throw is "
    "returned as a result, not an error. This runs in the target's origin through the sandbox."
)

BROWSER_PROBE_DOM_XSS_DESC = (
    "Prove — or disprove — DOM XSS at a sink, deterministically. Navigate with a payload that "
    f"contains the placeholder {MARKER_PLACEHOLDER} where its JavaScript body goes; the placeholder "
    "is replaced with an assignment of a fresh unguessable token to a page global, and after load "
    "the probe reports whether that global actually holds the token. "
    "REFLECTION IS NOT EXECUTION: the tool returns marker_reflected (the payload was echoed into "
    "the DOM) and marker_executed (the payload's JavaScript RAN) as separate booleans, and only "
    "verdict='executed' is evidence of XSS — 'reflected-not-executed' means the sink escaped or "
    "never fired and is a lead to keep probing, not a finding. "
    "param='hash' puts the payload in the fragment (where DOM-only sinks live: a fragment is never "
    "sent to the server, so a hit there cannot show up in any captured request); any other param "
    "name sets it as a query parameter. Leave payload empty to use "
    f"{DEFAULT_XSS_PAYLOAD!r}, which is the right shape for an innerHTML sink."
)

BROWSER_RENDER_SCHEMA: dict = {"url": str}
BROWSER_EVAL_SCHEMA: dict = {"url": str, "expression": str}
BROWSER_PROBE_DOM_XSS_SCHEMA: dict = {"url": str, "param": str, "payload": str}


async def run_browser_render(driver: Any, url: str) -> dict:
    if driver is None:
        return _no_driver()
    return await driver.render(url)


async def run_browser_eval(driver: Any, url: str, expression: str) -> dict:
    if driver is None:
        return _no_driver()
    return await driver.evaluate(url, expression)


async def run_browser_probe_dom_xss(driver: Any, url: str, param: str = "hash", payload: str = "") -> dict:
    if driver is None:
        return _no_driver()
    return await driver.probe_dom_xss(url, param=param or "hash", payload=payload or "")


def _no_driver() -> dict:
    """Uniform answer when the engagement was built without a browser.

    Returned rather than raised for the same reason the driver writes a digest on every failure
    path: a tool that throws takes the whole dispatch's exploit context with it.
    """
    return {
        "ok": False,
        "error": "browser-unavailable",
        "detail": "this engagement has no browser driver wired in",
        "remedy": "install the optional extra: pip install 'a2pwn[browser]' && playwright install firefox",
    }


def browser_tools(driver: Any, engagement: Any = None) -> list[BaseTool]:
    """LangChain adapters over the same definitions the native-SDK path uses.

    All three drive real, attacker-controlled navigation of the target, so all three refuse
    deterministically when the engagement did not authorise active exploitation. The check is inside
    each coroutine rather than a wrapper, so the tool keeps its real signature: a tool the model
    cannot call at all reads as a missing capability, not as an explicit, explainable refusal.
    """
    allowed = True if engagement is None else bool(getattr(engagement, "active_exploit_allowed", True))

    def _blocked(name: str) -> dict | None:
        return None if allowed else active_refusal(name)

    async def browser_render(url: str) -> dict:
        return _blocked("browser_render") or await run_browser_render(driver, url)

    async def browser_eval(url: str, expression: str) -> dict:
        return _blocked("browser_eval") or await run_browser_eval(driver, url, expression)

    async def browser_probe_dom_xss(url: str, param: str = "hash", payload: str = "") -> dict:
        return _blocked("browser_probe_dom_xss") or await run_browser_probe_dom_xss(
            driver, url, param, payload
        )

    specs = (
        (browser_render, "browser_render", BROWSER_RENDER_DESC),
        (browser_eval, "browser_eval", BROWSER_EVAL_DESC),
        (browser_probe_dom_xss, "browser_probe_dom_xss", BROWSER_PROBE_DOM_XSS_DESC),
    )
    out: list[BaseTool] = []
    for fn, name, desc in specs:
        fn.__doc__ = desc
        out.append(StructuredTool.from_function(coroutine=fn, name=name))
    return out
