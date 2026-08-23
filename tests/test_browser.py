"""The headless-browser capability: the digest channel, and the one distinction it exists to make.

Two invariants are worth more than everything else in this file.

**Reflection is not execution.** A payload echoed into the DOM proves the sink is reachable; it does
not prove a single line of attacker JavaScript ran. Reporting the first as XSS is the most common
false positive in automated scanning, and a2pwn's whole premise is that a finding is proven or it is
not a finding. So `classify_dom_xss` and the driver's marker check are tested on all four corners:
executed, executed-and-reflected, reflected-only, and neither.

**A missing browser must degrade a dispatch, never abort one.** Playwright is an optional extra and
the browser lives on the far side of `burpwn exec`, which returns no stdout — so there are three
distinct ways to end up with nothing (no playwright, no digest file, a sandbox exec that threw), and
all three must come back as a result dict the model can read. An exception thrown out of a tool
takes the exploit context of the whole dispatch with it.

**No test here starts a browser, imports playwright, or opens the sandbox.** The client is a fake
that writes whatever digest the test asked for into the `--out` path, which is also how the
host-side plumbing (argv construction, file read-back, cleanup, capture merge) gets exercised
without a browser existing at all.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from a2pwn import _browser_driver as driver_mod
from a2pwn.browser import (
    DEFAULT_XSS_PAYLOAD,
    MARKER_PLACEHOLDER,
    BrowserDriver,
    build_driver_argv,
    build_probe_url,
    classify_dom_xss,
    marker_js,
    new_marker,
    parse_digest,
    substitute_marker,
)
from a2pwn.config import EngagementSpec
from a2pwn.scope import ScopeGuard
from a2pwn.throttle import Throttle
from a2pwn.tools.browser_tools import (
    BROWSER_PROBE_DOM_XSS_DESC,
    browser_tools,
    run_browser_eval,
    run_browser_probe_dom_xss,
    run_browser_render,
)

_URL = "https://app.example.com/dashboard"


# --------------------------------------------------------------------------- fakes
class FakeClient:
    """Stands in for BurpwnClient.exec: records the argv and writes the digest the test chose.

    Writing the file is the point — the driver's only channel back to the host is that path, so a
    fake that skipped it would exercise none of the plumbing that actually breaks in practice.
    """

    def __init__(self, digest: dict | str | None = None, captured: list[int] | None = None) -> None:
        self.digest = digest
        self.captured = [1, 2, 3] if captured is None else captured
        self.calls: list[dict] = []
        self.raises: Exception | None = None

    async def exec(self, argv, workspace=None, timeout_secs=None) -> dict:
        self.calls.append({"argv": argv, "workspace": workspace, "timeout_secs": timeout_secs})
        if self.raises is not None:
            raise self.raises
        out = Path(argv[argv.index("--out") + 1])
        if self.digest is not None:
            out.write_text(self.digest if isinstance(self.digest, str) else json.dumps(self.digest))
        return {"exit_code": 0, "captured_request_ids": list(self.captured), "exec_id": "exec-1"}


class FakeFrame:
    """One browser frame: `evaluate` answers by substring so the driver's real JS is exercised."""

    def __init__(self, marker_global: str | None, html: str, url: str = _URL) -> None:
        self._marker = marker_global
        self._html = html
        self.url = url

    def evaluate(self, expression, *args):
        if driver_mod.MARKER_GLOBAL in expression and "outerHTML" not in expression:
            return self._marker is not None and json.dumps(self._marker) in expression
        return self._html


class FakePage:
    def __init__(self, frames) -> None:
        self.frames = list(frames)


def _guarded_driver(tmp_path: Path, client, **kw) -> BrowserDriver:
    engagement = EngagementSpec(name="t", targets=[_URL], in_scope=["app.example.com"], session="t")
    return BrowserDriver(client, work_dir=tmp_path, guard=ScopeGuard.from_engagement(engagement), **kw)


# --------------------------------------------------------------------------- digest parsing
def test_empty_digest_is_reported_as_the_unwritable_workdir_it_almost_always_is():
    # The host pre-creates the file, so "exists but empty" can only mean the sandbox could not write
    # it. /tmp there is a private tmpfs and ~/.cache and ~/.local/share are read-only mounts, so this
    # is a configuration mistake with a specific fix, not a generic failure.
    out = parse_digest("")
    assert out["ok"] is False and out["error"] == "browser-unavailable"
    assert "writable" in out["detail"]


def test_unparseable_digest_never_raises():
    out = parse_digest("{not json")
    assert out["ok"] is False and out["error"] == "browser-error"


def test_non_object_digest_is_rejected_rather_than_indexed():
    assert parse_digest("[1, 2]")["error"] == "browser-error"


def test_valid_digest_passes_through_untouched():
    assert parse_digest('{"ok": true, "title": "x"}') == {"ok": True, "title": "x"}


# --------------------------------------------------------------------------- marker plumbing
def test_marker_is_unguessable_and_fresh_each_probe():
    # A predictable token could be planted by the page, or survive from a previous probe on the same
    # origin, and be read back as a hit.
    markers = {new_marker() for _ in range(50)}
    assert len(markers) == 50
    assert all(len(m) > 20 for m in markers)


def test_placeholder_becomes_an_assignment_of_the_token_to_a_page_global():
    payload = substitute_marker(DEFAULT_XSS_PAYLOAD, "TOK")
    assert MARKER_PLACEHOLDER not in payload
    assert marker_js("TOK") in payload
    assert driver_mod.MARKER_GLOBAL in payload


def test_payload_without_a_placeholder_is_left_alone():
    # Silently injecting a marker into a payload the operator wrote would change what is being
    # tested; the probe reports that execution is unprovable instead.
    assert substitute_marker("<b>hi</b>", "TOK") == "<b>hi</b>"


# --------------------------------------------------------------------------- execution vs reflection
def test_execution_wins_even_when_the_payload_is_also_reflected():
    # The normal case for a real hit: the payload is in the DOM *and* it ran. Ordering the checks the
    # other way round would downgrade every genuine DOM XSS to a reflection.
    out = classify_dom_xss({"ok": True, "marker": "T", "marker_executed": True, "marker_reflected": True})
    assert out["verdict"] == "executed" and out["dom_xss"] is True


def test_reflection_alone_is_explicitly_not_a_finding():
    out = classify_dom_xss({"ok": True, "marker": "T", "marker_executed": False, "marker_reflected": True})
    assert out["verdict"] == "reflected-not-executed" and out["dom_xss"] is False


def test_neither_reflected_nor_executed_is_a_clean_negative():
    out = classify_dom_xss({"ok": True, "marker": "T", "marker_executed": False, "marker_reflected": False})
    assert out["verdict"] == "not-reflected" and out["dom_xss"] is False


def test_a_failed_probe_is_not_reported_as_a_negative_result():
    # "the browser could not run" and "the payload did not fire" are different facts, and collapsing
    # them would let an unavailable browser read as "not vulnerable".
    out = classify_dom_xss({"ok": False, "error": "browser-unavailable"})
    assert out["verdict"] == "probe-failed" and "dom_xss" not in out


def test_a_probe_with_no_marker_says_so_instead_of_returning_false():
    out = classify_dom_xss({"ok": True, "marker": "", "marker_executed": False})
    assert out["verdict"] == "no-marker" and "dom_xss" not in out


def test_driver_marker_check_reads_the_global_not_the_html():
    # The reflected-only shape: the token is in the serialised DOM (it was echoed into a text node)
    # but no global holds it. This is the exact input that must NOT become a finding.
    page = FakePage([FakeFrame(marker_global=None, html="<b>TOK</b>")])
    out = driver_mod._probe_result(page, "TOK")
    assert out == {"marker": "TOK", "marker_executed": False, "marker_reflected": True, "marker_frame": None}


def test_driver_marker_check_finds_execution_in_a_subframe():
    # A payload landing in an iframe executes in that frame's global, not the top one; only walking
    # the top frame would report a real hit as a miss.
    page = FakePage([FakeFrame(None, "<html></html>", url="https://app.example.com/"), FakeFrame("TOK", "<b>TOK</b>", url="https://app.example.com/widget")])
    out = driver_mod._probe_result(page, "TOK")
    assert out["marker_executed"] is True and out["marker_frame"].endswith("/widget")


def test_driver_marker_check_survives_a_frame_that_throws():
    class Detached:
        url = "about:blank"

        def evaluate(self, expression, *args):
            raise RuntimeError("frame detached")

    page = FakePage([Detached(), FakeFrame("TOK", "<b>TOK</b>")])
    assert driver_mod._probe_result(page, "TOK")["marker_executed"] is True


# --------------------------------------------------------------------------- URL construction
def test_hash_param_puts_the_payload_where_the_server_never_sees_it():
    # A fragment is not sent upstream, which is why a hit there is DOM XSS by construction and why
    # no captured request could ever have revealed it.
    url = build_probe_url("https://app.example.com/p?a=1", "hash", "<img>")
    assert url == "https://app.example.com/p?a=1#<img>"


def test_named_param_is_encoded_and_replaces_an_existing_value():
    url = build_probe_url("https://app.example.com/p?q=old&keep=1", "q", "<img>")
    assert "keep=1" in url and "q=%3Cimg%3E" in url and "q=old" not in url


def test_named_param_keeps_an_existing_fragment():
    assert build_probe_url("https://app.example.com/p#frag", "q", "x").endswith("#frag")


# --------------------------------------------------------------------------- argv
def test_argv_uses_an_absolute_interpreter_and_omits_empty_options():
    # A bare `python` inside the sandbox resolves to the host's system interpreter, which has
    # neither a2pwn nor playwright installed — it would fail as an ImportError, not as a browser.
    argv = build_driver_argv(python="/venv/bin/python", url=_URL, out_path="/w/d.json")
    assert argv[0] == "/venv/bin/python" and argv[1:3] == ["-m", "a2pwn._browser_driver"]
    assert "--expression" not in argv and "--marker" not in argv and "--profile" not in argv


def test_argv_carries_the_optional_options_when_set():
    argv = build_driver_argv(
        python="p", url=_URL, out_path="/w/d.json", action="eval", expression="() => 1", marker="T"
    )
    assert argv[argv.index("--expression") + 1] == "() => 1"
    assert argv[argv.index("--marker") + 1] == "T"


# --------------------------------------------------------------------------- host-side driver
async def test_render_merges_the_digest_with_the_flows_that_prove_it_happened(tmp_path):
    client = FakeClient({"ok": True, "title": "Dash"}, captured=[7, 8])
    out = await _guarded_driver(tmp_path, client).render(_URL)
    assert out["title"] == "Dash"
    assert out["captured_request_ids"] == [7, 8] and out["capture_confirmed"] is True


async def test_a_render_that_captured_nothing_is_flagged_not_silently_trusted(tmp_path):
    # A page that rendered without generating a single captured flow came from a cache, or found a
    # way around the proxy. Either way it is not evidence about the target.
    client = FakeClient({"ok": True, "title": "Dash"}, captured=[])
    out = await _guarded_driver(tmp_path, client).render(_URL)
    assert out["capture_confirmed"] is False


async def test_the_digest_file_is_cleaned_up_after_every_run(tmp_path):
    client = FakeClient({"ok": True})
    await _guarded_driver(tmp_path, client).render(_URL)
    assert list(tmp_path.glob("digest-*.json")) == []


async def test_an_out_of_scope_url_is_refused_before_the_browser_ever_starts(tmp_path):
    # One navigation pulls in every third-party script and beacon a page references, so the browser
    # is the easiest way to leave scope by accident. The refusal must happen host-side, before exec.
    client = FakeClient({"ok": True})
    out = await _guarded_driver(tmp_path, client).render("https://evil.example.net/")
    assert out["refused"] is True and out["ok"] is False
    assert client.calls == []


async def test_a_tripped_circuit_breaker_refuses_without_adding_traffic(tmp_path):
    client = FakeClient({"ok": True})
    throttle = Throttle()
    throttle.tripped = True
    out = await _guarded_driver(tmp_path, client, throttle=throttle).render(_URL)
    assert out["ok"] is False and client.calls == []


async def test_a_sandbox_exec_failure_becomes_a_result_not_an_exception(tmp_path):
    client = FakeClient({"ok": True})
    client.raises = RuntimeError("burpwn is gone")
    out = await _guarded_driver(tmp_path, client).render(_URL)
    assert out["error"] == "browser-exec-failed" and "burpwn is gone" in out["detail"]


async def test_a_driver_that_wrote_nothing_degrades_instead_of_crashing(tmp_path):
    # This is what a base install (no playwright) and an unwritable work_dir both look like from the
    # host: the exec succeeded and the file is empty.
    client = FakeClient(digest=None)
    out = await _guarded_driver(tmp_path, client).render(_URL)
    assert out["ok"] is False and out["error"] == "browser-unavailable"


async def test_an_unusable_work_dir_is_reported_rather_than_raised(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    client = FakeClient({"ok": True})
    engagement = EngagementSpec(name="t", targets=[_URL], in_scope=["app.example.com"], session="t")
    d = BrowserDriver(client, work_dir=blocker, guard=ScopeGuard.from_engagement(engagement))
    out = await d.render(_URL)
    assert out["ok"] is False and out["error"] == "browser-unavailable"


async def test_eval_refuses_an_empty_expression_without_spending_a_navigation(tmp_path):
    client = FakeClient({"ok": True})
    out = await _guarded_driver(tmp_path, client).evaluate(_URL, "   ")
    assert out["error"] == "bad-request" and client.calls == []


async def test_eval_passes_the_expression_through_to_the_driver(tmp_path):
    client = FakeClient({"ok": True, "result": [1, 2]})
    out = await _guarded_driver(tmp_path, client).evaluate(_URL, "() => [1,2]")
    argv = client.calls[0]["argv"]
    assert argv[argv.index("--expression") + 1] == "() => [1,2]"
    assert out["result"] == [1, 2]


async def test_probe_sends_a_fresh_marker_and_returns_the_verdict(tmp_path):
    client = FakeClient({"ok": True, "marker_executed": True, "marker_reflected": True})
    driver = _guarded_driver(tmp_path, client)
    out = await driver.probe_dom_xss(_URL, param="hash")
    argv = client.calls[0]["argv"]
    marker = argv[argv.index("--marker") + 1]
    # The digest the driver returns is keyed on the marker the host generated, so a probe can never
    # be satisfied by a token from an earlier run.
    assert marker in argv[argv.index("--url") + 1]
    assert out["verdict"] == "executed" and out["dom_xss"] is True
    assert out["param"] == "hash" and out["requested_url"] == _URL


async def test_probe_without_the_placeholder_says_execution_was_unprovable(tmp_path):
    client = FakeClient({"ok": True, "marker": "", "marker_executed": False, "marker_reflected": True})
    out = await _guarded_driver(tmp_path, client).probe_dom_xss(_URL, param="hash", payload="<b>inert</b>")
    assert out["verdict"] == "no-marker"
    assert MARKER_PLACEHOLDER in out["marker_hint"]


async def test_probe_reflected_only_result_is_carried_through_as_not_a_finding(tmp_path):
    client = FakeClient({"ok": True, "marker": "T", "marker_executed": False, "marker_reflected": True})
    out = await _guarded_driver(tmp_path, client).probe_dom_xss(_URL)
    assert out["verdict"] == "reflected-not-executed" and out["dom_xss"] is False


# --------------------------------------------------------------------------- in-sandbox driver
def test_driver_reports_browser_unavailable_when_playwright_is_missing(monkeypatch, tmp_path):
    # The base install has no playwright. `run` must answer with a digest carrying the remedy, not
    # propagate an ImportError that would surface as a dead dispatch.
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    args = driver_mod._parse_args(["--url", _URL, "--out", str(tmp_path / "d.json")])
    out = driver_mod.run(args)
    assert out["ok"] is False and out["error"] == "browser-unavailable"
    assert "playwright install firefox" in out["remedy"]


def test_driver_main_always_writes_a_digest_file(monkeypatch, tmp_path):
    # `burpwn exec` returns no stdout, so a file that was never written is indistinguishable from a
    # hung sandbox. Every exit path has to leave a readable verdict behind.
    monkeypatch.setitem(sys.modules, "playwright.sync_api", None)
    out_path = tmp_path / "d.json"
    assert driver_mod.main(["--url", _URL, "--out", str(out_path)]) == 0
    assert json.loads(out_path.read_text())["error"] == "browser-unavailable"


def test_driver_write_failure_does_not_raise(tmp_path):
    driver_mod._write(str(tmp_path / "missing-dir" / "d.json"), {"ok": True})  # must not raise


# --------------------------------------------------------------------------- tool adapters
def test_tool_names_are_the_three_browser_capabilities():
    names = [t.name for t in browser_tools(object())]
    assert names == ["browser_render", "browser_eval", "browser_probe_dom_xss"]


def test_tool_descriptions_teach_the_distinction_the_probe_exists_for():
    # The model decides on the description alone whether a reflected payload is worth reporting.
    assert "REFLECTION IS NOT EXECUTION" in BROWSER_PROBE_DOM_XSS_DESC
    assert MARKER_PLACEHOLDER in BROWSER_PROBE_DOM_XSS_DESC


@pytest.mark.parametrize(
    "call",
    [
        lambda: run_browser_render(None, _URL),
        lambda: run_browser_eval(None, _URL, "() => 1"),
        lambda: run_browser_probe_dom_xss(None, _URL),
    ],
)
async def test_every_tool_degrades_cleanly_when_no_browser_is_wired_in(call):
    out = await call()
    assert out["ok"] is False and out["error"] == "browser-unavailable"
    assert "playwright" in out["remedy"]


async def test_tools_delegate_to_the_driver_with_the_arguments_they_were_given(tmp_path):
    client = FakeClient({"ok": True, "marker_executed": True, "marker_reflected": False})
    driver = _guarded_driver(tmp_path, client)
    tools = {t.name: t for t in browser_tools(driver)}
    out = await tools["browser_probe_dom_xss"].ainvoke({"url": _URL, "param": "q", "payload": DEFAULT_XSS_PAYLOAD})
    assert out["verdict"] == "executed"
    assert client.calls[0]["argv"][client.calls[0]["argv"].index("--action") + 1] == "probe-dom-xss"
