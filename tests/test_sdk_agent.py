"""Native-SDK executor observability: the tool wrapper logs calls, surfaces failures to the model
instead of swallowing them, and honours the active-exploit block.

Regression guard for "the agent can't use burpwn but I have no logs" — a burpwn tool error used to
propagate as an opaque SDK exception with nothing logged, so a `--plain` run gave no signal about
whether burpwn was driven or why it failed.
"""

from __future__ import annotations

import json
import logging

from a2pwn import sdk_agent


def _text_of(result: dict) -> str:
    return result["content"][0]["text"]


async def test_observe_tool_passes_result_through():
    async def handler(args):
        return sdk_agent._text_result(f"ok:{args['x']}")

    fn = sdk_agent._observe_tool("burpwn_exec", handler, set())
    out = await fn({"x": 1})
    assert _text_of(out) == "ok:1"


async def test_observe_tool_surfaces_failure_as_error_result_and_warns(caplog):
    async def handler(args):
        raise RuntimeError("burpwn mcp stdin broken")

    fn = sdk_agent._observe_tool("burpwn_exec", handler, set())
    with caplog.at_level(logging.WARNING, logger="a2pwn.executor"):
        out = await fn({"argv": ["curl", "-s", "https://x"]})

    # The model gets a clean error result (not an opaque crash) so it can react / retry.
    text = _text_of(out)
    assert "ERROR from burpwn_exec" in text
    assert "burpwn mcp stdin broken" in text
    # …and the failure is logged loudly enough to show up in a --plain run.
    assert any(
        r.levelno == logging.WARNING and "burpwn_exec FAILED" in r.getMessage() for r in caplog.records
    )


async def test_observe_tool_blocks_when_active_exploit_denied(caplog):
    called = {"ran": False}

    async def handler(args):
        called["ran"] = True
        return sdk_agent._text_result("should not run")

    fn = sdk_agent._observe_tool("burpwn_fuzz", handler, {"burpwn_fuzz"})
    out = await fn({"flow": 1})
    assert called["ran"] is False  # handler never touched the target
    assert "BLOCKED" in _text_of(out)


async def test_observe_tool_logs_call_at_info(caplog):
    async def handler(args):
        return sdk_agent._json_result({"ok": True})

    fn = sdk_agent._observe_tool("burpwn_req_show", handler, set())
    with caplog.at_level(logging.INFO, logger="a2pwn.executor"):
        await fn({"id": 42})
    # The call itself is visible at INFO (what --plain shows) with its args.
    assert any("tool burpwn_req_show" in r.getMessage() and "42" in r.getMessage() for r in caplog.records)


def test_json_result_head_roundtrips():
    # sanity: the wrapper's debug head serialises dict results without throwing
    payload = sdk_agent._json_result({"a": [1, 2, 3]})
    assert json.loads(_text_of(payload)) == {"a": [1, 2, 3]}


def test_is_model_refusal_text_matches_observed_claude_code_boilerplate():
    """Regression: a live engagement hit a genuine Claude Code safety refusal mid-dispatch (after
    real tool calls had already run), but the SDK surfaces the eventual failure under the same
    generic "executor loop error" label as a technical crash — with a misleading exception message
    ("returned an error result: success"). Without this heuristic a --plain run can't tell a model
    refusal from a bug."""
    refusal = (
        "API Error: Sonnet 5 has safety measures that flagged this message for a cybersecurity "
        "topic. To learn about the Cyber Verification Program and apply for access, visit our "
        "help center."
    )
    assert sdk_agent._is_model_refusal_text(refusal) is True


def test_is_model_refusal_text_false_for_normal_narration():
    assert sdk_agent._is_model_refusal_text("Found a reflected XSS in the search parameter.") is False


def test_oracles_allowlist_includes_state_change():
    """Regression: state_change (the business-logic/CSRF oracle, shipped and documented in
    EXECUTOR_SYS) was missing from this allow-list, so report_finding silently rewrote every
    state_change candidate to "signature" — the adjudicator then re-derived the wrong oracle
    against the wrong flow shape and rejected genuinely-proven HIGH findings with no signal to
    the operator that anything had gone wrong."""
    assert "state_change" in sdk_agent._ORACLES
