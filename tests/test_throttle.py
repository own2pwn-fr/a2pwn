"""Traffic policy: the global rate limit and the target-is-blocking circuit breaker.

The breaker exists because of a specific, dangerous failure mode: once a WAF answers 429/403 to
everything, every oracle legitimately fails to re-derive, every candidate is rejected, and the run
burns its whole budget producing a 0-finding report that is INDISTINGUISHABLE from a genuinely
secure target. These tests pin that the breaker trips, that it stops traffic, and that the report
says so.
"""

from __future__ import annotations

import time

from a2pwn.config import EngagementSpec
from a2pwn.report import Report, render_html, render_markdown
from a2pwn.throttle import Throttle, clamp_fuzz_payloads
from a2pwn.tools import burpwn_tools


def _engagement() -> EngagementSpec:
    return EngagementSpec(
        name="t", targets=["https://app.example.com/"], in_scope=["app.example.com"], session="t"
    )


def _blocked(status=429, body="Attention Required | Cloudflare"):
    return {"response": {"status": status, "body": body}}


# --------------------------------------------------------------------------- rate limiting
async def test_acquire_paces_calls_to_max_rps():
    throttle = Throttle(max_rps=50)  # 20ms apart
    t0 = time.monotonic()
    for _ in range(4):
        await throttle.acquire()
    assert time.monotonic() - t0 >= 0.05  # 3 gaps x 20ms, minus scheduler slack


async def test_no_rate_limit_configured_does_not_sleep():
    throttle = Throttle(max_rps=None)
    t0 = time.monotonic()
    for _ in range(50):
        await throttle.acquire()
    assert time.monotonic() - t0 < 0.2


# --------------------------------------------------------------------------- breaker
def test_hard_status_trips_after_the_threshold():
    throttle = Throttle(block_threshold=3)
    for _ in range(2):
        throttle.observe(_blocked())
    assert throttle.tripped is False
    throttle.observe(_blocked())
    assert throttle.tripped is True
    assert "429" in throttle.trip_reason


def test_a_successful_response_resets_the_consecutive_run():
    # The breaker must key on a CONSECUTIVE run: a healthy engagement produces 401/403s constantly
    # by design (that is what access-control testing looks like).
    throttle = Throttle(block_threshold=3)
    throttle.observe(_blocked())
    throttle.observe(_blocked())
    throttle.observe({"response": {"status": 200, "body": "ok"}})
    throttle.observe(_blocked())
    assert throttle.tripped is False
    assert throttle.consecutive_blocked == 1


def test_plain_403_without_a_waf_signature_does_not_count():
    # Otherwise every access-control test would trip its own breaker.
    throttle = Throttle(block_threshold=2)
    for _ in range(10):
        throttle.observe({"response": {"status": 403, "body": '{"error":"forbidden"}'}})
    assert throttle.tripped is False


def test_403_with_a_waf_signature_does_count():
    throttle = Throttle(block_threshold=2)
    for _ in range(2):
        throttle.observe({"response": {"status": 403, "body": "Request blocked by mod_security"}})
    assert throttle.tripped is True


def test_threshold_zero_disables_the_breaker():
    throttle = Throttle(block_threshold=0)
    for _ in range(100):
        throttle.observe(_blocked())
    assert throttle.tripped is False


def test_reset_clears_the_breaker():
    throttle = Throttle(block_threshold=1)
    throttle.observe(_blocked())
    throttle.reset()
    assert throttle.tripped is False


def test_statuses_are_found_inside_nested_result_shapes():
    throttle = Throttle(block_threshold=2)
    throttle.observe(
        {"results": [{"status": 429, "body": "cloudflare"}, {"status": 429, "body": "cloudflare"}]}
    )
    assert throttle.tripped is True


# --------------------------------------------------------------------------- tool layer
async def test_a_tripped_breaker_refuses_further_traffic(fake_client):
    throttle = Throttle(block_threshold=1)
    throttle.observe(_blocked())
    tools = {t.name: t for t in burpwn_tools(fake_client, _engagement(), throttle=throttle)}
    res = await tools["burpwn_exec"].ainvoke({"argv": ["curl", "https://app.example.com/"]})
    assert res["refused"] is True
    assert res["error"] == "target-blocking"
    assert fake_client.execs == []


async def test_exec_traffic_feeds_the_breaker_via_its_captured_flow(fake_client):
    # A real burpwn exec result carries ONLY captured_request_ids/exec_id/exit_code — no status and
    # no body (verified live). Observing the result dict directly therefore saw NOTHING, so the
    # breaker was inert against exec-driven traffic, which is most of a run's traffic.
    fake_client.exec_return = {"exit_code": 0, "captured_request_ids": [9], "exec_id": "e1"}
    fake_client.all_flows = [{"id": 9, "response": {"status": 429, "body": "cloudflare"}}]
    throttle = Throttle(block_threshold=2)
    tools = {t.name: t for t in burpwn_tools(fake_client, _engagement(), throttle=throttle)}
    await tools["burpwn_exec"].ainvoke({"argv": ["curl", "https://app.example.com/"]})
    await tools["burpwn_exec"].ainvoke({"argv": ["curl", "https://app.example.com/"]})
    assert throttle.tripped is True


async def test_the_breaker_costs_no_extra_call_when_disarmed(fake_client):
    # The flow fetch is one extra round-trip per exec; it must not happen when the breaker is off.
    fake_client.exec_return = {"exit_code": 0, "captured_request_ids": [9], "exec_id": "e1"}
    throttle = Throttle(block_threshold=0)
    tools = {t.name: t for t in burpwn_tools(fake_client, _engagement(), throttle=throttle)}
    await tools["burpwn_exec"].ainvoke({"argv": ["curl", "https://app.example.com/"]})
    assert fake_client.req_show_calls == []


async def test_tool_results_feed_the_breaker(fake_client):
    throttle = Throttle(block_threshold=2)
    fake_client.replay_return = _blocked()
    tools = {t.name: t for t in burpwn_tools(fake_client, _engagement(), throttle=throttle)}
    await tools["burpwn_req_replay"].ainvoke({"id": 1})
    await tools["burpwn_req_replay"].ainvoke({"id": 1})
    assert throttle.tripped is True


# --------------------------------------------------------------------------- fuzz clamp
def test_clamp_truncates_and_reports_the_drop():
    # Silent truncation would read as "we fuzzed everything"; the notice is the whole point.
    payloads, notice = clamp_fuzz_payloads([str(i) for i in range(100)], 10)
    assert len(payloads) == 10
    assert "clamped" in notice and "90" in notice


def test_clamp_below_the_cap_is_a_no_op():
    payloads, notice = clamp_fuzz_payloads(["a", "b"], 10)
    assert payloads == ["a", "b"]
    assert notice is None


def test_clamp_cap_zero_disables_clamping():
    payloads, notice = clamp_fuzz_payloads([str(i) for i in range(100)], 0)
    assert len(payloads) == 100
    assert notice is None


async def test_fuzz_clamps_payloads_and_surfaces_the_notice(fake_client):
    tools = {t.name: t for t in burpwn_tools(fake_client, _engagement(), fuzz_cap=5)}
    res = await tools["burpwn_fuzz"].ainvoke(
        {"flow": 1, "positions": ["0:1"], "payloads": [str(i) for i in range(50)]}
    )
    assert len(fake_client.fuzzes[0]["payloads"]) == 5
    assert "clamp_notice" in res


# --------------------------------------------------------------------------- report surfacing
def test_markdown_report_shouts_when_testing_was_blocked():
    report = Report(engagement="t", traffic={"tripped": True, "trip_reason": "30 consecutive blocks"})
    body = render_markdown(report)
    assert "TESTING WAS BLOCKED" in body
    assert "NOT evidence of security" in body


def test_html_report_shows_the_blocked_banner():
    report = Report(engagement="t", traffic={"tripped": True, "trip_reason": "30 consecutive blocks"})
    assert "TESTING WAS BLOCKED" in render_html(report)


def test_clean_run_has_no_blocked_banner():
    assert "TESTING WAS BLOCKED" not in render_markdown(Report(engagement="t", traffic={"tripped": False}))
