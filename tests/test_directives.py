"""Out-of-band directives: the bus, the delivery mechanism, and the three producers.

Fan-out used to be fire-and-forget — once ``run_subagent`` awaited a child there was no way to
reach it again until it returned, so a sibling proving the same bug, the target starting to block,
and the engagement running out of budget were all things the master KNEW while a dispatch was
burning turns on the wrong thing, and could not say. These tests pin the three properties that make
the channel safe to have at all: it reaches the agent without needing its cooperation (delivery
rides on a tool result, not a tool the model might never call), it never floods a transcript (once
per message, once per key, capped per drain, no backlog for a late joiner), and nothing it does is
load-bearing — a directive is a hint, the hard controls stay in the tool wrappers and the routers.
"""

from __future__ import annotations

import a2pwn.graph as g
from _graphkit import make_budget, make_cfg, make_finding, make_master_state, sub_input
from a2pwn import sdk_agent
from a2pwn.artifacts import ArtifactStore
from a2pwn.directives import _MAX_LEN, _MAX_PER_DRAIN, DirectiveBus
from a2pwn.models import CleanResult, SubAgentInput
from a2pwn.throttle import Throttle


def _blocked(status: int = 429, body: str = "Attention Required | Cloudflare") -> dict:
    return {"response": {"status": status, "body": body}}


# --------------------------------------------------------------------------- the bus
def test_targeted_reaches_only_its_dispatch():
    # The point of addressing: telling ONE sibling to stand down must not stand the fan-out down.
    bus = DirectiveBus()
    bus.join("d-1")
    bus.join("d-2")
    bus.post("stop probing /admin", to="d-1")

    assert bus.drain("d-1") == ["stop probing /admin"]
    assert bus.drain("d-2") == []


def test_broadcast_reaches_every_joined_dispatch():
    bus = DirectiveBus()
    bus.join("d-1")
    bus.join("d-2")
    bus.post("the target has started blocking")

    assert bus.drain("d-1") == ["the target has started blocking"]
    assert bus.drain("d-2") == ["the target has started blocking"]


def test_drain_returns_targeted_before_broadcast():
    # A message addressed to this dispatch is about this dispatch's own work, so it is the one the
    # agent must read first if the banner is skimmed.
    bus = DirectiveBus()
    bus.join("d-1")
    bus.post("engagement-wide notice")
    bus.post("your task specifically", to="d-1")

    assert bus.drain("d-1") == ["your task specifically", "engagement-wide notice"]


def test_a_directive_is_delivered_exactly_once():
    # Re-delivery would append the same sentence to every subsequent tool result for the rest of the
    # dispatch, which is how a channel the model is supposed to obey becomes noise it learns to skip.
    bus = DirectiveBus()
    bus.join("d-1")
    bus.post("sibling proved the sqli")
    bus.post("look at /api", to="d-1")

    assert len(bus.drain("d-1")) == 2
    assert bus.drain("d-1") == []


def test_a_late_dispatch_does_not_inherit_the_backlog():
    """A dispatch that joins late starts at the END of the broadcast log.

    Otherwise a fresh dispatch in hour three of an engagement opens with dozens of stale directives
    dumped into its first tool result — every one of them about work that finished before it
    existed, and all of them charged to its context window.
    """
    bus = DirectiveBus()
    for i in range(20):
        bus.post(f"old news {i}")
    bus.join("late")

    assert bus.drain("late") == []

    bus.post("something that happened after it started")
    assert bus.drain("late") == ["something that happened after it started"]


def test_a_dispatch_that_never_joined_is_treated_as_joining_now():
    # Same invariant, reached by the other door: `join` is optional, so the first `drain` must not
    # hand over the whole engagement's history.
    bus = DirectiveBus()
    bus.post("old news")

    assert bus.drain("never-joined") == []
    bus.post("fresh")
    assert bus.drain("never-joined") == ["fresh"]


def test_post_once_fires_once_per_key_ever():
    """Standing conditions are re-evaluated every phase; the message must not be.

    'Near the budget ceiling' and 'the breaker tripped' stay true for the rest of the run, so a
    plain `post` from a per-phase check would repeat the same sentence until the model stops
    reading directives entirely.
    """
    bus = DirectiveBus()
    bus.join("d-1")
    for _ in range(5):
        bus.post_once("budget-ceiling", "wrap up, the engagement is nearly out of budget")

    assert bus.drain("d-1") == ["wrap up, the engagement is nearly out of budget"]
    bus.post_once("budget-ceiling", "wrap up, the engagement is nearly out of budget")
    assert bus.drain("d-1") == []


def test_post_once_keys_are_independent():
    bus = DirectiveBus()
    bus.join("d-1")
    bus.post_once("budget-ceiling", "nearly out of budget")
    bus.post_once("circuit-breaker", "the target is blocking")

    assert len(bus.drain("d-1")) == 2


def test_empty_and_whitespace_directives_are_dropped():
    # A producer that computes an empty reason must not append a bare banner with nothing after it.
    bus = DirectiveBus()
    bus.join("d-1")
    bus.post("")
    bus.post("   \n\t ")
    bus.post(None)  # type: ignore[arg-type]

    assert bus.drain("d-1") == []


def test_directive_text_is_length_capped():
    # The whole channel is paid for out of the dispatch's context window, so an unbounded producer
    # (a trip reason built from a response body, say) cannot be allowed to dominate a tool result.
    bus = DirectiveBus()
    bus.join("d-1")
    bus.post("x" * 5000)

    assert bus.drain("d-1") == ["x" * _MAX_LEN]


def test_a_drain_hands_over_at_most_the_per_drain_cap():
    bus = DirectiveBus()
    bus.join("d-1")
    for i in range(_MAX_PER_DRAIN + 6):
        bus.post(f"notice {i}")

    assert bus.drain("d-1") == [f"notice {i}" for i in range(_MAX_PER_DRAIN)]
    # …and the cap is a rate limit, not a filter: the rest are still owed to this dispatch.
    assert bus.drain("d-1") == [f"notice {i}" for i in range(_MAX_PER_DRAIN, _MAX_PER_DRAIN * 2)]


def test_annotate_appends_a_labelled_banner():
    # The label matters: the text arrives inside a tool RESULT, so without it the model has to guess
    # whether the sentence came from the target (i.e. is potentially attacker-controlled) or from us.
    bus = DirectiveBus()
    bus.join("d-1")
    bus.post("stop probing, a sibling already proved this")

    out = bus.annotate("d-1", "HTTP/1.1 200 OK")

    assert out.startswith("HTTP/1.1 200 OK")
    assert "[DIRECTIVE from the engagement coordinator]" in out
    assert "a sibling already proved this" in out


def test_annotate_is_identity_when_nothing_is_pending():
    bus = DirectiveBus()
    bus.join("d-1")
    assert bus.annotate("d-1", "HTTP/1.1 200 OK") == "HTTP/1.1 200 OK"


def test_annotate_without_a_dispatch_id_is_identity():
    # Tool calls made outside a dispatch (bootstrap, recon seeding) have no mailbox to drain.
    bus = DirectiveBus()
    bus.post("broadcast")
    assert bus.annotate("", "body") == "body"


# --------------------------------------------------------------------------- SDK delivery
def _text_of(result: dict) -> str:
    return result["content"][0]["text"]


def test_annotate_directives_appends_to_the_first_text_block():
    """Delivery rides on the tool result the agent is already reading.

    Chosen over a "check your messages" tool the model may never call, and over a LangGraph
    interrupt the checkpointerless child cannot take — an agent that is still working is still
    reading tool results, so this reaches it without needing its cooperation.
    """
    bus = DirectiveBus()
    bus.join("d-1")
    bus.post("wrap up")
    result = {"content": [{"type": "text", "text": "flow 12 captured"}]}

    out = sdk_agent._annotate_directives(result, bus, "d-1")

    assert _text_of(out).startswith("flow 12 captured")
    assert "wrap up" in _text_of(out)


def test_annotate_directives_leaves_the_remaining_blocks_untouched():
    bus = DirectiveBus()
    bus.join("d-1")
    bus.post("wrap up")
    tail = [{"type": "image", "data": "..."}, {"type": "text", "text": "second"}]
    result = {"content": [{"type": "text", "text": "first", "extra": "kept"}, *tail]}

    out = sdk_agent._annotate_directives(result, bus, "d-1")

    assert out["content"][1:] == tail
    assert out["content"][0]["extra"] == "kept"  # the block is enriched, not rebuilt


def test_annotate_directives_passes_non_text_and_empty_content_through():
    # Shape-defensive on purpose: an undeliverable directive must degrade to no delivery, never to
    # a mangled tool result the model then has to make sense of.
    bus = DirectiveBus()
    bus.join("d-1")
    bus.post("wrap up")

    for result in (
        {"content": []},
        {"content": [{"type": "image", "data": "..."}]},
        {"content": "not a list"},
        {"no_content": True},
        "not a dict",
    ):
        assert sdk_agent._annotate_directives(result, bus, "d-1") == result  # type: ignore[arg-type]


def test_annotate_directives_with_no_bus_is_a_no_op():
    # The bus only exists on a real engagement; every other caller (tests, retest, a bare SDK run)
    # passes None and must not pay for it.
    result = {"content": [{"type": "text", "text": "flow 12 captured"}]}
    assert sdk_agent._annotate_directives(result, None, "d-1") is result


async def test_a_bulky_result_gets_the_artifact_envelope_AND_the_directive(tmp_path):
    """The two tool-result rewrites compose, in that order.

    ``_offload`` replaces a bulky result with a short artifact envelope and ``_annotate_directives``
    appends the banner; they both rewrite the same single text block, so the one that ran second
    could trivially discard the other's work. The directive must survive the offload, and it must
    land on the ENVELOPE (which the model reads) rather than inside the blob it never sees.
    """
    bus = DirectiveBus()
    bus.join("d-1")
    bus.post("a sibling already proved the sqli on /login")
    artifacts = ArtifactStore(spill_dir=tmp_path, inline_limit=200)
    blob = "MINIFIED-BUNDLE-" + ("z" * 5000)

    async def handler(args):  # noqa: ARG001 - the tool's inputs are irrelevant here
        return sdk_agent._text_result(blob)

    fn = sdk_agent._observe_tool("burpwn_req_show", handler, set(), artifacts, bus, "d-1")
    text = _text_of(await fn({"id": 1}))

    assert blob not in text  # offloaded: the 5 kB never reaches the transcript
    assert "art-0001" in text  # …replaced by the envelope the model greps into
    assert "[DIRECTIVE from the engagement coordinator]" in text
    assert "a sibling already proved the sqli" in text
    assert text.index("art-0001") < text.index("[DIRECTIVE")  # envelope first, banner appended


async def test_a_small_result_still_gets_the_directive():
    bus = DirectiveBus()
    bus.join("d-1")
    bus.post("wrap up")
    artifacts = ArtifactStore(inline_limit=100_000)

    async def handler(args):  # noqa: ARG001
        return sdk_agent._text_result("HTTP/1.1 200 OK")

    fn = sdk_agent._observe_tool("burpwn_req_show", handler, set(), artifacts, bus, "d-1")
    text = _text_of(await fn({"id": 1}))

    assert text.startswith("HTTP/1.1 200 OK")
    assert "wrap up" in text


# --------------------------------------------------------------------------- producer: throttle
def test_the_circuit_breaker_broadcasts_once():
    """Every sibling learns the target is blocking at the same moment, and only once.

    Without the broadcast each dispatch in the fan-out rediscovers the wall independently, burning
    its remaining turns against a WAF until its own next tool call happens to be refused. Without
    ``post_once`` the same sentence would be re-posted on every subsequent trip.
    """
    bus = DirectiveBus()
    bus.join("d-1")
    throttle = Throttle(block_threshold=2, directives=bus)
    for _ in range(2):
        throttle.observe(_blocked())

    pending = bus.drain("d-1")
    assert len(pending) == 1
    assert "circuit breaker tripped" in pending[0]
    assert "429" in pending[0]  # the trip REASON, not just the fact of the trip


def test_a_second_trip_does_not_broadcast_again():
    bus = DirectiveBus()
    bus.join("d-1")
    throttle = Throttle(block_threshold=1, directives=bus)
    throttle.observe(_blocked())
    bus.drain("d-1")

    throttle.reset()  # operator-driven retry after the block is lifted
    throttle.observe(_blocked())

    assert throttle.tripped is True
    assert bus.drain("d-1") == []


def test_an_untripped_breaker_broadcasts_nothing():
    bus = DirectiveBus()
    bus.join("d-1")
    throttle = Throttle(block_threshold=5, directives=bus)
    for _ in range(4):
        throttle.observe(_blocked())

    assert throttle.tripped is False
    assert bus.drain("d-1") == []


def test_the_breaker_works_without_a_bus():
    # The directive is a hint layered on top; the hard control (refusing traffic) must not depend
    # on a bus being wired in.
    throttle = Throttle(block_threshold=1)
    throttle.observe(_blocked())
    assert throttle.tripped is True


# --------------------------------------------------------------------------- producer: dispatches
class _CleanGraph:
    """Stand-in compiled sub-agent returning a canned ``CleanResult``."""

    def __init__(self, result: CleanResult):
        self._result = result

    async def ainvoke(self, state, config=None):  # noqa: ARG002 - signature parity only
        return {"clean_result": self._result}


def _bus(monkeypatch) -> DirectiveBus:
    bus = DirectiveBus()
    monkeypatch.setattr(g, "DIRECTIVE_BUS", bus)
    return bus


def _payload(cfg, *, intent, candidate=None):
    data = sub_input(cfg, intent=intent, candidate=candidate)
    return SubAgentInput(
        dispatch_id=f"0-{intent}-0",
        intent=intent,
        candidate=candidate,
        master_ctx=data["master_ctx"],
    )


async def test_a_proven_finding_is_broadcast_to_the_siblings(monkeypatch):
    """Parallel dispatches routinely overlap on a target; the second proof buys nothing.

    Two siblings independently proving the same bug is the fan-out's characteristic waste: the
    turns are spent, the budget is charged, and the engagement ends up with exactly the finding it
    already had. Naming the KEYS is what lets the sibling tell 'already done' from 'adjacent'.
    """
    cfg = make_cfg()
    bus = _bus(monkeypatch)
    bus.join("watcher")
    proven = make_finding(confirmed=True, vuln="sqli", param="user")
    monkeypatch.setattr(
        g, "SUBAGENT_GRAPH", _CleanGraph(CleanResult(dispatch_id="", status="confirmed", findings=[proven]))
    )

    await g.run_subagent(_payload(cfg, intent="task"))

    pending = bus.drain("watcher")
    assert len(pending) == 1
    assert "has PROVEN" in pending[0]
    assert proven.key in pending[0]


async def test_a_verify_dispatch_does_not_broadcast(monkeypatch):
    """An independent-verify dispatch re-proves something the engagement already knows.

    Broadcasting it would tell the siblings to stop working on a finding that was announced when
    the ORIGINAL task dispatch proved it — the same message twice, the second time as news.
    """
    cfg = make_cfg()
    bus = _bus(monkeypatch)
    bus.join("watcher")
    candidate = make_finding(confirmed=True)
    monkeypatch.setattr(
        g,
        "SUBAGENT_GRAPH",
        _CleanGraph(CleanResult(dispatch_id="", status="confirmed", findings=[candidate])),
    )

    await g.run_subagent(_payload(cfg, intent="verify", candidate=candidate))

    assert bus.drain("watcher") == []


async def test_a_dispatch_that_proved_nothing_broadcasts_nothing(monkeypatch):
    cfg = make_cfg()
    bus = _bus(monkeypatch)
    bus.join("watcher")
    monkeypatch.setattr(
        g, "SUBAGENT_GRAPH", _CleanGraph(CleanResult(dispatch_id="", status="no_finding", findings=[]))
    )

    await g.run_subagent(_payload(cfg, intent="task"))

    assert bus.drain("watcher") == []


# --------------------------------------------------------------------------- producer: budget
def _warn(monkeypatch, **state_kw) -> list[str]:
    bus = _bus(monkeypatch)
    bus.join("watcher")
    cfg = make_cfg()
    g._warn_on_budget(make_master_state(cfg, **state_kw))
    return bus.drain("watcher")


def test_the_dispatch_ceiling_warns_at_eighty_percent(monkeypatch):
    """A sub-agent knows its own turn cap and nothing about the engagement's.

    Without this it opens a brand-new line of investigation on the last dispatch the run can
    afford, and the report is assembled out of work that was one turn away from being useful.
    """
    cfg = make_cfg()
    pending = _warn(monkeypatch, spent=8, budget=make_budget(cfg, max_dispatches=10))
    assert len(pending) == 1
    assert "near its budget ceiling" in pending[0]


def test_below_the_threshold_says_nothing(monkeypatch):
    cfg = make_cfg()
    assert _warn(monkeypatch, spent=7, budget=make_budget(cfg, max_dispatches=10)) == []


def test_the_dollar_ceiling_warns_independently(monkeypatch):
    # Real spend, not the dispatch COUNT: one dispatch ranges from 3 to 60 turns, so a run can be
    # 5% through its dispatches and 90% through its money.
    cfg = make_cfg()
    pending = _warn(
        monkeypatch,
        spent=1,
        spent_usd=8.0,
        budget=make_budget(cfg, max_dispatches=100, max_usd=10.0),
    )
    assert len(pending) == 1
    assert "near its budget ceiling" in pending[0]


def test_the_token_ceiling_warns_independently(monkeypatch):
    cfg = make_cfg()
    pending = _warn(
        monkeypatch,
        spent=1,
        spent_tokens=800_000,
        budget=make_budget(cfg, max_dispatches=100, max_tokens=1_000_000),
    )
    assert len(pending) == 1
    assert "near its budget ceiling" in pending[0]


def test_unset_cost_ceilings_are_not_treated_as_zero(monkeypatch):
    # max_usd/max_tokens default to None; a naive fraction would divide by zero or read as 100%.
    cfg = make_cfg()
    assert _warn(monkeypatch, spent=1, spent_usd=99.0, budget=make_budget(cfg, max_dispatches=100)) == []


def test_the_budget_warning_fires_only_once_across_phases(monkeypatch):
    """`integrate` calls this every phase, and the condition stays true once it is true."""
    bus = _bus(monkeypatch)
    bus.join("watcher")
    cfg = make_cfg()
    state = make_master_state(cfg, spent=9, budget=make_budget(cfg, max_dispatches=10))

    for _ in range(4):
        g._warn_on_budget(state)

    assert len(bus.drain("watcher")) == 1


def test_no_bus_means_no_warning(monkeypatch):
    # A retest / library caller builds no bus; the budget check must stay a no-op, not a crash.
    monkeypatch.setattr(g, "DIRECTIVE_BUS", None)
    cfg = make_cfg()
    g._warn_on_budget(make_master_state(cfg, spent=10, budget=make_budget(cfg, max_dispatches=10)))


# --------------------------------------------------------------------------- regressions
def test_the_per_drain_cap_defers_the_overflow_instead_of_dropping_it():
    """A capped drain owes the remainder to the NEXT drain; it must not silently discard it.

    ``drain`` used to advance the cursor past the whole broadcast log and only then slice to the
    cap, so everything past the fourth message was consumed and thrown away — permanently, since
    the cursor had already moved. The observable damage is not "the agent read four banners
    instead of nine": it is that a directive the coordinator believed it had delivered was never
    delivered to anyone.
    """
    bus = DirectiveBus()
    bus.join("d-1")
    posted = [f"notice {i}" for i in range(_MAX_PER_DRAIN * 2 + 1)]
    for text in posted:
        bus.post(text)

    drained: list[str] = []
    for _ in range(3):
        drained.extend(bus.drain("d-1"))

    assert drained == posted  # every message, in order, across successive tool results
    assert bus.drain("d-1") == []  # …and exactly once


def test_a_burst_of_targeted_messages_cannot_mask_a_later_broadcast():
    """Targeted messages take priority, but priority must not mean pre-emption.

    Targeted directives fill the drain first, so a dispatch that has accumulated a handful of
    "look at X" notes used to consume the whole cap AND the cursor in one go — and the
    circuit-breaker broadcast posted behind them, the one message in the system that says the rest
    of the run is worthless, was the one that vanished. It has to arrive on a later drain instead.
    """
    bus = DirectiveBus()
    bus.join("d-1")
    breaker = "circuit breaker tripped: 429 from the WAF, stop and report what you have"
    for i in range(_MAX_PER_DRAIN + 2):
        bus.post(f"look at /api/v{i}", to="d-1")
    bus.post(breaker)

    first = bus.drain("d-1")
    assert len(first) == _MAX_PER_DRAIN
    assert breaker not in first  # masked by the burst, as designed…

    later = bus.drain("d-1") + bus.drain("d-1")
    assert breaker in later  # …but deferred, not dropped
    assert bus.drain("d-1") == []


def test_a_targeted_burst_beyond_the_cap_is_also_carried_over():
    # Same invariant on the other queue: the targeted list is spliced by exactly what was taken.
    bus = DirectiveBus()
    bus.join("d-1")
    for i in range(_MAX_PER_DRAIN + 3):
        bus.post(f"note {i}", to="d-1")

    assert bus.drain("d-1") == [f"note {i}" for i in range(_MAX_PER_DRAIN)]
    assert bus.drain("d-1") == [f"note {i}" for i in range(_MAX_PER_DRAIN, _MAX_PER_DRAIN + 3)]
    assert bus.drain("d-1") == []


def test_post_reports_whether_it_queued_anything():
    """`post` is a predicate, not a statement — its callers need to know it landed.

    The bus drops empty and whitespace-only text, and until that outcome was visible to the caller
    every producer had to assume its message got through.
    """
    bus = DirectiveBus()
    bus.join("d-1")

    assert bus.post("the target has started blocking") is True
    assert bus.post("look at /admin", to="d-1") is True
    assert bus.post("") is False
    assert bus.post("   \n\t ") is False
    assert bus.post(None) is False  # type: ignore[arg-type]


def test_an_empty_post_once_leaves_the_key_usable():
    """A dropped message must not burn the key that would have let it be sent later.

    ``post_once`` used to add the key before checking that anything was queued, so a producer whose
    reason string was still empty the first time it ran — a breaker that trips before the blocking
    response body has been read, a budget warning built from a not-yet-populated field — silenced
    itself permanently for the rest of the engagement.
    """
    bus = DirectiveBus()
    bus.join("d-1")

    bus.post_once("circuit-breaker", "")
    assert bus.drain("d-1") == []

    bus.post_once("circuit-breaker", "circuit breaker tripped: 429 from the WAF")
    assert bus.drain("d-1") == ["circuit breaker tripped: 429 from the WAF"]

    # …and the key is burned for real this time.
    bus.post_once("circuit-breaker", "circuit breaker tripped again")
    assert bus.drain("d-1") == []


class _RecordingBus(DirectiveBus):
    """A bus that logs `join` calls, so a test can order them against the child starting."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[str] = []

    def join(self, dispatch_id: str) -> None:
        self.events.append(f"join:{dispatch_id}")
        super().join(dispatch_id)


class _ClarifyingGraph:
    """Sub-agent stand-in that spends time before its first tool call, like a real child.

    A dispatch clarifies, then reasons, then calls a tool. Everything the coordinator broadcasts in
    that window is what this stands in for: the bus is posted to *inside* ``ainvoke``, and the
    drain that follows is the one the child's first tool result would carry.
    """

    def __init__(self, bus: DirectiveBus, dispatch_id: str, result: CleanResult):
        self._bus = bus
        self._id = dispatch_id
        self._result = result
        self.first_tool_result: list[str] = []

    async def ainvoke(self, state, config=None):  # noqa: ARG002 - signature parity only
        if isinstance(self._bus, _RecordingBus):
            self._bus.events.append("child-start")
        self._bus.post("circuit breaker tripped: 429 from the WAF")
        self.first_tool_result = self._bus.drain(self._id)
        return {"clean_result": self._result}


async def test_a_dispatch_joins_the_bus_before_its_child_runs(monkeypatch):
    """Registration happens at dispatch START, not at the first tool call.

    ``join`` was never called by anything: the only cursor placement was the lazy one inside
    ``drain``, which sets it to the current END of the log. A dispatch therefore joined at its
    first tool call, and every broadcast posted while it was still clarifying — precisely the
    window in which a freshly-spun-up sibling is told the target has started blocking — was
    treated as backlog it had missed and skipped.
    """
    cfg = make_cfg()
    bus = _RecordingBus()
    monkeypatch.setattr(g, "DIRECTIVE_BUS", bus)
    child = _ClarifyingGraph(
        bus, "0-task-0", CleanResult(dispatch_id="", status="no_finding", findings=[])
    )
    monkeypatch.setattr(g, "SUBAGENT_GRAPH", child)

    await g.run_subagent(_payload(cfg, intent="task"))

    assert bus.events == ["join:0-task-0", "child-start"]
    assert child.first_tool_result == ["circuit breaker tripped: 429 from the WAF"]


async def test_a_broadcast_posted_before_the_dispatch_started_is_still_not_backlog(monkeypatch):
    # The join must place the cursor, not reset it: joining at start still means "from here on",
    # so a dispatch spun up in hour three does not open with the whole engagement's history.
    cfg = make_cfg()
    bus = _RecordingBus()
    monkeypatch.setattr(g, "DIRECTIVE_BUS", bus)
    for i in range(20):
        bus.post(f"old news {i}")
    child = _ClarifyingGraph(
        bus, "0-task-0", CleanResult(dispatch_id="", status="no_finding", findings=[])
    )
    monkeypatch.setattr(g, "SUBAGENT_GRAPH", child)

    await g.run_subagent(_payload(cfg, intent="task"))

    assert child.first_tool_result == ["circuit breaker tripped: 429 from the WAF"]
