"""Parity between the two executor paths — the regression class that cost real findings.

The LangChain adapters and the native-SDK adapters used to be independent hand-maintained copies of
the same tool surface, and every divergence shipped as a bug: ``state_change`` missing from one
allow-list (findings silently rewritten to the wrong oracle and rejected), the client-side scope
refusal present on the LangChain path ONLY (i.e. absent on the default ``claude-code`` backend), and
the fuzz-contract fixes written twice.

Both paths now derive from :func:`a2pwn.toolcore.build_tool_specs`. These tests assert they still do,
so a future hand-edit to one path fails here rather than in a live engagement.
"""

from __future__ import annotations

import inspect
from typing import Any

from _graphkit import make_cfg
from a2pwn import runtime, sdk_agent
from a2pwn.artifacts import ArtifactStore
from a2pwn.browser import BrowserDriver
from a2pwn.config import EngagementSpec, IdentitySpec
from a2pwn.identity import IdentityStore
from a2pwn.models import Finding
from a2pwn.oracles import VerificationOracle
from a2pwn.research import ResearchClient
from a2pwn.scope import ScopeGuard
from a2pwn.subgraph import _active_tools, _is_active_tool
from a2pwn.toolcore import ACTIVE_TOOL_NAMES, build_tool_specs, tool_names
from a2pwn.tools import burpwn_tools, finding_tools, oracle_tools, recon_tools
from a2pwn.tools.artifact_tools import ARTIFACT_TOOL_SPECS, artifact_tools
from a2pwn.tools.browser_tools import (
    BROWSER_EVAL_SCHEMA,
    BROWSER_PROBE_DOM_XSS_SCHEMA,
    BROWSER_RENDER_SCHEMA,
    browser_tools,
)
from a2pwn.tools.coverage_tools import build_probe, coverage_tools
from a2pwn.tools.finding_tools import _ORACLES as LANGCHAIN_ORACLES
from a2pwn.tools.research_tools import research_tools
from a2pwn.tools.websocket_tools import (
    WS_CONNECT_SCHEMA,
    WS_REPLAY_SCHEMA,
    build_ws_tool_specs,
    websocket_tools,
)


def _engagement(identities=None) -> EngagementSpec:
    return EngagementSpec(
        name="t",
        targets=["https://app.example.com/"],
        in_scope=["app.example.com"],
        identities=list(identities or []),
        session="t",
    )


# --------------------------------------------------------------------------- oracle allow-lists
def test_oracle_allow_lists_match_across_both_paths():
    assert LANGCHAIN_ORACLES == sdk_agent._ORACLES


def test_oracle_allow_lists_match_the_finding_model():
    # The dispatcher, the model's Literal and both tool paths must agree — the state_change bug was
    # exactly this set diverging, and it silently rewrote proven findings to the wrong oracle.
    model_kinds = set(Finding.model_fields["oracle_kind"].annotation.__args__)
    assert LANGCHAIN_ORACLES == model_kinds


def test_oracle_allow_lists_match_the_dispatcher():
    dispatcher_kinds = set(VerificationOracle.model_fields["kind"].annotation.__args__)
    assert LANGCHAIN_ORACLES <= dispatcher_kinds


# --------------------------------------------------------------------------- tool surface
def test_langchain_path_exposes_exactly_the_shared_tool_set(fake_client):
    shared = tool_names(build_tool_specs(fake_client, guard=ScopeGuard.from_engagement(_engagement())))
    langchain = [t.name for t in burpwn_tools(fake_client, _engagement())]
    assert langchain == shared


def test_identity_tools_are_added_on_both_paths_together(fake_client):
    store = IdentityStore(fake_client, [IdentitySpec(name="a", headers={"X": "1"})])
    shared = tool_names(build_tool_specs(fake_client, identities=store))
    langchain = [t.name for t in burpwn_tools(fake_client, _engagement(), identities=store)]
    assert langchain == shared
    assert "identity_request" in shared


def test_every_shared_spec_has_a_description_and_a_schema(fake_client):
    for spec in build_tool_specs(fake_client):
        assert spec.description.strip(), f"{spec.name} has no model-facing description"
        assert isinstance(spec.schema, dict)


def test_schema_keys_are_all_real_parameters_of_the_function(fake_client):
    # The SDK path calls fn(**args) against `schema`; a schema key with no matching parameter would
    # raise TypeError at the worst possible moment (mid-exploit, inside the model loop).
    for spec in build_tool_specs(
        fake_client, identities=IdentityStore(fake_client, [IdentitySpec(name="a", headers={"X": "1"})])
    ):
        params = set(inspect.signature(spec.fn).parameters)
        assert set(spec.schema) <= params, f"{spec.name}: schema keys not in signature"


def test_active_tool_names_are_marked_active_in_the_shared_specs(fake_client):
    store = IdentityStore(fake_client, [IdentitySpec(name="a", headers={"X": "1"})])
    specs = {s.name: s for s in build_tool_specs(fake_client, identities=store)}
    for name in ACTIVE_TOOL_NAMES:
        if name in specs:
            assert specs[name].active is True, f"{name} generates traffic but is not marked active"


# --------------------------------------------------------------------------- scope on BOTH paths
async def test_shared_specs_refuse_out_of_scope_regardless_of_the_calling_path(fake_client):
    # This is the defect that mattered most: the SDK path (the DEFAULT backend) had no client-side
    # scope check at all, so the documented containment was not running in a normal engagement.
    specs = {s.name: s for s in build_tool_specs(fake_client, guard=ScopeGuard(targets=["example.com"]))}
    res = await specs["burpwn_exec"].fn(argv=["curl", "https://evil.example.org/"])
    assert res["refused"] is True
    assert fake_client.execs == []


async def test_shared_specs_allow_in_scope_traffic(fake_client):
    specs = {s.name: s for s in build_tool_specs(fake_client, guard=ScopeGuard(targets=["example.com"]))}
    await specs["burpwn_exec"].fn(argv=["curl", "https://app.example.com/"])
    assert len(fake_client.execs) == 1


async def test_replay_host_override_is_refused_on_the_shared_path(fake_client):
    specs = {s.name: s for s in build_tool_specs(fake_client, guard=ScopeGuard(targets=["example.com"]))}
    res = await specs["burpwn_req_replay"].fn(
        id=1, set_headers=[{"name": "Host", "value": "evil.example.org"}]
    )
    assert res["refused"] is True
    assert fake_client.replays == []


async def test_fuzz_payload_pointing_off_scope_is_refused_on_the_shared_path(fake_client):
    specs = {s.name: s for s in build_tool_specs(fake_client, guard=ScopeGuard(targets=["example.com"]))}
    res = await specs["burpwn_fuzz"].fn(
        flow=1, positions=["0:1"], payloads=["http://169.254.169.254/latest/meta-data/"]
    )
    assert res["refused"] is True
    assert fake_client.fuzzes == []


# --------------------------------------------------------------------------- report_finding parity
def test_report_finding_accepts_the_same_fields_on_both_paths(fake_client):
    # A field added to one path and forgotten on the other is the exact shape of the state_change
    # data-loss bug: the finding is still constructed, just missing what the other path threaded in.
    from a2pwn.tools.finding_tools import finding_tools

    tool = finding_tools(fake_client)[0]
    langchain_fields = set(inspect.signature(tool.coroutine).parameters)
    assert set(sdk_agent.REPORT_FINDING_SCHEMA) == langchain_fields


def test_report_finding_fields_all_exist_on_the_finding_model():
    # Every declared field must actually reach the model; a field the model drops is a field the
    # executor was told to fill for nothing.
    constructor_only = {"flow_ids", "exec_ids", "workspace", "tag", "key_flow"}
    declared = set(sdk_agent.REPORT_FINDING_SCHEMA) - constructor_only
    assert declared <= set(Finding.model_fields)


# --------------------------------------------------------------------------- record_probe parity
def test_record_probe_exists_on_both_paths_with_the_same_schema():
    # Coverage declarations are the only record a run keeps of NEGATIVE results. If the tool were
    # registered on one executor path only, the default backend could sweep an endpoint clean and
    # leave the matrix showing it as untested — re-dispatched forever, and unreportable.
    from a2pwn.tools.coverage_tools import PROBE_SCHEMA, coverage_tools

    tool = {t.name: t for t in coverage_tools()}["record_probe"]
    langchain_fields = set(inspect.signature(tool.coroutine).parameters)
    assert set(sdk_agent.PROBE_SCHEMA) == langchain_fields
    # Same constants and same normaliser, not a hand-copied duplicate: the copies are what diverged
    # last time. The SDK path registers the tool inside `run_sdk_agent`'s spec table.
    assert sdk_agent.PROBE_SCHEMA is PROBE_SCHEMA
    assert sdk_agent.build_probe is build_probe
    assert '"record_probe"' in inspect.getsource(sdk_agent.run_sdk_agent)


# =========================================================================== #
# The four newest tool families: websocket, browser, research, coverage/artifacts.
#
# Same invariant as everything above, one generation later. These families were added to BOTH
# executor paths by hand in the same change, which is precisely the situation that produced every
# defect this file exists for: a family wired into the SDK spec table and forgotten in the LangChain
# tuple is invisible on the API backends, and the reverse is invisible on the DEFAULT
# (``claude-code``) backend — where "invisible" means the model is never told the capability exists,
# so the whole vulnerability class silently reads as "tested, nothing found".
# =========================================================================== #

#: Tools whose whole job is to send attacker-controlled traffic at the target. They are asserted
#: against ``ACTIVE_TOOL_NAMES`` *and* exercised through the SDK block path below.
NEW_ACTIVE_TOOLS = (
    "ws_connect",
    "ws_replay",
    "browser_render",
    "browser_eval",
    "browser_probe_dom_xss",
)

#: Every tool the four new families contribute, by family, so a missing one is named in the failure.
NEW_TOOLS_BY_FAMILY = {
    "websocket": ("ws_connect", "ws_replay"),
    "browser": ("browser_render", "browser_eval", "browser_probe_dom_xss"),
    "research": ("js_analyze", "cve_lookup", "research_fetch", "jwt_decode"),
    "coverage": ("record_probe",),
    "artifacts": ("artifact_grep", "artifact_slice", "artifact_list", "artifact_drop"),
}
NEW_TOOL_NAMES = frozenset(n for names in NEW_TOOLS_BY_FAMILY.values() for n in names)

#: In-scope, side-effect-free arguments for each active tool, used to prove the block fires.
ACTIVE_CALL_ARGS: dict[str, dict] = {
    "ws_connect": {"url": "wss://app.example.com/socket", "messages": ["hi"]},
    "ws_replay": {"flow_id": 1, "message": "hi"},
    "browser_render": {"url": "https://app.example.com/"},
    "browser_eval": {"url": "https://app.example.com/", "expression": "() => 1"},
    "browser_probe_dom_xss": {"url": "https://app.example.com/"},
}


class _RecordingBrowser:
    """Stand-in for :class:`a2pwn.browser.BrowserDriver` that records instead of navigating.

    A real driver would need a sandbox and a Firefox; what these tests need to know is only whether
    the call reached the driver at all — which is exactly the difference between "blocked" and
    "silently ran".
    """

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    async def render(self, url: str) -> dict:
        self.calls.append(("render", url))
        return {"ok": True, "url": url}

    async def evaluate(self, url: str, expression: str) -> dict:
        self.calls.append(("evaluate", url, expression))
        return {"ok": True, "value": None}

    async def probe_dom_xss(self, url: str, param: str = "hash", payload: str = "") -> dict:
        self.calls.append(("probe_dom_xss", url, param, payload))
        return {"ok": True, "verdict": "not-reflected"}


def _deps(client, browser=None) -> dict[str, Any]:
    """Every optional dependency the two paths gate their new tools on, all wired.

    Parity is only meaningful when both sides are given the same wiring: the SDK path omits the
    browser tools when ``browser is None`` and the research tools when ``research is None``, so
    comparing an all-wired SDK table against an all-wired LangChain tuple is the honest comparison —
    it is also what ``runtime.bootstrap`` actually builds.
    """
    eng = _engagement([IdentitySpec(name="a", headers={"X": "1"})])
    return {
        "engagement": eng,
        "identities": IdentityStore(client, eng.identities),
        "artifacts": ArtifactStore(),
        "research": ResearchClient(enabled=False, in_scope_hosts=list(eng.in_scope)),
        "browser": browser if browser is not None else _RecordingBrowser(),
    }


async def _sdk_tool_table(monkeypatch, client, *, deps: dict, active_exploit_blocked=None) -> dict:
    """The tools the SDK path REALLY registers, captured out of ``run_sdk_agent`` itself.

    This is deliberately not a re-implementation of the spec table against the module's DESC/SCHEMA
    constants: a constant that exists but is never appended to ``specs`` is one of the exact bugs
    this file is for, and asserting against the constants would call that green. The model loop is
    the only thing stubbed out (``query`` yields nothing), so everything up to and including
    ``create_sdk_mcp_server`` runs for real, wrappers included.
    """
    captured: dict[str, Any] = {}
    real_create = sdk_agent.create_sdk_mcp_server

    def _capture(name, version, tools=None):
        captured["tools"] = list(tools or [])
        return real_create(name, version, tools=tools)

    async def _no_query(prompt=None, options=None):
        return
        yield  # pragma: no cover - makes this an async generator; the loop body never runs

    monkeypatch.setattr(sdk_agent, "create_sdk_mcp_server", _capture)
    monkeypatch.setattr(sdk_agent, "query", _no_query)
    await sdk_agent.run_sdk_agent(
        model="fake",
        system_prompt="",
        task="noop",
        client=client,
        collab=None,
        skills=[],
        active_exploit_blocked=list(active_exploit_blocked or []),
        **deps,
    )
    return {t.name: t for t in captured["tools"]}


def _langchain_tool_table(client, deps: dict) -> dict:
    """The LangChain tool list, assembled exactly the way ``runtime.bootstrap`` assembles it.

    Skill tools are left out on purpose: the SDK side is built with ``skills=[]``, so both sides
    carry zero of them and the comparison stays about the tool families themselves.
    """
    eng = deps["engagement"]
    tools = (
        burpwn_tools(client, eng, identities=deps["identities"])
        + oracle_tools(None, client)
        + finding_tools(client)
        + recon_tools(eng)
        + coverage_tools()
        + artifact_tools(deps["artifacts"])
        + research_tools(deps["artifacts"], deps["research"])
        + websocket_tools(client, eng, identities=deps["identities"])
        + browser_tools(deps["browser"])
    )
    return {t.name: t for t in tools}


# --------------------------------------------------------------------------- 1. name parity
async def test_both_executor_paths_expose_the_same_tool_names(monkeypatch, fake_client):
    # The failure this prevents: a family added to one path only. On the LangChain path that is a
    # capability the API backends never get; on the SDK path it is a capability the DEFAULT backend
    # never gets. Either way nothing errors — the class just comes back "clean".
    deps = _deps(fake_client)
    sdk = await _sdk_tool_table(monkeypatch, fake_client, deps=deps)
    lang = _langchain_tool_table(fake_client, deps)
    assert set(sdk) == set(lang)
    # ...and not vacuously: every new tool must actually be in there. Two empty sets are equal.
    assert NEW_TOOL_NAMES <= set(sdk)


async def test_each_new_family_is_present_on_both_paths(monkeypatch, fake_client):
    # Same assertion, sliced per family so a failure names the family that drifted rather than
    # dumping a 29-element set diff.
    deps = _deps(fake_client)
    sdk = set(await _sdk_tool_table(monkeypatch, fake_client, deps=deps))
    lang = set(_langchain_tool_table(fake_client, deps))
    for family, names in NEW_TOOLS_BY_FAMILY.items():
        assert set(names) <= sdk, f"{family}: missing from the native-SDK executor path"
        assert set(names) <= lang, f"{family}: missing from the LangChain executor path"


def test_every_new_family_is_wired_into_the_runtime_tool_tuple():
    # Agreeing with each other is not enough: a family both paths define but ``bootstrap`` never
    # hands to the executor is a tool nobody can call. The LangChain tuple is built there, so that
    # is where the wiring has to be asserted.
    src = inspect.getsource(runtime.bootstrap)
    for builder in ("websocket_tools(", "browser_tools(", "research_tools(", "coverage_tools(", "artifact_tools("):
        assert builder in src, f"{builder} is not wired into runtime.bootstrap's tools tuple"
    # The SDK path receives its dependencies by keyword; without them it silently drops the family.
    for kwarg in ("artifacts=artifacts", "research=research", "browser=browser"):
        assert kwarg in src, f"{kwarg} is not threaded to the native-SDK executor"


# --------------------------------------------------------------------------- 2. schema parity
def test_websocket_and_browser_schemas_match_the_langchain_signatures(fake_client):
    # The SDK path calls ``fn(**args)`` against the declared schema. A schema key the coroutine has
    # no parameter for raises TypeError inside the model loop; a parameter the schema omits is one
    # the model is never told exists — an Origin header it cannot set is a CSWSH test that cannot
    # run, and reads as "no WebSocket issue here".
    lang = _langchain_tool_table(fake_client, _deps(fake_client))
    expected = {
        "ws_connect": WS_CONNECT_SCHEMA,
        "ws_replay": WS_REPLAY_SCHEMA,
        "browser_render": BROWSER_RENDER_SCHEMA,
        "browser_eval": BROWSER_EVAL_SCHEMA,
        "browser_probe_dom_xss": BROWSER_PROBE_DOM_XSS_SCHEMA,
    }
    for name, schema in expected.items():
        params = set(inspect.signature(lang[name].coroutine).parameters)
        assert set(schema) == params, f"{name}: SDK schema keys != LangChain parameters"


async def test_the_schemas_the_sdk_registers_are_those_same_schemas(monkeypatch, fake_client):
    # Asserting the constants agree with the coroutines proves nothing if the spec table registers a
    # different dict; compare against what ``run_sdk_agent`` actually handed the SDK.
    deps = _deps(fake_client)
    sdk = await _sdk_tool_table(monkeypatch, fake_client, deps=deps)
    lang = _langchain_tool_table(fake_client, deps)
    for name in NEW_ACTIVE_TOOLS:
        assert set(sdk[name].input_schema) == set(inspect.signature(lang[name].coroutine).parameters)


# --------------------------------------------------------------------------- 3. the active block
def test_the_new_traffic_generating_tools_are_listed_as_active():
    # ws_replay resends a captured authenticated channel with tampered content and
    # browser_probe_dom_xss navigates the target with a live payload: both are as active as a
    # replay. Omitting one here means an engagement that did NOT pre-authorise active exploitation
    # would still fire real payloads at the target.
    for name in NEW_ACTIVE_TOOLS:
        assert name in ACTIVE_TOOL_NAMES


async def test_the_active_block_actually_fires_on_the_sdk_path(monkeypatch, fake_client):
    # A name in a set nothing reads is the bug class this file exists for. The block lives in
    # ``sdk_agent._observe_tool``'s blocked-set check, so drive it: every active tool must refuse
    # BEFORE its body runs, with no traffic and no browser navigation.
    browser = _RecordingBrowser()
    deps = _deps(fake_client, browser=browser)
    sdk = await _sdk_tool_table(
        monkeypatch, fake_client, deps=deps, active_exploit_blocked=sorted(ACTIVE_TOOL_NAMES)
    )
    for name in NEW_ACTIVE_TOOLS:
        out = await sdk[name].handler(dict(ACTIVE_CALL_ARGS[name]))
        text = out["content"][0]["text"]
        assert text.startswith("BLOCKED"), f"{name} ran despite being blocked: {text[:120]}"
    assert browser.calls == [], "a blocked browser tool still navigated"
    assert fake_client.execs == [], "a blocked tool still drove the sandbox"


async def test_those_same_tools_do_run_when_active_exploitation_is_authorised(monkeypatch, fake_client):
    # The control for the test above: without it, a tool that failed for ANY reason (a typo'd
    # handler, a missing dependency) would satisfy "did not reach the target" and the block test
    # would pass while proving nothing.
    browser = _RecordingBrowser()
    deps = _deps(fake_client, browser=browser)
    sdk = await _sdk_tool_table(monkeypatch, fake_client, deps=deps, active_exploit_blocked=[])
    for name in ("browser_render", "browser_eval", "browser_probe_dom_xss"):
        out = await sdk[name].handler(dict(ACTIVE_CALL_ARGS[name]))
        assert "BLOCKED" not in out["content"][0]["text"]
    assert [c[0] for c in browser.calls] == ["render", "evaluate", "probe_dom_xss"]
    # ws_connect reaches its body too — proven without traffic by letting the scope guard refuse it.
    ws = await sdk["ws_connect"].handler({"url": "wss://evil.example.org/socket"})
    assert "out-of-scope" in ws["content"][0]["text"]
    assert fake_client.execs == []


# --------------------------------------------------------------------------- 4. refusal envelopes
async def test_websocket_refusal_envelope_is_field_for_field_the_toolcore_one(fake_client):
    # A second refusal shape means a second thing for the model (and the report) to understand, and
    # the model only has to mis-read one of them once to conclude the tool is broken rather than the
    # destination out of scope. Compared field by field against a real toolcore refusal, not by
    # eyeballing keys.
    guard = ScopeGuard(targets=["example.com"])
    ws = {s.name: s for s in build_ws_tool_specs(fake_client, guard=guard)}
    core = {s.name: s for s in build_tool_specs(fake_client, guard=guard)}
    ws_refusal = await ws["ws_connect"].fn(url="wss://evil.example.org/socket")
    core_refusal = await core["burpwn_exec"].fn(argv=["curl", "https://evil.example.org/"])
    assert set(ws_refusal) == set(core_refusal)
    # Everything but the message is identical; the message differs only by the ``where`` label.
    assert {k: v for k, v in ws_refusal.items() if k != "message"} == {
        k: v for k, v in core_refusal.items() if k != "message"
    }
    assert ws_refusal == guard.refusal(["evil.example.org"], "ws_connect url")
    assert fake_client.execs == []


async def test_ws_replay_refuses_with_the_same_envelope_before_reconnecting(fake_client):
    # ws_replay reads its destination out of a CAPTURED flow rather than from the model, so its
    # scope check runs after a req_show and on a URL nobody typed. That is its own chance to drift:
    # a flow captured before an `exclude` carve-out was applied must still be refused on replay.
    guard = ScopeGuard(targets=["example.com"])
    fake_client.all_flows = [
        {
            "id": 7,
            "scheme": "https",
            "request": {"authority": "evil.example.org", "path": "/socket", "headers": "Cookie: s=1"},
        }
    ]
    ws = {s.name: s for s in build_ws_tool_specs(fake_client, guard=guard)}
    core = {s.name: s for s in build_tool_specs(fake_client, guard=guard)}
    core_refusal = await core["burpwn_exec"].fn(argv=["curl", "https://evil.example.org/"])
    out = await ws["ws_replay"].fn(flow_id=7, message="x")
    assert out == guard.refusal(["evil.example.org"], "ws_replay url")
    assert {k: v for k, v in out.items() if k != "message"} == {
        k: v for k, v in core_refusal.items() if k != "message"
    }
    assert fake_client.execs == [], "the channel was re-established despite the refusal"


async def test_browser_driver_refuses_with_the_same_envelope(fake_client, tmp_path):
    # The browser is the easiest way to leave scope by accident, and its guard lives in
    # BrowserDriver rather than in a tool wrapper — a different code path, so a different chance to
    # drift. Its refusal is toolcore's, plus ``ok: False`` for the digest-shaped result.
    guard = ScopeGuard(targets=["example.com"])
    core = {s.name: s for s in build_tool_specs(fake_client, guard=guard)}
    core_refusal = await core["burpwn_exec"].fn(argv=["curl", "https://evil.example.org/"])
    driver = BrowserDriver(fake_client, work_dir=tmp_path, guard=guard)
    out = await driver.render("https://evil.example.org/")
    assert out["ok"] is False
    assert set(out) - {"ok"} == set(core_refusal)
    assert {k: v for k, v in out.items() if k not in {"ok", "message"}} == {
        k: v for k, v in core_refusal.items() if k != "message"
    }
    assert out == {"ok": False, **guard.refusal(["evil.example.org"], "browser")}
    assert fake_client.execs == [], "the browser was launched despite the refusal"


# --------------------------------------------------------------------------- 5. ToolSpec.active
def test_websocket_specs_declare_active_and_the_subgraph_picks_them_up(fake_client):
    # Two consumers read "is this tool active": the SDK block set and the executor prompt's
    # disclosure of what is forbidden. They must not drift apart — a tool blocked at the tool layer
    # but absent from the prompt burns turns on calls that can only ever refuse, and a tool named in
    # the prompt but not blocked is a promise nothing keeps.
    specs = build_ws_tool_specs(fake_client)
    assert [s.name for s in specs] == ["ws_connect", "ws_replay"]
    assert all(s.active is True for s in specs)
    for spec in specs:
        assert _is_active_tool(spec) is True

    tools = websocket_tools(fake_client, _engagement()) + browser_tools(_RecordingBrowser())
    gated = _active_tools(make_cfg(active=False), tools)
    assert set(gated) == set(NEW_ACTIVE_TOOLS)
    # ...and nothing is gated once the operator authorised active exploitation.
    assert _active_tools(make_cfg(active=True), tools) == []


# --------------------------------------------------------------------------- 6. descriptions
#: What each new tool's description MUST still say about the evidence/answer it hands back. These
#: are the sentences the model steers on: drop "captured_request_ids" from ws_connect and the agent
#: stops attaching flows to a WebSocket finding, which the oracle then rejects as unproven; drop
#: "LEAD, not a finding" from js_analyze/cve_lookup and a version string starts getting reported as
#: a vulnerability. A description is an interface, so it is asserted like one.
DESCRIPTION_MUST_MENTION = {
    "ws_connect": ("captured_request_ids", "handshake"),
    "ws_replay": ("CAPTURED", "prove"),
    "browser_render": ("captured_request_ids", "LEAD, not a finding"),
    "browser_eval": ("returning the result",),
    "browser_probe_dom_xss": ("marker_executed", "REFLECTION IS NOT EXECUTION"),
    "js_analyze": ("LEAD, not a finding",),
    "cve_lookup": ("LEAD",),
    "research_fetch": ("Refused",),
    "jwt_decode": ("without validating",),
    "record_probe": ("coverage matrix",),
    "artifact_grep": ("context",),
    "artifact_slice": ("offset",),
    "artifact_list": ("dropped",),
    "artifact_drop": ("reason",),
}


async def test_new_tool_descriptions_are_non_empty_and_still_state_their_evidence(monkeypatch, fake_client):
    deps = _deps(fake_client)
    sdk = await _sdk_tool_table(monkeypatch, fake_client, deps=deps)
    lang = _langchain_tool_table(fake_client, deps)
    for name, required in DESCRIPTION_MUST_MENTION.items():
        desc = sdk[name].description
        assert desc and desc.strip(), f"{name} has no model-facing description on the SDK path"
        # A floor, not a style rule: the shortest of these (artifact_list) is one full sentence,
        # and anything shorter is a description that stopped explaining the tool.
        assert len(desc) > 60, f"{name}'s description was gutted down to {len(desc)} chars"
        for token in required:
            assert token in desc, f"{name}'s description no longer mentions {token!r}"
        # Same words on both paths: a description edited on one path only is a model that behaves
        # differently depending on the backend, with nothing failing to say so.
        assert lang[name].description == desc, f"{name}: the two paths describe it differently"


def test_the_artifact_description_table_is_the_one_both_paths_read():
    # Same shared-constant argument as ``record_probe`` above: the artifact tools are declared once
    # as a table, and both adapters must iterate THAT table rather than re-listing the names.
    assert '"artifact_grep"' in inspect.getsource(sdk_agent.run_sdk_agent)
    assert "ARTIFACT_TOOL_SPECS" in inspect.getsource(sdk_agent.run_sdk_agent)
    assert {n for n, _d, _s in ARTIFACT_TOOL_SPECS} == set(NEW_TOOLS_BY_FAMILY["artifacts"])
