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

from a2pwn import sdk_agent
from a2pwn.config import EngagementSpec, IdentitySpec
from a2pwn.identity import IdentityStore
from a2pwn.models import Finding
from a2pwn.oracles import VerificationOracle
from a2pwn.scope import ScopeGuard
from a2pwn.toolcore import ACTIVE_TOOL_NAMES, build_tool_specs, tool_names
from a2pwn.tools import burpwn_tools
from a2pwn.tools.finding_tools import _ORACLES as LANGCHAIN_ORACLES


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
