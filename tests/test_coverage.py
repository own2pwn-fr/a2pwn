"""The coverage matrix: exhaustiveness as a data structure rather than as prose.

Before this module existed a run could stop, report zero findings, and be structurally unable to
say whether that meant "secure" or "never visited" — a probed-and-clean parameter and a parameter
no dispatch ever reached were the same empty space. These tests pin the four properties that make
the matrix trustworthy enough to answer that question:

* it is derived from CAPTURED TRAFFIC, not from the model's narration (``assets_from_flow``);
* it is BOUNDED — id-shaped path segments collapse, so a paginated site cannot explode the surface
  into ten thousand assets and drown the cells that matter;
* it is MONOTONE under a parallel `Send` fan-out (``record`` / ``merge_surface``), so a sibling
  dispatch that probed nothing cannot erase one that proved something;
* it cannot be SELF-CERTIFIED — a model calling ``record_probe`` can say "I tested this", never
  "I proved this"; only the deterministic oracle promotes a cell to ``proven``.

No model is contacted and no sandbox is opened here: every function under test is pure.
"""

from __future__ import annotations

import inspect
import json

from a2pwn.coverage import (
    _MAX_BODY_PARAMS,
    _RANK,
    ENDPOINT_CLASSES,
    HOST_CLASSES,
    PARAM_CLASSES,
    Asset,
    Probe,
    SurfaceMap,
    applicable_classes,
    assets_from_flow,
    coverage_digest,
    expand_coverage_tasks,
    harvest,
    merge_surface,
    needs_body_harvest,
    params_from_detail,
)
from a2pwn.graph import _harvest_surface
from a2pwn.tools.coverage_tools import PROBE_SCHEMA, build_probe, coverage_tools


def _flow(**over) -> dict:
    base = {"id": 1, "authority": "app.example.com", "path": "/", "method": "GET", "protocol": "http"}
    base.update(over)
    return base


def _kinds(assets: list[Asset]) -> list[str]:
    return [a.kind for a in assets]


# --------------------------------------------------------------------------- harvesting traffic
def test_a_query_flow_yields_host_endpoint_and_one_asset_per_parameter():
    """One captured request is three distinct testable things, and the matrix has to see all three:
    the origin (CORS, host-header), the endpoint (IDOR, CSRF) and each input sink (injection). A
    flow that collapsed to a single "endpoint" asset would silently drop the injection surface."""
    assets = assets_from_flow(_flow(path="/search?q=shoes&page=2"))

    assert _kinds(assets) == ["host", "endpoint", "param", "param"]
    assert [a.param for a in assets if a.kind == "param"] == ["q", "page"]
    assert all(a.location == "query" for a in assets if a.kind == "param")
    # Provenance is recorded so a disputed asset can be traced back to the flow that revealed it.
    assert {a.source for a in assets} == {"flow:1"}


def test_tracking_parameters_are_not_attack_surface():
    """utm_* / cache-busters are echoed by every analytics-instrumented page. Treating them as
    injectable inputs would spend twelve dispatch-classes each on parameters the application never
    reads, which is exactly the noise that makes a coverage report unreadable."""
    assets = assets_from_flow(_flow(path="/?utm_source=x&utm_medium=y&_=1699&cb=42&real=1"))

    assert [a.param for a in assets if a.kind == "param"] == ["real"]


def test_a_js_bundle_is_a_js_asset_and_never_an_endpoint():
    """A script is source to read for secrets and supply-chain risk, not a request handler. Filing
    it as an endpoint would queue seven server-side classes (IDOR, CSRF, race…) against a static
    file — dispatches that cannot ever produce a finding."""
    assets = assets_from_flow(_flow(path="/static/app.min.js?v=3"))

    assert _kinds(assets) == ["host", "js"]
    assert applicable_classes(assets[1]) == ("js-supplychain",)
    # the cache-busting query is not part of the asset's identity
    assert assets[1].path == "/static/app.min.js"


def test_a_graphql_path_gets_its_own_kind():
    """GraphQL is one endpoint hiding an entire API: introspection, batching and field-level
    authz have nothing to do with the REST checklist, so it must not be filed as a plain endpoint."""
    assets = assets_from_flow(_flow(path="/graphql", method="POST"))

    assert _kinds(assets) == ["host", "graphql"]
    assert applicable_classes(assets[1]) == ("graphql",)


def test_websocket_flows_yield_the_channel_and_the_host_only():
    assets = assets_from_flow(_flow(path="/socket", protocol="ws"))

    assert _kinds(assets) == ["host", "websocket"]


def test_non_http_protocols_yield_the_host_and_nothing_else():
    """DNS, raw TCP and a TLS pass-through carry no path or parameter surface. Deriving an
    "endpoint" from them would invent cells no HTTP-shaped class could ever test."""
    for protocol in ("dns", "rawtcp", "tls-passthru"):
        assets = assets_from_flow(_flow(path="/whatever", protocol=protocol))
        assert _kinds(assets) == ["host"], protocol


def test_a_flow_with_no_host_yields_nothing():
    # An asset keyed on an empty host would merge every hostless flow into one bogus origin.
    assert assets_from_flow({"id": 9, "path": "/x"}) == []


def test_numeric_id_segments_collapse_to_a_single_endpoint():
    """The bound on the whole structure: /order/42 and /order/99 are ONE handler with one set of
    applicable classes. Without this, a paginated catalogue turns into ten thousand assets, each
    with its own untested-cell fan-out, and the matrix becomes noise instead of a work-list."""
    a = assets_from_flow(_flow(id=1, path="/order/42"))
    b = assets_from_flow(_flow(id=2, path="/order/99"))

    assert [x.key for x in a] == [x.key for x in b]
    assert a[1].path == "/order/{id}"


def test_uuid_and_long_hex_segments_collapse_too():
    """Same bound, for the id shapes a modern API actually uses — a UUID per row would defeat the
    numeric check entirely."""
    uuid_flow = assets_from_flow(_flow(path="/users/550e8400-e29b-41d4-a716-446655440000/profile"))
    hex_flow = assets_from_flow(_flow(path="/users/deadbeefcafebabe0123/profile"))

    assert uuid_flow[1].path == "/users/{id}/profile"
    assert hex_flow[1].path == "/users/{id}/profile"
    assert uuid_flow[1].key == hex_flow[1].key


def test_harvest_skips_flows_at_or_below_the_cursor():
    """Harvesting is incremental because it runs every phase against the whole capture. Re-folding
    flow 1 on phase 20 is wasted work; the cursor is what keeps the cost flat as traffic grows."""
    surface = SurfaceMap(harvest_cursor=5)

    out = harvest(surface, [_flow(id=3, path="/old"), _flow(id=5, path="/boundary"), _flow(id=6, path="/new")])

    paths = {a.path for a in out.assets.values() if a.kind == "endpoint"}
    assert paths == {"/new"}  # 3 is below and 5 is AT the cursor: both already folded in


def test_harvest_advances_the_cursor_to_the_highest_id_seen():
    out = harvest(SurfaceMap(), [_flow(id=4, path="/a"), _flow(id=7, path="/b"), _flow(id=11, path="/c")])

    assert out.harvest_cursor == 11
    assert {a.path for a in out.assets.values() if a.kind == "endpoint"} == {"/a", "/b", "/c"}


def test_harvest_does_not_mutate_the_map_it_was_given():
    # `harvest` is called on state the master still holds; folding in place would mean a failed
    # phase left a half-updated matrix behind.
    before = SurfaceMap()
    harvest(before, [_flow(id=1, path="/x")])

    assert before.assets == {}
    assert before.harvest_cursor == 0


# --------------------------------------------------------------------------- monotone verdicts
def _cell(verdict: str, key: str = "endpoint|h|/x|GET|") -> Probe:
    return Probe(asset_key=key, vuln_class="sqli", verdict=verdict)  # type: ignore[arg-type]


def test_verdict_ranking_is_the_documented_order():
    """The whole monotonicity argument rests on this ordering, so it is asserted directly rather
    than inferred: knowing nothing < knowing it does not apply < being blocked < having tested it
    < having proven it."""
    assert (
        _RANK["untested"] < _RANK["not_applicable"] < _RANK["blocked"] < _RANK["probed"] < _RANK["proven"]
    )


def test_a_probed_cell_can_never_be_demoted_back_to_untested():
    """The property that makes the matrix a ledger rather than a scratchpad: a later dispatch
    reporting nothing about a cell must not erase what an earlier one established, or the run
    re-dispatches work it already did and never converges."""
    surface = SurfaceMap()
    surface.record(_cell("probed"))
    surface.record(_cell("untested"))

    assert surface.verdict_of("endpoint|h|/x|GET|", "sqli") == "probed"


def test_proven_outranks_everything_and_nothing_outranks_proven():
    """`proven` is written by the oracle, so it must survive any subsequent claim — including a
    sibling dispatch that hit a WAF on the same cell and would otherwise mark it `blocked`."""
    for weaker in ("untested", "not_applicable", "blocked", "probed"):
        surface = SurfaceMap()
        surface.record(_cell("proven"))
        surface.record(_cell(weaker))
        assert surface.verdict_of("endpoint|h|/x|GET|", "sqli") == "proven", weaker

        surface = SurfaceMap()
        surface.record(_cell(weaker))
        surface.record(_cell("proven"))
        assert surface.verdict_of("endpoint|h|/x|GET|", "sqli") == "proven", weaker


def test_record_is_monotone_for_every_verdict_pair():
    """Order-independence over the whole lattice: whichever of two dispatches lands first, the
    surviving verdict is the more informative one. This is what lets the reducer run on a fan-out
    whose completion order is not deterministic."""
    ranked = sorted(_RANK, key=lambda v: _RANK[v])
    for i, low in enumerate(ranked):
        for high in ranked[i + 1 :]:
            forward, backward = SurfaceMap(), SurfaceMap()
            forward.record(_cell(low))
            forward.record(_cell(high))
            backward.record(_cell(high))
            backward.record(_cell(low))
            assert forward.verdict_of("endpoint|h|/x|GET|", "sqli") == high
            assert backward.verdict_of("endpoint|h|/x|GET|", "sqli") == high


# --------------------------------------------------------------------------- the reducer
def _map_with(asset: Asset, probe: Probe | None = None, cursor: int = 0) -> SurfaceMap:
    surface = SurfaceMap(harvest_cursor=cursor)
    surface.add_asset(asset)
    if probe is not None:
        surface.record(probe)
    return surface


def test_merge_keeps_assets_discovered_by_both_branches():
    """Two dispatches in the same phase each discover surface the other never saw. A last-writer
    reducer would throw one side away and the engagement would never revisit it."""
    left = _map_with(Asset(kind="endpoint", host="a.example.com", path="/one", method="GET"))
    right = _map_with(Asset(kind="endpoint", host="b.example.com", path="/two", method="GET"))

    merged = merge_surface(left, right)

    assert set(merged.assets) == set(left.assets) | set(right.assets)


def test_merge_keeps_the_higher_verdict_for_a_cell_both_branches_touched():
    asset = Asset(kind="endpoint", host="a.example.com", path="/one", method="GET")
    weak = _map_with(asset, _cell("probed", asset.key))
    strong = _map_with(asset, _cell("proven", asset.key))

    assert merge_surface(weak, strong).verdict_of(asset.key, "sqli") == "proven"
    # …and symmetrically: the fan-out's completion order must not decide what is known.
    assert merge_surface(strong, weak).verdict_of(asset.key, "sqli") == "proven"


def test_merge_does_not_mutate_either_input():
    """The reducer runs against shared graph state that other branches still hold references to.
    Mutating an operand would let one branch's merge corrupt what a concurrent branch reads —
    the same aliasing class of bug that made a delta's default budget caps overwrite the real
    ones in a parallel `Send` fan-out."""
    asset_l = Asset(kind="endpoint", host="a.example.com", path="/one", method="GET")
    asset_r = Asset(kind="endpoint", host="b.example.com", path="/two", method="GET")
    left = _map_with(asset_l, _cell("probed", asset_l.key), cursor=3)
    right = _map_with(asset_r, _cell("proven", asset_l.key), cursor=9)
    left_before, right_before = left.model_dump(), right.model_dump()

    merge_surface(left, right)

    assert left.model_dump() == left_before
    assert right.model_dump() == right_before


def test_merge_takes_the_furthest_harvest_cursor():
    # Rewinding the cursor would make the next harvest re-fold flows already in the matrix.
    asset = Asset(kind="host", host="a.example.com")
    assert merge_surface(_map_with(asset, cursor=9), _map_with(asset, cursor=3)).harvest_cursor == 9
    assert merge_surface(_map_with(asset, cursor=3), _map_with(asset, cursor=9)).harvest_cursor == 9


def test_merge_tolerates_a_missing_side_and_still_copies():
    """LangGraph calls a reducer with `None` on the first write to the channel; it must not blow
    up, and it must not hand back the caller's own object as the new channel value."""
    surface = _map_with(Asset(kind="host", host="a.example.com"), cursor=2)

    assert merge_surface(None, None).assets == {}
    for merged in (merge_surface(None, surface), merge_surface(surface, None)):
        assert set(merged.assets) == set(surface.assets)
        assert merged.harvest_cursor == 2
        assert merged is not surface


# --------------------------------------------------------------------------- work-list & stats
def test_untested_is_exactly_the_applicability_matrix_when_nothing_has_been_probed():
    """`untested()` IS the work-list the planner is handed when it runs dry, so it has to be the
    full cross product — a class missing here is a class the engagement will never test."""
    surface = SurfaceMap()
    for asset in assets_from_flow(_flow(path="/search?q=1")):
        surface.add_asset(asset)

    cells = surface.untested()

    assert len(cells) == len(HOST_CLASSES) + len(ENDPOINT_CLASSES) + len(PARAM_CLASSES)
    assert {c for a, c in cells if a.kind == "param"} == set(PARAM_CLASSES)


def test_any_verdict_at_all_takes_a_cell_out_of_the_work_list():
    """`not_applicable` and `blocked` are answers too. If only `probed` cleared the queue, a class
    that genuinely cannot apply here would be re-dispatched forever and starve real work."""
    asset = Asset(kind="host", host="a.example.com")
    for verdict in ("probed", "not_applicable", "blocked", "proven"):
        surface = _map_with(asset)
        surface.record(Probe(asset_key=asset.key, vuln_class="cors", verdict=verdict))  # type: ignore[arg-type]
        assert "cors" not in {c for _, c in surface.untested()}, verdict


def test_stats_counts_agree_with_the_matrix():
    asset = Asset(kind="host", host="a.example.com")
    surface = _map_with(asset)
    surface.record(Probe(asset_key=asset.key, vuln_class="cors", verdict="probed"))

    st = surface.stats()

    assert st["assets"] == 1
    assert st["assets_by_kind"] == {"host": 1}
    assert st["cells"] == len(HOST_CLASSES)
    assert st["untested"] == len(HOST_CLASSES) - 1 == len(surface.untested())
    assert st["by_verdict"] == {"untested": len(HOST_CLASSES) - 1, "probed": 1}
    assert st["covered_pct"] == round(100.0 / len(HOST_CLASSES), 1)


def test_stats_on_an_empty_surface_does_not_divide_by_zero():
    # `stats` feeds the digest on every planning phase, including the very first one.
    assert SurfaceMap().stats() == {
        "assets": 0,
        "assets_by_kind": {},
        "cells": 0,
        "by_verdict": {},
        "untested": 0,
        "covered_pct": 0.0,
    }


# --------------------------------------------------------------------------- deterministic planning
def _three_kind_surface() -> SurfaceMap:
    """Host + endpoint + param, inserted in reverse priority order so the ordering assertion is
    testing the sort and not the insertion order."""
    surface = SurfaceMap()
    for asset in reversed(assets_from_flow(_flow(path="/search?q=1"))):
        surface.add_asset(asset)
    return surface


def test_expand_groups_several_classes_into_one_dispatch():
    """A hundred untested cells must become a handful of tasks, not a hundred dispatches: the
    budget is counted in dispatches and one class per dispatch would exhaust it during recon."""
    tasks = expand_coverage_tasks(_three_kind_surface(), limit=20)

    first = tasks[0]
    classes = [h for h in first.hints if h.startswith("classes=")][0].removeprefix("classes=")
    assert classes.split(", ") == list(HOST_CLASSES[:4])
    # every host class is eventually emitted, just spread across chunked tasks
    emitted = [
        c
        for t in tasks
        for h in t.hints
        if h.startswith("classes=")
        for c in h.removeprefix("classes=").split(", ")
    ]
    assert set(HOST_CLASSES) <= set(emitted)


def test_expand_orders_hosts_before_endpoints_before_params():
    """Recon-shaped work first: fingerprinting and content discovery on the origin usually reveal
    more surface, and doing it after the injection sweep means fuzzing a surface still unknown."""
    tasks = expand_coverage_tasks(_three_kind_surface(), limit=20)
    kinds = [h.removeprefix("coverage-cell=").split("|")[0] for t in tasks for h in t.hints if "|" in h]

    assert kinds == sorted(kinds, key=["host", "endpoint", "param"].index)
    assert kinds[0] == "host" and kinds[-1] == "param"


def test_expand_hints_carry_the_cell_key_and_the_classes():
    """The hints are how a dispatch's `record_probe` calls find their way back to the right cell.
    A task without them can only be attributed by guesswork."""
    tasks = expand_coverage_tasks(_three_kind_surface(), limit=20)

    for task in tasks:
        cell = [h for h in task.hints if h.startswith("coverage-cell=")]
        classes = [h for h in task.hints if h.startswith("classes=")]
        assert len(cell) == 1 and len(classes) == 1
        assert cell[0].removeprefix("coverage-cell=") in _three_kind_surface().assets


def test_only_parameter_sweeps_are_marked_as_mutating():
    """`mutates` serialises a task against its siblings. Host and endpoint probes are read-mostly,
    so marking them mutating would collapse the whole fan-out to one dispatch per phase for no
    safety gain; parameter injection actually sends payloads and must stay serialised."""
    tasks = expand_coverage_tasks(_three_kind_surface(), limit=20)
    by_kind = {
        h.removeprefix("coverage-cell=").split("|")[0]: t.mutates
        for t in tasks
        for h in t.hints
        if h.startswith("coverage-cell=")
    }

    assert by_kind == {"host": False, "endpoint": False, "param": True}


def test_expand_respects_the_limit_and_refuses_to_run_at_all_at_zero():
    """The limit is the batch width the budget allows. Overshooting it would queue work the phase
    cannot dispatch, and `limit=0` (a spent budget) must produce nothing rather than one 'free' task."""
    surface = _three_kind_surface()

    assert len(expand_coverage_tasks(surface, limit=3)) == 3
    assert expand_coverage_tasks(surface, limit=0) == []
    assert expand_coverage_tasks(surface, limit=-1) == []


def test_expand_on_an_empty_surface_yields_no_work():
    # Before any traffic is captured there is nothing to sweep; inventing tasks here would send
    # the executor at a surface nobody has confirmed exists.
    assert expand_coverage_tasks(SurfaceMap(), limit=6) == []


def test_expand_intents_split_recon_from_exploitation():
    tasks = expand_coverage_tasks(_three_kind_surface(), limit=20)

    assert tasks[0].intent == "recon"  # tech-fingerprint / content-discovery chunk
    assert {t.intent for t in tasks[1:]} == {"exploit"}


# --------------------------------------------------------------------------- the digest
def test_digest_truncates_and_says_how_much_it_left_out():
    """The digest rides in the planner's context alongside history and findings. An untruncated
    matrix dump would push the things it is meant to inform out of the window — but silently
    truncating would let the planner believe it had seen the whole remainder."""
    digest = coverage_digest(_three_kind_surface(), max_lines=2)

    assert "UNTESTED (asset -> classes):" in digest
    assert digest.rstrip().endswith("… and 1 more asset(s)")
    assert len([ln for ln in digest.splitlines() if ln.startswith("  ") and "->" in ln]) == 2


def test_digest_states_the_none_case_explicitly():
    """When everything has a verdict the digest must SAY so. An empty UNTESTED section reads
    identically to a surface nobody has mapped, and that ambiguity is the exact failure this
    module exists to remove."""
    asset = Asset(kind="host", host="a.example.com")
    surface = _map_with(asset)
    for vuln_class in HOST_CLASSES:
        surface.record(Probe(asset_key=asset.key, vuln_class=vuln_class, verdict="probed"))

    digest = coverage_digest(surface)

    assert "UNTESTED: none — every applicable class has a verdict on every known asset." in digest
    assert "covered=100.0%" in digest


def test_digest_reports_the_inventory_up_front():
    digest = coverage_digest(_three_kind_surface())

    assert digest.splitlines()[0] == "assets=3 (endpoint:1, host:1, param:1)"
    assert "untested=" in digest.splitlines()[1]


# --------------------------------------------------------------------------- record_probe rows
def test_build_probe_normalises_host_and_method_casing():
    """The key is the join between a model-typed declaration and traffic-derived assets. If
    `APP.Example.com` and `app.example.com` key differently, the declaration lands on a phantom
    cell and the real one stays untested — a silently lost negative result."""
    probe = build_probe(
        {"asset_kind": "ENDPOINT", "host": "APP.Example.com ", "path": "/x", "method": "post",
         "vuln_class": "sqli"}
    )

    assert probe is not None
    assert probe.asset_key == "endpoint|app.example.com|/x|POST|"
    assert probe.asset_key == Asset(kind="endpoint", host="app.example.com", path="/x", method="POST").key


def test_build_probe_rejects_a_row_that_identifies_nothing():
    """A probe with no host or no class cannot be attributed to a cell. Storing it anyway would
    inflate the coverage percentage with rows that cover nothing."""
    assert build_probe({"host": "", "vuln_class": "sqli"}) is None
    assert build_probe({"host": "app.example.com", "vuln_class": " "}) is None
    assert build_probe({}) is None


def test_a_model_claiming_proven_is_downgraded_to_probed():
    """THE anti-self-certification property. `proven` is what the deterministic oracle writes after
    a candidate reproduced with captured evidence; if the executor could set it by calling a tool,
    a model could talk the matrix to 100% covered and the report would repeat the claim. The tool
    can say "I tested this" — only the oracle can say "this is real"."""
    probe = build_probe({"host": "app.example.com", "vuln_class": "sqli", "verdict": "proven"})

    assert probe is not None
    assert probe.verdict == "probed"


def test_an_unknown_verdict_falls_back_to_probed_rather_than_being_dropped():
    # Fail-soft on the LOW side only: a typo'd verdict still records that the cell was worked on,
    # and never records more than the strongest verdict the tool is allowed to write.
    for claimed in ("PROBED", "definitely-vulnerable", "", "untested"):
        probe = build_probe({"host": "h", "vuln_class": "xss", "verdict": claimed})
        assert probe is not None
        assert probe.verdict == "probed", claimed


def test_the_three_declarable_verdicts_survive_intact():
    """`not_applicable` and `blocked` carry real information — the second one especially: a class
    a WAF stopped us from testing must not read as a class we tested and cleared."""
    for claimed in ("probed", "not_applicable", "blocked"):
        probe = build_probe({"host": "h", "vuln_class": "xss", "verdict": claimed.upper()})
        assert probe is not None
        assert probe.verdict == claimed


def test_build_probe_threads_dispatch_and_evidence_for_attribution():
    """A `probed` verdict with a flow id is a claim the capture can be held against; without one it
    is only the model's word about its own work, which is why the flow is carried at all."""
    probe = build_probe(
        {"host": "h", "vuln_class": "xss", "evidence_flow": "42", "note": "n" * 900}, "d-7"
    )

    assert probe is not None
    assert probe.evidence_flow == 42 and probe.dispatch_id == "d-7"
    assert len(probe.note) == 400  # notes are truncated: the matrix is a ledger, not a transcript
    # a missing / zero flow is recorded as absent rather than as flow 0
    assert build_probe({"host": "h", "vuln_class": "xss", "evidence_flow": 0}).evidence_flow is None
    assert build_probe({"host": "h", "vuln_class": "xss", "evidence_flow": "nope"}).evidence_flow is None


async def test_the_langchain_tool_returns_the_probe_as_an_artifact():
    """`record_probe` is `content_and_artifact`: the text is for the model, the Probe list is what
    `subgraph._harvest` folds into the matrix. A tool returning only prose would look like it
    worked while recording nothing."""
    tool = {t.name: t for t in coverage_tools("d-1")}["record_probe"]

    message, probes = await tool.coroutine(
        asset_kind="param", host="App.Example.com", vuln_class="sqli", verdict="proven", param="q"
    )

    assert [p.verdict for p in probes] == ["probed"]  # downgrade holds on the tool path too
    assert probes[0].dispatch_id == "d-1"
    assert "sqli" in message and "probed" in message

    refused, empty = await tool.coroutine(asset_kind="param", host="", vuln_class="sqli")
    assert empty == [] and "host and vuln_class" in refused


def test_probe_schema_matches_the_langchain_signature():
    """Local parity guard (the cross-path one lives in test_tool_parity): the SDK path calls
    `build_probe` with a dict keyed by PROBE_SCHEMA, so a key with no matching argument on the
    LangChain wrapper means the two executors record different rows for the same declaration."""
    tool = {t.name: t for t in coverage_tools()}["record_probe"]

    assert set(PROBE_SCHEMA) == set(inspect.signature(tool.coroutine).parameters)


# =========================================================================== regressions
# Everything below pins a defect that actually shipped in this module. Each docstring states what
# broke and what the breakage cost, because the failure mode of a coverage matrix is never a crash
# — it is a run that reports a high covered% over a surface it never enumerated.


def test_harvest_folds_the_whole_batch_whatever_order_the_flows_arrive_in():
    """The cursor advances ONCE, after the batch — not inside the loop.

    Advancing it per-flow made the result depend on input order: burpwn's proxy history comes back
    newest-first, so the very first flow pushed the cursor past every remaining id and the rest of
    the batch was skipped as 'already folded'. One endpoint entered the matrix per phase out of a
    capture holding hundreds, and because the survivors looked ordinary the digest read as a small
    but healthy surface rather than as a broken harvest."""
    descending = [_flow(id=9, path="/c"), _flow(id=8, path="/b"), _flow(id=7, path="/a")]

    out = harvest(SurfaceMap(), descending)

    assert {a.path for a in out.assets.values() if a.kind == "endpoint"} == {"/a", "/b", "/c"}
    assert out.harvest_cursor == 9
    # The invariant is order-independence, not merely "descending happens to work".
    ascending = harvest(SurfaceMap(), list(reversed(descending)))
    assert set(out.assets) == set(ascending.assets)
    assert ascending.harvest_cursor == out.harvest_cursor


def _detail(body, *, method: str = "POST", headers: str = "content-type: application/json", **over) -> dict:
    detail = {
        "id": 5,
        "request": {
            "authority": "api.example.com",
            "path": "/v1/orders",
            "method": method,
            "headers": headers,
            "body": body,
        },
    }
    detail.update(over)
    return detail


def test_a_json_body_yields_dotted_parameter_names_including_nested_and_list_elements():
    """Body parameters are attack surface the flow LISTING cannot see.

    Only the query string is visible without a `req_show`, and a JSON API keeps every one of its
    injection sinks in the body. Harvesting query strings alone gave an API-shaped target host and
    endpoint cells and *zero* param cells — so the twelve injection classes were never applicable
    to anything, and the matrix reported full coverage of a surface whose actual input sinks had
    never been enumerated. Nesting matters as much: `user.email` and `items[].sku` are distinct
    sinks, and flattening to the top-level keys alone would hide them behind `user` and `items`."""
    body = json.dumps({"user": {"email": "a@b.c", "id": 1}, "items": [{"sku": "X", "qty": 2}]})

    assets = params_from_detail(_detail(body))
    names = [a.param for a in assets]

    assert "user.email" in names and "user.id" in names
    assert "items[].sku" in names and "items[].qty" in names
    assert {"user", "items"} <= set(names)  # the containers are sinks too (mass assignment)
    assert all(a.location == "json" for a in assets)
    assert all(a.kind == "param" and a.method == "POST" for a in assets)
    assert applicable_classes(assets[0]) == PARAM_CLASSES


def test_a_form_encoded_body_is_located_as_body_not_as_json():
    """`location` decides which sinks a parameter can plausibly reach and is echoed into the task
    text the sub-agent is handed. Calling a form field `json` sends the executor at the wrong
    serialisation and its payloads land as literal strings in a field the app never parses."""
    assets = params_from_detail(
        _detail("user=alice&next=/admin", headers="content-type: application/x-www-form-urlencoded")
    )

    assert [(a.param, a.location) for a in assets] == [("user", "body"), ("next", "body")]


def test_a_bodyless_detail_yields_no_parameters_at_all():
    """A GET (or an empty body) has nothing to enumerate. Synthesising param assets from it would
    fabricate cells no dispatch can ever clear, and untested cells that cannot be tested are how a
    work-list stops converging."""
    assert params_from_detail(_detail("", method="GET")) == []
    assert params_from_detail(_detail(None, method="GET")) == []
    assert params_from_detail({"request": {"path": "/x", "method": "POST"}}) == []
    # …and a body with no host: an asset keyed on an empty host merges every such flow into one
    # bogus origin, exactly as for `assets_from_flow`.
    assert params_from_detail({"id": 5, "request": {"authority": "", "method": "POST", "body": "a=1"}}) == []


def test_body_parameter_harvest_is_capped_per_flow():
    """The bound that keeps one chatty request from owning the matrix: a document-shaped JSON body
    with hundreds of keys would otherwise contribute hundreds of assets × twelve injection classes,
    burying every other untested cell in the digest the planner actually reads."""
    body = json.dumps({f"field{i}": i for i in range(_MAX_BODY_PARAMS * 3)})

    assert len(params_from_detail(_detail(body))) == _MAX_BODY_PARAMS


def test_only_body_bearing_methods_are_worth_paying_a_req_show_for():
    """`needs_body_harvest` is the filter in front of an extra burpwn round-trip per flow. Firing
    it on GETs doubles the harvest cost of an ordinary browse for nothing; missing PUT/PATCH/DELETE
    loses the bodies of exactly the API verbs where mass-assignment and IDOR sinks live."""
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        assert needs_body_harvest({"method": method}), method
        assert needs_body_harvest({"method": method.lower()}), method
    for method in ("GET", "HEAD", "OPTIONS", "TRACE", "", None):
        assert not needs_body_harvest({"method": method}), method


class _FakeBurpwn:
    """Just enough of `BurpwnClient` for `_harvest_surface`: a listing plus per-flow details."""

    def __init__(self, flows: list[dict], details: dict[int, dict]):
        self._flows = flows
        self._details = details
        self.shown: list[int] = []

    async def req_list(self, limit: int = 0) -> dict:
        return {"flows": list(self._flows)}

    async def req_show(self, fid: int) -> dict:
        self.shown.append(fid)
        return self._details[fid]


async def test_the_graph_harvest_pays_for_bodies_only_on_new_body_bearing_flows():
    """The wiring of the two halves: `_harvest_surface` folds the listing AND enumerates bodies.

    It has to do both in one pass or the JSON sinks never reach the matrix — and it has to be
    selective, because one `req_show` per flow on a capture of thousands turns coverage bookkeeping
    into the dominant cost of the run."""
    body = json.dumps({"user": {"email": "a@b.c"}})
    flows = [_flow(id=1, path="/search?q=1"), _flow(id=2, path="/v1/orders", method="POST")]
    client = _FakeBurpwn(
        flows,
        {
            2: {
                "id": 2,
                "request": {
                    "authority": "app.example.com",
                    "path": "/v1/orders",
                    "method": "POST",
                    "headers": "content-type: application/json",
                    "body": body,
                },
            }
        },
    )

    out = await _harvest_surface(client, SurfaceMap())

    assert client.shown == [2]  # the GET cost nothing extra
    params = {(a.param, a.location) for a in out.assets.values() if a.kind == "param"}
    assert ("q", "query") in params
    assert ("user.email", "json") in params
    assert out.harvest_cursor == 2


def test_a_normalised_asset_still_carries_a_concrete_requestable_url():
    """`path` is the normalised matrix KEY (`/order/{id}`); `example_url` is a real sighting.

    Building the task target out of the key handed the sub-agent `https://host/order/{id}` — an
    address no HTTP client can resolve and the scope guard refuses. The dispatch burned budget
    failing to connect, reported nothing, and the cell stayed untested and got re-queued."""
    out = harvest(SurfaceMap(), [_flow(id=3, path="/order/42?ref=1")])
    endpoint = next(a for a in out.assets.values() if a.kind == "endpoint")

    assert endpoint.path == "/order/{id}"  # normalised, so /order/43 is the same handler
    assert endpoint.example_url == "https://app.example.com/order/42?ref=1"

    tasks = expand_coverage_tasks(out, limit=30)

    assert any(t.target == "https://app.example.com/order/42?ref=1" for t in tasks)
    for task in tasks:
        # The placeholder may live in the `coverage-cell=` hint (it IS the key); it must never
        # reach an address or the prose the executor is asked to act on.
        assert "{" not in task.target and "}" not in task.target, task.target
        assert "{" not in task.task and "}" not in task.task, task.task


def test_the_captured_scheme_is_carried_into_every_url_rather_than_assumed_https():
    """URLs used to be hardcoded to `https://`. A plain-HTTP target — an internal app, a staging
    box, an admin panel on a non-TLS port — got a whole coverage sweep aimed at a port that does
    not speak TLS. Every dispatch failed to connect, so no cell ever left `untested` and the run
    re-planned the same unreachable work until the budget ran out."""
    assets = assets_from_flow(_flow(path="/login?next=/", method="POST", scheme="http"))

    assert [a.example_url for a in assets] == [
        "http://app.example.com",
        "http://app.example.com/login?next=/",
        "http://app.example.com/login?next=/",
    ]
    # …and on the paths that return early, where a hardcoded scheme is easiest to miss.
    assert assets_from_flow(_flow(path="/app.js", scheme="http"))[1].example_url == "http://app.example.com/app.js"
    ws = assets_from_flow(_flow(path="/live", protocol="ws", scheme="http"))
    assert ws[1].example_url == "http://app.example.com/live"
    body_asset = params_from_detail(_detail("a=1", headers="", scheme="http"))[0]
    assert body_asset.example_url == "http://api.example.com/v1/orders"


def test_merge_deep_copies_so_the_channel_never_aliases_an_operand():
    """The merged map is what the `surface` channel holds. Inserting `right`'s own pydantic objects
    by reference left committed state aliasing a branch that still owns those objects, so a later
    mutation on that branch silently rewrote the matrix after the fact — the same aliasing shape as
    the budget-caps bug, where a delta's default caps overwrote the real ones under a `Send`
    fan-out and produced an infinite loop."""
    asset = Asset(kind="endpoint", host="a.example.com", path="/one", method="GET", note="first")
    probe = Probe(asset_key=asset.key, vuln_class="sqli", verdict="probed", note="clean")
    right = _map_with(asset, probe, cursor=4)
    merged = [
        merge_surface(SurfaceMap(), right),  # ordinary two-sided merge
        merge_surface(None, right),  # LangGraph's first write to the channel
        merge_surface(right, None),  # …and the mirror of it
    ]

    right.assets[asset.key].note = "MUTATED"
    right.probes[probe.key].verdict = "proven"

    for out in merged:
        assert out.assets[asset.key].note == "first"
        assert out.probes[probe.key].verdict == "probed"
        assert out.assets[asset.key] is not right.assets[asset.key]
        assert out.probes[probe.key] is not right.probes[probe.key]


def test_the_digest_groups_remaining_classes_by_asset_key_not_by_label():
    """Labels collide across kinds: a websocket channel and a GET endpoint on the same host+path
    both render as `GET host/path`. Grouping by label merged their remaining classes onto one line,
    so the planner's ONLY view of the matrix showed websocket work filed under an endpoint and one
    of the two assets disappeared from the remainder entirely — an asset the digest says nothing
    about is an asset the planner will not ask for."""
    ws = Asset(kind="websocket", host="app.example.com", path="/live")
    endpoint = Asset(kind="endpoint", host="app.example.com", path="/live", method="GET")
    assert ws.label() == endpoint.label()  # the collision the grouping has to survive
    surface = SurfaceMap()
    surface.add_asset(ws)
    surface.add_asset(endpoint)

    rows = [ln for ln in coverage_digest(surface).splitlines() if ln.startswith("  ") and "->" in ln]

    assert len(rows) == 2
    assert any(r.endswith("-> websocket") for r in rows)
    assert any("access-control" in r for r in rows)


def test_graphql_detection_is_anchored_to_a_whole_path_segment():
    """A substring match filed `/graphql-docs` (a documentation page) and `/lang/gql-tutorial` (an
    article) as GraphQL assets. That is not a cosmetic mislabel: a `graphql` asset has exactly one
    applicable class, so the swap REPLACED seven endpoint classes — access-control, IDOR, CSRF,
    race, mass-assignment, business-logic, file-upload — with one, and the endpoint counted as
    fully covered without ever being tested for anything it could actually be vulnerable to."""
    for path in ("/graphql", "/graphql/", "/api/gql", "/v2/graphql"):
        asset = assets_from_flow(_flow(path=path, method="POST"))[1]
        assert asset.kind == "graphql", path
        assert applicable_classes(asset) == ("graphql",), path

    for path in ("/graphql-docs", "/lang/gql-tutorial", "/graphqlish", "/mygql"):
        asset = assets_from_flow(_flow(path=path, method="POST"))[1]
        assert asset.kind == "endpoint", path
        assert applicable_classes(asset) == ENDPOINT_CLASSES, path
