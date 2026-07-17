"""Oracle semantics: differential / two_identity / oob (+ marker, timing, signature,
run_oracle dispatch) exercised against a fake burpwn client and a fake collaborator."""

from a2pwn.collaborator import OOBHit
from a2pwn.oracles import (
    OracleResult,
    VerificationOracle,
    differential,
    marker,
    oob,
    run_oracle,
    signature,
    timing_blind,
    two_identity,
)


class FakeClient:
    """Canned-response stand-in for BurpwnClient. Each accessor returns a preset dict
    shaped exactly like the real MCP handler output."""

    def __init__(self, *, compare_out=None, search_out=None, fuzz_out=None, show_out=None):
        self._compare = compare_out
        self._search = search_out
        self._fuzz = fuzz_out
        self._show = show_out
        self.calls: list[tuple] = []

    async def compare(self, flow_a, flow_b, what="all"):
        self.calls.append(("compare", flow_a, flow_b, what))
        return self._compare

    async def req_search(self, query):
        self.calls.append(("req_search", query))
        return self._search

    async def fuzz_results(self, attack_id, sort="anomaly"):
        self.calls.append(("fuzz_results", attack_id, sort))
        return self._fuzz

    async def req_show(self, id, raw=False):
        self.calls.append(("req_show", id, raw))
        return self._show


class FakeCollaborator:
    def __init__(self, hits):
        self._hits = hits
        self.calls: list[tuple] = []

    async def poll(self, correlation_id, timeout_secs=30, protocols=("dns", "http", "rawtcp")):
        self.calls.append((correlation_id, timeout_secs, protocols))
        return self._hits


def _compare(status_a, status_b, *, identical, reflected=None, only_in_b=None, len_a=10, len_b=10):
    return {
        "flow_a": 1,
        "flow_b": 2,
        "status": {"a": status_a, "b": status_b, "changed": status_a != status_b},
        "body": {
            "identical": identical,
            "len_a": len_a,
            "len_b": len_b,
            "only_in_a": [],
            "only_in_b": only_in_b or [],
            "reflected": reflected or [],
        },
    }


# --- differential ---------------------------------------------------------------


async def test_differential_reflection_confirms():
    client = FakeClient(compare_out=_compare(200, 200, identical=False, reflected=["injecthere"]))
    res = await differential(client, 1, 2, {"signal": "reflection"})
    assert res.confirmed is True
    assert res.kind == "differential"
    assert res.flow_ids == [1, 2]
    assert "injecthere" in res.evidence


async def test_differential_reflection_marker_mismatch_rejects():
    client = FakeClient(compare_out=_compare(200, 200, identical=False, reflected=["injecthere"]))
    res = await differential(client, 1, 2, {"signal": "reflection", "marker": "not-present"})
    assert res.confirmed is False


async def test_differential_no_delta_rejects():
    client = FakeClient(compare_out=_compare(200, 200, identical=True, len_a=42, len_b=42))
    res = await differential(client, 1, 2, {"signal": "any"})
    assert res.confirmed is False


async def test_differential_status_change_confirms():
    client = FakeClient(compare_out=_compare(200, 500, identical=True))
    res = await differential(client, 1, 2, {"signal": "status_change"})
    assert res.confirmed is True


async def test_differential_any_signal_needs_body_and_length():
    # body changed + length delta present => 'any' confirms
    client = FakeClient(compare_out=_compare(200, 200, identical=False, len_a=10, len_b=90))
    res = await differential(client, 1, 2, {})
    assert res.confirmed is True


# --- two_identity (IDOR / BOLA / broken access control) -------------------------


async def test_two_identity_reproduces_victim_object_confirms():
    # A-authed cross access returns byte-identical victim object => confirmed
    client = FakeClient(compare_out=_compare(200, 200, identical=True))
    res = await two_identity(client, 5, 6)
    assert res.confirmed is True
    assert res.kind == "two_identity"
    assert res.flow_ids == [5, 6]


async def test_two_identity_superset_confirms():
    # not byte-identical but attacker response contains every victim line (only_in_b empty)
    client = FakeClient(
        compare_out=_compare(200, 200, identical=False, only_in_b=[], len_a=120, len_b=100)
    )
    res = await two_identity(client, 5, 6)
    assert res.confirmed is True


async def test_two_identity_access_controlled_rejects():
    # attacker got 403 => access control held => rejected
    client = FakeClient(compare_out=_compare(403, 200, identical=False, only_in_b=["secret"]))
    res = await two_identity(client, 5, 6)
    assert res.confirmed is False


async def test_two_identity_divergent_body_rejects():
    # attacker got 200 but body diverges (victim-only lines missing) => not the victim object
    client = FakeClient(
        compare_out=_compare(200, 200, identical=False, only_in_b=["victim-secret"], len_a=80)
    )
    res = await two_identity(client, 5, 6)
    assert res.confirmed is False


# --- oob (out-of-band callback) -------------------------------------------------


async def test_oob_callback_confirms():
    hit = OOBHit(correlation_id="abc123", protocol="dns", source_ip="10.1.2.3", flow_id=7)
    collab = FakeCollaborator([hit])
    res = await oob(collab, "abc123", timeout_secs=5)
    assert res.confirmed is True
    assert res.kind == "oob"
    assert res.flow_ids == [7]
    assert collab.calls[0][0] == "abc123"


async def test_oob_no_callback_rejects():
    collab = FakeCollaborator([])
    res = await oob(collab, "abc123", timeout_secs=5)
    assert res.confirmed is False
    assert res.flow_ids == []


# --- marker / timing / signature ------------------------------------------------


async def test_marker_hit_confirms():
    client = FakeClient(search_out={"flow_ids": [11, 12]})
    res = await marker(client, "uniqmarker")
    assert res.confirmed is True
    assert res.flow_ids == [11, 12]


async def test_marker_accepts_plain_list():
    client = FakeClient(search_out=[13])
    res = await marker(client, "uniqmarker")
    assert res.confirmed is True
    assert res.flow_ids == [13]


async def test_marker_miss_rejects():
    client = FakeClient(search_out={"flow_ids": []})
    res = await marker(client, "uniqmarker")
    assert res.confirmed is False


async def test_timing_blind_over_threshold_confirms():
    fuzz = {
        "results": [
            {"payload": "1", "flow_id": 20, "latency_ms": 120, "anomaly_score": 0.1},
            {"payload": "SLEEP(5)", "flow_id": 21, "latency_ms": 5200, "anomaly_score": 0.9},
        ],
        "count": 2,
    }
    client = FakeClient(fuzz_out=fuzz)
    res = await timing_blind(client, 99, threshold_ms=5000)
    assert res.confirmed is True
    assert res.flow_ids == [21]


async def test_timing_blind_under_threshold_rejects():
    fuzz = {"results": [{"payload": "x", "flow_id": 20, "latency_ms": 120}], "count": 1}
    client = FakeClient(fuzz_out=fuzz)
    res = await timing_blind(client, 99, threshold_ms=5000)
    assert res.confirmed is False


async def test_signature_match_confirms():
    show = {"id": 30, "response": {"status": 500, "body": "You have an error in your SQL syntax"}}
    client = FakeClient(show_out=show)
    res = await signature(client, 30, ["SQL syntax", "ORA-01756"])
    assert res.confirmed is True
    assert res.flow_ids == [30]


async def test_signature_no_match_rejects():
    show = {"id": 30, "response": {"status": 200, "body": "welcome home"}}
    client = FakeClient(show_out=show)
    res = await signature(client, 30, ["SQL syntax"])
    assert res.confirmed is False


# --- run_oracle dispatcher ------------------------------------------------------


async def test_run_oracle_routes_two_identity():
    client = FakeClient(compare_out=_compare(200, 200, identical=True))
    spec = VerificationOracle(kind="two_identity")
    res = await run_oracle(spec, {"client": client, "a_ref": 5, "b_ref": 6})
    assert isinstance(res, OracleResult)
    assert res.kind == "two_identity"
    assert res.confirmed is True


async def test_run_oracle_routes_oob_with_spec_correlation():
    hit = OOBHit(correlation_id="cid", protocol="http", flow_id=9)
    collab = FakeCollaborator([hit])
    spec = VerificationOracle(kind="oob", correlation_id="cid", expect={"timeout_secs": 2})
    res = await run_oracle(spec, {"collaborator": collab})
    assert res.confirmed is True
    assert res.flow_ids == [9]


async def test_run_oracle_routes_timing_threshold_from_expect():
    fuzz = {"results": [{"payload": "s", "flow_id": 1, "latency_ms": 6000}]}
    client = FakeClient(fuzz_out=fuzz)
    spec = VerificationOracle(kind="timing", expect={"threshold_ms": 5000})
    res = await run_oracle(spec, {"client": client, "attack_id": 3})
    assert res.confirmed is True


async def test_run_oracle_llm_rubric_abstains():
    spec = VerificationOracle(kind="llm_rubric", confirm_prompt="is this exploitable?")
    res = await run_oracle(spec, {})
    assert res.confirmed is False
    assert res.kind == "llm_rubric"
