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
    client = FakeClient(compare_out=_compare(200, 200, identical=False, only_in_b=[], len_a=120, len_b=100))
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


async def test_marker_stored_in_response_confirms():
    # marker surfaces in the RESPONSE of a flow whose request did not carry it => stored/second-order
    show = {"request": {"body": "post a comment"}, "response": {"body": "page shows uniqmarker here"}}
    client = FakeClient(search_out={"flow_ids": [11]}, show_out=show)
    res = await marker(client, "uniqmarker")
    assert res.confirmed is True
    assert res.flow_ids == [11]


async def test_marker_request_only_echo_rejects():
    # REGRESSION: the injection request contains the marker so req_search always matches; a
    # request-only echo (never in a response) must NOT auto-confirm the oracle.
    show = {"request": {"body": "q=uniqmarker"}, "response": {"body": "no reflection here"}}
    client = FakeClient(search_out={"flow_ids": [11]}, show_out=show)
    res = await marker(client, "uniqmarker")
    assert res.confirmed is False


async def test_marker_same_flow_reflection_rejects():
    # marker in BOTH the request and its own response = reflection (differential's job), not storage
    show = {"request": {"body": "q=uniqmarker"}, "response": {"body": "you searched uniqmarker"}}
    client = FakeClient(search_out={"flow_ids": [11]}, show_out=show)
    res = await marker(client, "uniqmarker")
    assert res.confirmed is False


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


async def test_timing_blind_uniform_slow_rejects():
    # REGRESSION: an endpoint that is slow for EVERY payload (high baseline) is not a controlled
    # SLEEP — the slowest must stand out from the baseline by a large fraction of the threshold.
    fuzz = {
        "results": [
            {"payload": "a", "flow_id": 1, "latency_ms": 5000},
            {"payload": "b", "flow_id": 2, "latency_ms": 5100},
            {"payload": "SLEEP", "flow_id": 3, "latency_ms": 5300},
        ]
    }
    client = FakeClient(fuzz_out=fuzz)
    res = await timing_blind(client, 99, threshold_ms=5000)
    assert res.confirmed is False
    assert "baseline" in res.evidence


async def test_timing_blind_spike_over_baseline_confirms():
    # A single payload far slower than the low baseline = a real controlled delay.
    fuzz = {
        "results": [
            {"payload": "a", "flow_id": 1, "latency_ms": 90},
            {"payload": "b", "flow_id": 2, "latency_ms": 110},
            {"payload": "SLEEP(5)", "flow_id": 3, "latency_ms": 5200},
        ]
    }
    client = FakeClient(fuzz_out=fuzz)
    res = await timing_blind(client, 99, threshold_ms=5000)
    assert res.confirmed is True
    assert res.flow_ids == [3]


# --- two_identity negative control (public-resource false positive) -------------


class _PerFlowCompare:
    """Fake client returning a different compare() result keyed on the first flow id."""

    def __init__(self, by_a):
        self.by_a = by_a

    async def compare(self, flow_a, flow_b, what="all"):
        return self.by_a[flow_a]


async def test_two_identity_public_resource_rejects_with_control():
    # REGRESSION: A reproduces B, but an anonymous control also reproduces B => the object is
    # public, not an IDOR. The negative control must sink the finding.
    client = FakeClient(compare_out=_compare(200, 200, identical=True))
    res = await two_identity(client, 5, 6, c_ref=7)
    assert res.confirmed is False
    assert "PUBLIC" in res.evidence


async def test_two_identity_private_with_denied_control_confirms():
    client = _PerFlowCompare(
        {
            5: _compare(200, 200, identical=True),  # attacker reproduces owner object
            7: _compare(403, 200, identical=False, only_in_b=["secret"]),  # anon control denied
        }
    )
    res = await two_identity(client, 5, 6, c_ref=7)
    assert res.confirmed is True


# --- differential noise floor ---------------------------------------------------


async def test_differential_length_delta_below_floor_rejects():
    # REGRESSION: a sub-noise-floor length delta (dynamic content) is not a signal.
    client = FakeClient(compare_out=_compare(200, 200, identical=False, len_a=100, len_b=105))
    res = await differential(client, 1, 2, {"signal": "length_delta"})
    assert res.confirmed is False


async def test_differential_explicit_min_len_delta_overrides_floor():
    client = FakeClient(compare_out=_compare(200, 200, identical=False, len_a=100, len_b=105))
    res = await differential(client, 1, 2, {"signal": "length_delta", "min_len_delta": 4})
    assert res.confirmed is True


# --- state_change (business-logic / CSRF semantic oracle) -----------------------


async def test_state_change_must_appear_confirms():
    from a2pwn.oracles import state_change

    client = FakeClient(
        compare_out=_compare(200, 200, identical=False, only_in_b=["email=attacker@evil.com"])
    )
    res = await state_change(client, 1, 2, {"must_appear": "attacker@evil.com"})
    assert res.confirmed is True
    assert res.kind == "state_change"


async def test_state_change_must_appear_absent_rejects():
    from a2pwn.oracles import state_change

    client = FakeClient(compare_out=_compare(200, 200, identical=False, only_in_b=["unrelated"]))
    res = await state_change(client, 1, 2, {"must_appear": "attacker@evil.com"})
    assert res.confirmed is False


async def test_state_change_body_delta_confirms():
    from a2pwn.oracles import state_change

    client = FakeClient(compare_out=_compare(200, 200, identical=False, len_a=100, len_b=200))
    res = await state_change(client, 1, 2, {})
    assert res.confirmed is True


async def test_state_change_noise_floor_rejects():
    from a2pwn.oracles import state_change

    client = FakeClient(compare_out=_compare(200, 200, identical=False, len_a=100, len_b=105))
    res = await state_change(client, 1, 2, {})
    assert res.confirmed is False


async def test_run_oracle_routes_state_change():
    spec = VerificationOracle(kind="state_change", expect={"must_appear": "tok"})
    client = FakeClient(compare_out=_compare(200, 200, identical=False, only_in_b=["tok-here"]))
    res = await run_oracle(spec, {"client": client, "before_ref": 1, "after_ref": 2})
    assert res.confirmed is True
    assert res.kind == "state_change"


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


# --- run_oracle fail-closed contract (NEVER returns None) ------------------------


async def test_run_oracle_unknown_kind_fails_closed():
    # Bypass the Literal validation to feed a kind no oracle maps; must reject, not raise.
    spec = VerificationOracle.model_construct(kind="mystery")
    res = await run_oracle(spec, {})
    assert isinstance(res, OracleResult)
    assert res.confirmed is False
    assert res.kind == "mystery"
    assert "unknown" in res.evidence.lower()


async def test_run_oracle_missing_client_fails_closed():
    spec = VerificationOracle(kind="signature", signals=["boom"])
    res = await run_oracle(spec, {"flow_id": 1})  # no client handle
    assert isinstance(res, OracleResult)
    assert res.confirmed is False
    assert res.kind == "signature"


async def test_run_oracle_missing_flow_ids_fails_closed():
    client = FakeClient(compare_out=_compare(200, 200, identical=True))
    spec = VerificationOracle(kind="differential")
    res = await run_oracle(spec, {"client": client})  # no flow_a/flow_b
    assert res.confirmed is False


async def test_run_oracle_oracle_raises_fails_closed():
    class Boom:
        async def compare(self, *a, **k):
            raise RuntimeError("mcp down")

    spec = VerificationOracle(kind="two_identity")
    res = await run_oracle(spec, {"client": Boom(), "a_ref": 1, "b_ref": 2})
    assert res.confirmed is False
    assert "raised" in res.evidence.lower()


async def test_run_oracle_signature_uses_spec_signals():
    show = {"id": 9, "response": {"body": "PHP Warning: include(): failed to open stream"}}
    client = FakeClient(show_out=show)
    spec = VerificationOracle(kind="signature", signals=["failed to open stream"])
    res = await run_oracle(spec, {"client": client, "flow_id": 9})
    assert res.confirmed is True
    assert res.flow_ids == [9]


async def test_run_oracle_signature_empty_signals_fails_closed():
    client = FakeClient(show_out={"id": 9, "response": {"body": "whatever"}})
    spec = VerificationOracle(kind="signature", signals=[])
    res = await run_oracle(spec, {"client": client, "flow_id": 9})
    assert res.confirmed is False
    assert "signal" in res.evidence.lower()


async def test_run_oracle_oob_without_collaborator_fails_closed():
    spec = VerificationOracle(kind="oob", correlation_id="cid")
    res = await run_oracle(spec, {})  # no collaborator handle
    assert res.confirmed is False
    assert res.kind == "oob"


async def test_run_oracle_oob_without_correlation_fails_closed():
    collab = FakeCollaborator([])
    spec = VerificationOracle(kind="oob")  # no correlation_id anywhere
    res = await run_oracle(spec, {"collaborator": collab})
    assert res.confirmed is False
    assert collab.calls == []  # never polled — nothing to correlate
