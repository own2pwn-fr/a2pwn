"""Peer review of a dispatch, and chains that carry their material.

Two gaps in the fork boundary, both of which made the master's record of an engagement quietly
weaker than it looked:

* **Nothing compared a request to its result.** History only ever recorded outcomes, so a dispatch
  asked to settle eight vulnerability classes and settling three was indistinguishable from one
  that did the whole job. `CleanResult.spec` plus `_unmet_task_classes` makes that answerable
  mechanically, and `_adversarial_veto` gives the stronger role-model a say in the only direction
  that is safe.
* **A chain edge carried no leverage.** `enables` was a bare list of keys and the follow-up task was
  literally "Pursue cross-chain: A enables B", handed to a child with an empty transcript — so the
  credential, token or internal host that made the chain a chain never reached the agent meant to
  use it.
"""

from __future__ import annotations

import pytest

from _graphkit import (
    FakeClarifier,
    arm_differential,
    build_sub,
    exec_result,
    make_cfg,
    make_finding,
    sub_input,
)
from a2pwn import subgraph as sg
from a2pwn.coverage import Probe
from a2pwn.models import ChainEdge, TaskSpec, normalise_chain_edges

_NO_QUESTIONS = FakeClarifier(lambda ctx: [])


def _probe(vuln_class: str) -> Probe:
    return Probe(asset_key="param|app.example.com|/search|GET|q", vuln_class=vuln_class, verdict="probed")


class _FakeVerifier:
    """Stand-in for the independent role-model: canned last-message text, or a raised exception."""

    def __init__(self, reply):
        self._reply = reply
        self.prompts: list[str] = []

    async def ainvoke(self, state, *a, **k):
        from langchain_core.messages import AIMessage, HumanMessage

        prompt = next(
            (m.content for m in reversed(state["messages"]) if isinstance(m, HumanMessage)), ""
        )
        self.prompts.append(prompt)
        if isinstance(self._reply, BaseException):
            raise self._reply
        return {"messages": [AIMessage(content=self._reply)]}


# --------------------------------------------------------------------------- residual coverage
def test_a_partially_answered_task_reports_the_classes_it_never_settled():
    """The peer-review step: compare what was ASKED against what was settled.

    A coverage-expanded task names its classes in a `classes=` hint, so 'was the work actually
    done' needs no LLM — `record_probe` and the oracle already settled it. The operator should be
    able to see that a dispatch was asked for three classes and closed one.
    """
    spec = TaskSpec(task="probe /search", hints=["classes=xss,sqli,ssti"])

    gaps = sg._unmet_task_classes(spec, [_probe("xss")])

    assert len(gaps) == 1
    assert "NOT DONE" in gaps[0]
    assert "sqli" in gaps[0] and "ssti" in gaps[0]
    assert "xss" in gaps[0]  # the full ask is echoed, so the gap is readable without the spec


def test_full_coverage_leaves_no_residual_gap():
    spec = TaskSpec(task="probe /search", hints=["classes=xss,sqli"])
    assert sg._unmet_task_classes(spec, [_probe("xss"), _probe("sqli")]) == []


def test_a_task_that_named_no_classes_is_not_second_guessed():
    # Only coverage-expanded tasks make a checkable promise. Inventing one for a free-form task
    # would file a "NOT DONE" gap against every exploratory dispatch in the run.
    assert sg._unmet_task_classes(TaskSpec(task="poke around"), []) == []
    assert sg._unmet_task_classes(TaskSpec(task="poke around", hints=["origin_finding=x"]), []) == []


def test_no_spec_means_no_review():
    # A verify dispatch carries a candidate, not a spec.
    assert sg._unmet_task_classes(None, [_probe("xss")]) == []


# --------------------------------------------------------------------------- adversarial veto
async def test_the_verifier_can_refute_an_oracle_confirmed_candidate():
    """The second layer of the two-layer discipline, and the only direction that is safe.

    A veto can produce a false negative, never a false positive, so the fail-closed kernel stays
    fail-closed while the stronger model gets to catch what a mechanical oracle cannot — a
    'differential' that differs for an unrelated reason, an oracle re-derived against the
    attacker's own echoed request, a capture that proves the wrong thing.
    """
    finding = make_finding(confirmed=True)
    verifier = _FakeVerifier(f"VETO {finding.key}: the 500 comes from a malformed Host, not the payload")

    vetoes = await sg._adversarial_veto(verifier, [finding])

    assert vetoes == {finding.key: "the 500 comes from a malformed Host, not the payload"}


async def test_the_verifier_cannot_approve_anything():
    # Silence means the oracle's verdict stands; there is no ACCEPT verb by construction.
    finding = make_finding(confirmed=True)
    verifier = _FakeVerifier("Both candidates look solid to me. APPROVE.")

    assert await sg._adversarial_veto(verifier, [finding]) == {}


async def test_an_invented_key_cannot_delete_a_finding():
    """A hallucinated key must not vaporise something the oracle proved.

    The veto is applied by key lookup, so a model that mistypes or invents one would otherwise
    delete an unrelated finding — or, worse, a key it composed from the prompt's own listing.
    """
    finding = make_finding(confirmed=True, vuln="xss")
    verifier = _FakeVerifier(
        "VETO sqli|https://app.example.com/login|user: not reproducible\n"
        "VETO some-key-i-made-up: looks wrong"
    )

    assert await sg._adversarial_veto(verifier, [finding]) == {}


async def test_a_verifier_exception_fails_OPEN():
    """FAIL-OPEN, deliberately, and the opposite of every other verdict in this codebase.

    Adjudication is fail-closed because the default there is 'unproven'. Here the oracle has
    ALREADY proven the candidate, so a flaky verifier call — a timeout, a rate limit, an SDK
    hiccup — must not be allowed to silently delete a real finding from the report.
    """
    finding = make_finding(confirmed=True)
    verifier = _FakeVerifier(RuntimeError("verifier backend timed out"))

    assert await sg._adversarial_veto(verifier, [finding]) == {}


async def test_unparseable_prose_fails_OPEN():
    # Same invariant against the likelier failure: the model answers in paragraphs instead of the
    # one-line grammar. A veto that cannot be read is not a veto.
    finding = make_finding(confirmed=True)
    verifier = _FakeVerifier(
        "I have reservations about this finding — the differential could plausibly be caused by "
        "caching rather than the injected payload, and I would want another look."
    )

    assert await sg._adversarial_veto(verifier, [finding]) == {}


async def test_a_verifier_without_ainvoke_is_skipped():
    # The role-model is optional on some backends; its absence must leave the oracle's verdicts alone.
    assert await sg._adversarial_veto(object(), [make_finding(confirmed=True)]) == {}


async def test_nothing_confirmed_means_no_verifier_call():
    verifier = _FakeVerifier("VETO anything: no")
    assert await sg._adversarial_veto(verifier, []) == {}
    assert verifier.prompts == []


# --------------------------------------------------------------------------- veto end to end
async def test_a_vetoed_candidate_is_dropped_but_never_disappears(monkeypatch, fake_client):
    """Nothing may vanish without a trace.

    A finding the oracle confirmed and the adversarial verifier refuted must not reach the report —
    and the reason must ride back across the fork boundary as a residual gap, because a finding
    that is silently deleted between the oracle and the report is indistinguishable from one that
    was never found, both to the operator reading `run.jsonl` and to the planner deciding what is
    left to do.
    """
    cfg = make_cfg(max_verify_rounds=1)
    arm_differential(fake_client)
    candidate = make_finding(flow_ids=(101, 102), exec_ids=("e-ok",))
    verifier = _FakeVerifier(f"VETO {candidate.key}: the delta is the CSRF token rotating, not injection")
    sub = build_sub(
        monkeypatch,
        cfg,
        fake_client,
        clarifier=_NO_QUESTIONS,
        executor=_executor([candidate]),
        verifier=verifier,
    )

    out = await sub.ainvoke(
        sub_input(cfg, intent="task", spec=TaskSpec(task="probe", target="https://app.example.com"))
    )

    result = out["clean_result"]
    assert result.findings == []  # the oracle confirmed it; the verifier refuted it
    assert result.status != "confirmed"
    trace = [g for g in result.residual_gaps if g.startswith("VETOED")]
    assert len(trace) == 1
    assert candidate.key in trace[0]
    assert "CSRF token rotating" in trace[0]


async def test_an_unvetoed_candidate_survives_the_veto_pass(monkeypatch, fake_client):
    """Control for the above: wiring a live verifier in must not cost findings by itself."""
    cfg = make_cfg(max_verify_rounds=1)
    arm_differential(fake_client)
    candidate = make_finding(flow_ids=(101, 102), exec_ids=("e-ok",))
    sub = build_sub(
        monkeypatch,
        cfg,
        fake_client,
        clarifier=_NO_QUESTIONS,
        executor=_executor([candidate]),
        verifier=_FakeVerifier("Nothing to refute here."),
    )

    out = await sub.ainvoke(
        sub_input(cfg, intent="task", spec=TaskSpec(task="probe", target="https://app.example.com"))
    )

    assert [f.key for f in out["clean_result"].findings] == [candidate.key]
    assert out["clean_result"].status == "confirmed"


def _executor(findings):
    from _graphkit import FakeExecutor

    return FakeExecutor(exec_result(findings))


# --------------------------------------------------------------------------- chain edge parsing
def test_normalise_builds_a_typed_edge():
    edges = normalise_chain_edges(
        [{"to_key": "ssrf|https://app.example.com/fetch|url", "kind": "credential", "material": "s3cr3t"}]
    )
    assert len(edges) == 1
    assert edges[0].kind == "credential"
    assert edges[0].material == "s3cr3t"


def test_an_edge_with_no_destination_is_dropped():
    # The whole edge is "A enables B"; without B there is nothing to hand the material to.
    assert normalise_chain_edges([{"kind": "token", "material": "abc"}]) == []
    assert normalise_chain_edges([{"to_key": "   ", "material": "abc"}]) == []


def test_an_unknown_kind_degrades_to_other():
    """A malformed edge must degrade to a weaker edge, never abort the finding.

    The proof is the valuable part and the chain hint rides on top, so an invented `kind` from a
    model that did not read the enum cannot be allowed to raise out of `report_finding`.
    """
    edges = normalise_chain_edges([{"to_key": "b", "kind": "root_shell_obviously"}])
    assert edges[0].kind == "other"


def test_material_and_note_are_truncated():
    # The material is replayed verbatim into the next dispatch's task text; an unbounded dump would
    # be pasted straight into a prompt.
    edges = normalise_chain_edges([{"to_key": "b", "material": "m" * 9000, "note": "n" * 9000}])
    assert len(edges[0].material) == 2000
    assert len(edges[0].note) == 400


def test_non_dict_entries_are_tolerated():
    # This comes off a raw model tool argument, which is a JSON blob of whatever shape it emitted.
    assert normalise_chain_edges(["b", None, 7, {"to_key": "b"}]) == [ChainEdge(to_key="b")]
    assert normalise_chain_edges(None) == []
    assert normalise_chain_edges([]) == []


# --------------------------------------------------------------------------- chain hops
async def _hops(monkeypatch, fake_client, finding) -> list[TaskSpec]:
    cfg = make_cfg(max_verify_rounds=1)
    arm_differential(fake_client)
    sub = build_sub(
        monkeypatch, cfg, fake_client, clarifier=_NO_QUESTIONS, executor=_executor([finding])
    )
    out = await sub.ainvoke(
        sub_input(cfg, intent="task", spec=TaskSpec(task="probe", target="https://app.example.com"))
    )
    assert out["clean_result"].findings, "the chain hop only exists if the finding was confirmed"
    return out["clean_result"].next_hops


@pytest.fixture
def chained_finding():
    return make_finding(flow_ids=(101, 102), exec_ids=("e-ok",)).model_copy(
        update={
            "chain_edges": [
                ChainEdge(
                    to_key="ssrf|https://internal.example.com/admin|*",
                    kind="credential",
                    material="admin:hunter2 (from the leaked .env)",
                    note="works on the internal VIP only",
                )
            ]
        }
    )


async def test_a_typed_edge_hands_its_material_to_the_next_hop(monkeypatch, fake_client, chained_finding):
    """The follow-up dispatch starts from an empty transcript, so the leverage must travel WITH it.

    Told only "A enables B", the child re-derives the credential it was already handed — if it can
    at all, since it never sees the first finding's evidence. The material in the task text (which
    the executor reads) plus the `chain_material=` hint (which the clarifier and planner read) is
    what turns a suggestion back into a chain.
    """
    hops = await _hops(monkeypatch, fake_client, chained_finding)

    assert len(hops) == 1
    hop = hops[0]
    assert hop.intent == "chain"
    assert "admin:hunter2" in hop.task
    assert "do not re-derive it" in hop.task
    assert "works on the internal VIP only" in hop.task  # the note qualifies where it applies
    assert "chain_material=admin:hunter2 (from the leaked .env)" in hop.hints
    assert "chain_kind=credential" in hop.hints
    assert f"origin_finding={chained_finding.key}" in hop.hints


async def test_a_bare_enables_key_still_produces_the_old_style_hop(monkeypatch, fake_client):
    # `enables` predates typed edges and still backs the report's chain map and existing baselines,
    # so an untyped edge must keep producing a follow-up rather than being silently dropped.
    finding = make_finding(flow_ids=(101, 102), exec_ids=("e-ok",), enables=("sqli|https://app/db|id",))

    hops = await _hops(monkeypatch, fake_client, finding)

    assert len(hops) == 1
    assert hops[0].task == f"Pursue cross-chain: {finding.key} enables sqli|https://app/db|id."
    assert hops[0].hints == [f"origin_finding={finding.key}"]


async def test_a_key_in_both_enables_and_chain_edges_is_dispatched_once(
    monkeypatch, fake_client, chained_finding
):
    """`chain_edges` is the richer statement of the SAME relationship, not a second one.

    A model that fills both fields (which the tool schema invites, since `enables` is kept for
    back-compat) would otherwise get two dispatches for one hop — double the spend for one bug, and
    two siblings racing on identical work.
    """
    to_key = chained_finding.chain_edges[0].to_key
    finding = chained_finding.model_copy(update={"enables": [to_key]})

    hops = await _hops(monkeypatch, fake_client, finding)

    assert len(hops) == 1
    assert "admin:hunter2" in hops[0].task  # and it is the TYPED one that survives, not the bare key


async def test_a_finding_with_no_edges_produces_no_hops(monkeypatch, fake_client):
    assert await _hops(monkeypatch, fake_client, make_finding(flow_ids=(101, 102), exec_ids=("e-ok",))) == []
