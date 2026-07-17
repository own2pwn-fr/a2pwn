"""Deterministic verification oracles + dispatcher.

The anti-false-positive kernel. Every claimed finding is re-derived here through a
deterministic oracle before the adversarial verifier is allowed to promote it. The
``oob`` oracle uses the *real* :class:`~a2pwn.collaborator.Collaborator` (in-sandbox
listener + external Interactsh-style client) so blind SSRF/XXE/deserialization/SQLi
are proven by an out-of-band callback, not by heuristic guesswork.
"""

from typing import Any, Literal

from pydantic import BaseModel

from a2pwn.burpwn import BurpwnClient
from a2pwn.collaborator import Collaborator

# Minimum length delta (bytes) that counts as a real signal when a caller does not pin one.
# A 1-byte delta is almost always dynamic-content noise (a nonce/token/timestamp), so the old
# default of 1 auto-confirmed differential/state oracles on any live page.
_DEFAULT_LEN_FLOOR = 16
# Fraction of the SLEEP threshold the slowest sample must exceed the baseline by, so a uniformly
# slow endpoint (baseline already high) or a single jitter spike cannot pass the timing oracle.
_TIMING_MARGIN = 0.6


class VerificationOracle(BaseModel):
    kind: Literal[
        "differential",
        "timing",
        "oob",
        "marker",
        "signature",
        "two_identity",
        "state_change",
        "llm_rubric",
    ]
    expect: dict = {}  # oracle-specific params
    signals: list[str] = []
    correlation_id: str | None = None
    confirm_prompt: str | None = None


def _s(value: Any) -> str:
    return value if isinstance(value, str) else ("" if value is None else str(value))


class OracleResult(BaseModel):
    confirmed: bool
    kind: str
    evidence: str
    flow_ids: list[int] = []


def _status_ok(status: Any) -> bool:
    """True for a 2xx/3xx (successful/redirect) response status."""
    return isinstance(status, int) and 200 <= status < 400


async def differential(client: BurpwnClient, flow_a: int, flow_b: int, expect: dict) -> OracleResult:
    """Differential oracle: diff two flows (e.g. TRUE vs FALSE payload, or clean vs
    injected) and confirm when the requested signal — reflection, status change,
    length delta, or body change — is observed.

    ``expect`` keys: ``signal`` ∈ {reflection,status_change,length_delta,body_change,any}
    (default ``any``), ``marker`` (token that must appear in the reflected set),
    ``min_len_delta`` (int), ``what`` (compare scope, default ``all``).
    """
    cmp = await client.compare(flow_a, flow_b, what=expect.get("what", "all"))
    status = cmp.get("status", {}) or {}
    body = cmp.get("body", {}) or {}

    reflected = body.get("reflected") or []
    marker_tok = expect.get("marker")
    reflection_hit = bool(reflected) and (marker_tok is None or marker_tok in reflected)

    status_changed = bool(status.get("changed"))

    len_a = int(body.get("len_a") or 0)
    len_b = int(body.get("len_b") or 0)
    len_delta = abs(len_a - len_b)
    min_delta = int(expect.get("min_len_delta", _DEFAULT_LEN_FLOOR))
    length_hit = len_delta >= max(1, min_delta)

    body_changed = not bool(body.get("identical", True))

    signal = expect.get("signal", "any")
    if signal == "reflection":
        confirmed = reflection_hit
    elif signal == "status_change":
        confirmed = status_changed
    elif signal == "length_delta":
        confirmed = length_hit
    elif signal == "body_change":
        confirmed = body_changed
    else:  # 'any' — a meaningful, controllable difference between the two flows
        confirmed = reflection_hit or status_changed or (body_changed and length_hit)

    hits: list[str] = []
    if reflection_hit:
        hits.append(f"reflected={reflected}")
    if status_changed:
        hits.append(f"status {status.get('a')}->{status.get('b')}")
    if length_hit:
        hits.append(f"len_delta={len_delta}")
    if body_changed:
        hits.append("body_changed")
    evidence = (
        f"differential(signal={signal}) flows {flow_a} vs {flow_b}: {'; '.join(hits) if hits else 'no delta'}"
    )
    return OracleResult(
        confirmed=confirmed, kind="differential", evidence=evidence, flow_ids=[flow_a, flow_b]
    )


async def timing_blind(client: BurpwnClient, attack_id: int, threshold_ms: int) -> OracleResult:
    """Time-based blind oracle: read the intruder attack results and confirm when the
    slowest payload's latency crosses ``threshold_ms`` (a controlled SLEEP/delay took
    effect). Reads ``latency_ms``/``anomaly_score`` from ``fuzz_results``.
    """
    res = await client.fuzz_results(attack_id, sort="anomaly")
    rows = res.get("results", []) if isinstance(res, dict) else list(res)

    latencies: list[int] = []
    slowest: dict | None = None
    slowest_latency = -1
    for row in rows:
        latency = row.get("latency_ms")
        if not isinstance(latency, int):
            continue
        latencies.append(latency)
        if latency > slowest_latency:
            slowest_latency = latency
            slowest = row

    over_threshold = slowest is not None and slowest_latency >= threshold_ms
    # A lone slow sample can be jitter (GC pause, cold path) and a uniformly slow endpoint has a
    # high baseline for *every* payload — neither is a controlled SLEEP. Require the slowest to
    # stand out from the baseline (median of the other samples) by a large fraction of the sleep.
    baseline: int | None = None
    margin_ok = True
    if len(latencies) >= 2:
        rest = sorted(latencies)[:-1]  # drop one instance of the slowest
        baseline = rest[len(rest) // 2]
        margin_ok = (slowest_latency - baseline) >= threshold_ms * _TIMING_MARGIN
    confirmed = over_threshold and margin_ok

    flow_ids: list[int] = []
    if slowest is not None and isinstance(slowest.get("flow_id"), int):
        flow_ids = [slowest["flow_id"]]
    payload = slowest.get("payload") if slowest else None
    base_note = f", baseline={baseline}ms (n={len(latencies)})" if baseline is not None else ""
    evidence = (
        f"timing attack {attack_id}: slowest={slowest_latency}ms "
        f"(threshold {threshold_ms}ms{base_note}) payload={payload!r}"
        + ("" if margin_ok else " — rejected: not distinguishable from baseline jitter")
    )
    return OracleResult(confirmed=confirmed, kind="timing", evidence=evidence, flow_ids=flow_ids)


async def oob(
    collab: Collaborator,
    correlation_id: str,
    protocols=("dns", "http", "rawtcp"),
    timeout_secs: int = 30,
) -> OracleResult:
    """Out-of-band oracle: poll the collaborator for a callback carrying
    ``correlation_id``. A single hit proves blind SSRF/XXE/deserialization/SQLi that
    reaches an attacker-controlled listener — the strongest 0-FP signal there is.
    """
    hits = await collab.poll(correlation_id, timeout_secs=timeout_secs, protocols=protocols)
    confirmed = bool(hits)
    flow_ids = [h.flow_id for h in hits if getattr(h, "flow_id", None) is not None]
    seen = ", ".join(f"{h.protocol}<-{h.source_ip or '?'}" for h in hits)
    evidence = (
        f"oob correlation={correlation_id}: {len(hits)} callback(s) [{seen}]"
        if hits
        else f"oob correlation={correlation_id}: no callback within {timeout_secs}s"
    )
    return OracleResult(confirmed=confirmed, kind="oob", evidence=evidence, flow_ids=flow_ids)


def _marker_locations(detail: dict, needle: str) -> tuple[bool, bool]:
    """Where does ``needle`` appear in a flow — in its request, in its response, or both?"""
    resp = detail.get("response") or {}
    req = detail.get("request") or {}
    in_req = any(
        needle in _s(p)
        for p in (
            req.get("body"),
            req.get("headers"),
            req.get("url"),
            req.get("target"),
            req.get("query"),
            detail.get("raw_request"),
        )
    )
    in_resp = any(
        needle in _s(p) for p in (resp.get("body"), resp.get("headers"), detail.get("raw_response"))
    )
    return in_req, in_resp


async def marker(client: BurpwnClient, correlation_id: str) -> OracleResult:
    """Marker oracle: prove a unique marker *propagated* into an observable sink.

    FALSE-POSITIVE FIX: a plain FTS hit is NOT proof — the injection request itself contains
    the marker, so ``req_search`` always matches and the old oracle auto-confirmed on the
    request's own echo. This version requires the marker to surface in the **response** of a
    flow whose **request did not carry it** (genuine stored / second-order propagation). A
    marker that only appears in a request (or is reflected in the same request's response) is
    reflection, not storage — that is the ``differential`` oracle's job, not this one.
    """
    res = await client.req_search(correlation_id)
    found = list(res.get("flow_ids", [])) if isinstance(res, dict) else list(res)
    external: list[int] = []
    for fid in found:
        try:
            detail = await client.req_show(fid, raw=True)
        except Exception:  # noqa: BLE001 - a flow we cannot fetch simply cannot be proof
            continue
        if not isinstance(detail, dict):
            continue
        in_req, in_resp = _marker_locations(detail, correlation_id)
        if in_resp and not in_req:
            external.append(fid)
    confirmed = bool(external)
    evidence = (
        f"marker {correlation_id!r} surfaced in the RESPONSE of flow(s) {external} that did not "
        f"inject it (stored/second-order propagation) — searched {found}"
        if confirmed
        else (
            f"marker {correlation_id!r}: matched flows {found or '[]'} but never in a response "
            "of a flow that did not itself carry it (a request-only echo is not proof)"
        )
    )
    return OracleResult(confirmed=confirmed, kind="marker", evidence=evidence, flow_ids=external)


def _reproduces_owner(cmp: dict) -> tuple[bool, Any]:
    """Does the first flow in ``cmp`` reproduce the owner object (2nd flow)? Returns
    (reproduced, a_status). ``reproduced`` = identical body, or 2xx superset of the owner."""
    status = cmp.get("status", {}) or {}
    body = cmp.get("body", {}) or {}
    a_status = status.get("a")
    a_ok = _status_ok(a_status)
    identical = bool(body.get("identical"))
    only_in_b = body.get("only_in_b") or []
    len_a = int(body.get("len_a") or 0)
    return (identical or (a_ok and not only_in_b and len_a > 0)), a_status


async def two_identity(
    client: BurpwnClient, a_ref: int, b_ref: int, c_ref: int | None = None
) -> OracleResult:
    """Two-identity oracle for IDOR / BOLA / broken access control.

    ``a_ref`` = attacker (identity A) reaching identity B's object; ``b_ref`` = the
    legitimate owner (identity B) fetching the same object (ground truth). Confirmed
    when A's cross-object access *reproduces* B's object: A's response is 2xx and its
    body is byte-identical to B's, or contains every line B's does (a superset — B's
    object with attacker-specific chrome added). If A got 401/403 or a divergent body,
    access control held and the oracle rejects.

    FALSE-POSITIVE FIX: a *public* object is served identically to everyone, so A
    reproducing B proves nothing on its own. When a negative control ``c_ref`` (an
    unauthenticated / unauthorised identity fetching the same object) is supplied, the
    oracle additionally requires that control to be **denied** — if C also reproduces
    B, the object is public and there is no access-control violation.
    """
    cmp = await client.compare(a_ref, b_ref, what="all")
    status = cmp.get("status", {}) or {}
    body = cmp.get("body", {}) or {}

    a_status = status.get("a")
    b_status = status.get("b")
    a_ok = _status_ok(a_status)
    b_ok = _status_ok(b_status)

    identical = bool(body.get("identical"))
    only_in_b = body.get("only_in_b") or []
    len_a = int(body.get("len_a") or 0)
    reproduced = identical or (a_ok and not only_in_b and len_a > 0)

    confirmed = a_ok and b_ok and reproduced

    control_note = ""
    if confirmed and c_ref is not None:
        cmp_c = await client.compare(c_ref, b_ref, what="all")
        c_reproduced, c_status = _reproduces_owner(cmp_c)
        control_denied = not c_reproduced
        confirmed = confirmed and control_denied
        control_note = f"; neg-control (flow {c_ref}, status {c_status}) " + (
            "denied (object is private)"
            if control_denied
            else "ALSO reproduced the object => PUBLIC resource, not IDOR"
        )

    evidence = (
        f"two_identity: A-authed access (flow {a_ref}, status {a_status}) vs owner "
        f"(flow {b_ref}, status {b_status}); identical={identical}, "
        f"victim_only_lines={len(only_in_b)}{control_note} => "
        f"{'object reproduced' if confirmed else 'access controlled / public / divergent'}"
    )
    flow_ids = [a_ref, b_ref] + ([c_ref] if c_ref is not None else [])
    return OracleResult(confirmed=confirmed, kind="two_identity", evidence=evidence, flow_ids=flow_ids)


async def state_change(client: BurpwnClient, before_ref: int, after_ref: int, expect: dict) -> OracleResult:
    """Semantic oracle for business-logic / CSRF: prove a targeted piece of server state
    changed as a result of the action under test.

    Compares a **before** and an **after** observation flow (e.g. the account page read
    before and after the cross-site request). Deterministic modes via ``expect``:

    * ``must_appear`` — a token that must be ABSENT before and PRESENT after (state written).
    * ``must_disappear`` — a token PRESENT before and ABSENT after (state removed).
    * otherwise — a controlled body change: bodies differ AND the length delta clears the
      noise floor (``min_len_delta``), so a nonce/timestamp flip alone does not confirm.

    This gives logic/CSRF findings a deterministic proof path instead of an abstaining
    ``llm_rubric`` (which the 0-FP kernel always rejects).
    """
    cmp = await client.compare(before_ref, after_ref, what="all")
    body = cmp.get("body", {}) or {}
    only_in_before = body.get("only_in_a") or []  # present before, gone after
    only_in_after = body.get("only_in_b") or []  # appeared after
    identical = bool(body.get("identical"))
    len_a = int(body.get("len_a") or 0)
    len_b = int(body.get("len_b") or 0)

    must_appear = expect.get("must_appear")
    must_disappear = expect.get("must_disappear")
    if must_appear:
        confirmed = any(_s(must_appear) in _s(x) for x in only_in_after)
        why = (
            f"token {must_appear!r} appeared after the action"
            if confirmed
            else (f"token {must_appear!r} did not appear in the after-state")
        )
    elif must_disappear:
        confirmed = any(_s(must_disappear) in _s(x) for x in only_in_before)
        why = (
            f"token {must_disappear!r} was removed by the action"
            if confirmed
            else (f"token {must_disappear!r} still present after the action")
        )
    else:
        floor = int(expect.get("min_len_delta", _DEFAULT_LEN_FLOOR))
        confirmed = (not identical) and abs(len_a - len_b) >= max(1, floor)
        why = (
            f"controlled state change (len {len_a}->{len_b})"
            if confirmed
            else "no controlled state change above the noise floor"
        )
    evidence = f"state_change flows {before_ref}->{after_ref}: {why}"
    return OracleResult(
        confirmed=confirmed,
        kind="state_change",
        evidence=evidence,
        flow_ids=[before_ref, after_ref],
    )


async def signature(client: BurpwnClient, flow_id: int, signals: list[str]) -> OracleResult:
    """Signature oracle: match error strings / markers in a single flow's response.
    Confirmed when any ``signals`` substring appears in the response (or raw) of
    ``flow_id`` — e.g. a SQL error, a stack trace, a template-eval result.
    """
    detail = await client.req_show(flow_id, raw=True)
    haystack_parts: list[str] = []
    if isinstance(detail, dict):
        resp = detail.get("response") or {}
        req = detail.get("request") or {}
        for value in (
            resp.get("body"),
            resp.get("headers"),
            req.get("body"),
            detail.get("raw_response"),
            detail.get("raw_request"),
        ):
            if value:
                haystack_parts.append(value if isinstance(value, str) else str(value))
    haystack = "\n".join(haystack_parts)

    matched = [s for s in signals if s and s in haystack]
    confirmed = bool(matched)
    evidence = (
        f"signature flow {flow_id}: matched {matched}"
        if confirmed
        else f"signature flow {flow_id}: none of {signals} present"
    )
    return OracleResult(confirmed=confirmed, kind="signature", evidence=evidence, flow_ids=[flow_id])


def _pick(ctx: dict, spec: VerificationOracle, key: str, default: Any = None) -> Any:
    """Resolve an oracle parameter: ctx takes precedence over ``spec.expect``."""
    if key in ctx:
        return ctx[key]
    return spec.expect.get(key, default)


def _fail_closed(kind: str, reason: str) -> OracleResult:
    """Fail-closed abstention: the 0-FP kernel never lets an unevaluated oracle pass."""
    return OracleResult(confirmed=False, kind=kind, evidence=reason)


async def run_oracle(spec: VerificationOracle, ctx: dict) -> OracleResult:
    """Dispatch to the right deterministic oracle.

    ``ctx`` carries the live handles + relevant flow ids:
    ``{client, collaborator|collab, flow_a, flow_b, a_ref, b_ref, attack_id,
    flow_id, threshold_ms, correlation_id}``. Missing scalar params fall back to
    ``spec.expect``; ``correlation_id`` falls back to ``spec.correlation_id``.

    **Fail-closed contract**: this coroutine NEVER returns ``None``. An unknown kind,
    missing data, or an internal error yields ``OracleResult(confirmed=False, ...)`` so
    the adjudicator can reject-with-reason instead of swallowing an exception into a
    silent confirm. Every individual oracle returns a definite ``bool``.
    """
    kind = spec.kind
    client: BurpwnClient = ctx.get("client")
    collab: Collaborator = ctx.get("collaborator") or ctx.get("collab")

    try:
        if kind == "differential":
            if client is None:
                return _fail_closed(kind, "differential: no burpwn client in ctx (fail-closed)")
            flow_a = _pick(ctx, spec, "flow_a")
            flow_b = _pick(ctx, spec, "flow_b")
            if flow_a is None or flow_b is None:
                return _fail_closed(kind, f"differential: needs two flow ids, got a={flow_a!r} b={flow_b!r}")
            return await differential(client, flow_a, flow_b, spec.expect)
        if kind == "timing":
            if client is None:
                return _fail_closed(kind, "timing: no burpwn client in ctx (fail-closed)")
            attack_id = _pick(ctx, spec, "attack_id")
            if attack_id is None:
                return _fail_closed(kind, "timing: no attack_id to read fuzz results from")
            threshold = int(_pick(ctx, spec, "threshold_ms", default=5000))
            return await timing_blind(client, attack_id, threshold)
        if kind == "oob":
            cid = spec.correlation_id or ctx.get("correlation_id")
            if collab is None:
                return _fail_closed(kind, "oob: no collaborator in ctx (fail-closed)")
            if not cid:
                return _fail_closed(kind, "oob: no correlation_id to poll for (fail-closed)")
            protocols = tuple(spec.expect.get("protocols", ("dns", "http", "rawtcp")))
            timeout_secs = int(spec.expect.get("timeout_secs", 30))
            return await oob(collab, cid, protocols=protocols, timeout_secs=timeout_secs)
        if kind == "marker":
            cid = spec.correlation_id or ctx.get("correlation_id")
            if client is None:
                return _fail_closed(kind, "marker: no burpwn client in ctx (fail-closed)")
            if not cid:
                return _fail_closed(kind, "marker: no correlation_id to search for (fail-closed)")
            return await marker(client, cid)
        if kind == "two_identity":
            if client is None:
                return _fail_closed(kind, "two_identity: no burpwn client in ctx (fail-closed)")
            a_ref = _pick(ctx, spec, "a_ref")
            b_ref = _pick(ctx, spec, "b_ref")
            if a_ref is None or b_ref is None:
                return _fail_closed(
                    kind, f"two_identity: needs attacker+owner flows, got a={a_ref!r} b={b_ref!r}"
                )
            c_ref = _pick(ctx, spec, "c_ref")
            return await two_identity(client, a_ref, b_ref, c_ref)
        if kind == "state_change":
            if client is None:
                return _fail_closed(kind, "state_change: no burpwn client in ctx (fail-closed)")
            before_ref = _pick(ctx, spec, "before_ref")
            if before_ref is None:
                before_ref = _pick(ctx, spec, "flow_a")
            after_ref = _pick(ctx, spec, "after_ref")
            if after_ref is None:
                after_ref = _pick(ctx, spec, "flow_b")
            if before_ref is None or after_ref is None:
                return _fail_closed(
                    kind,
                    f"state_change: needs before+after flows, got before={before_ref!r} after={after_ref!r}",
                )
            return await state_change(client, before_ref, after_ref, spec.expect)
        if kind == "signature":
            if client is None:
                return _fail_closed(kind, "signature: no burpwn client in ctx (fail-closed)")
            flow_id = _pick(ctx, spec, "flow_id")
            if flow_id is None:
                return _fail_closed(kind, "signature: no flow_id to inspect (fail-closed)")
            if not any(s for s in spec.signals):
                return _fail_closed(kind, "signature: no signals to match — cannot re-derive (fail-closed)")
            return await signature(client, flow_id, spec.signals)
        if kind == "llm_rubric":
            return _fail_closed(
                kind,
                "llm_rubric is adjudicated by the adversarial verifier agent; "
                "no deterministic oracle can confirm it (0-FP kernel abstains)",
            )
        return _fail_closed(kind, f"unknown oracle kind {kind!r}; cannot re-derive (fail-closed)")
    except Exception as exc:  # noqa: BLE001 - an oracle crash must REJECT, never silent-confirm
        return _fail_closed(kind, f"oracle {kind!r} raised {exc!r}; cannot re-derive (fail-closed)")
