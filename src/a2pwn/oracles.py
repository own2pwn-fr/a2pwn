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


class VerificationOracle(BaseModel):
    kind: Literal[
        "differential", "timing", "oob", "marker", "signature", "two_identity", "llm_rubric"
    ]
    expect: dict = {}  # oracle-specific params
    signals: list[str] = []
    correlation_id: str | None = None
    confirm_prompt: str | None = None


class OracleResult(BaseModel):
    confirmed: bool
    kind: str
    evidence: str
    flow_ids: list[int] = []


def _status_ok(status: Any) -> bool:
    """True for a 2xx/3xx (successful/redirect) response status."""
    return isinstance(status, int) and 200 <= status < 400


async def differential(
    client: BurpwnClient, flow_a: int, flow_b: int, expect: dict
) -> OracleResult:
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
    min_delta = int(expect.get("min_len_delta", 1))
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
        f"differential(signal={signal}) flows {flow_a} vs {flow_b}: "
        f"{'; '.join(hits) if hits else 'no delta'}"
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

    slowest: dict | None = None
    slowest_latency = -1
    for row in rows:
        latency = row.get("latency_ms")
        if not isinstance(latency, int):
            continue
        if latency > slowest_latency:
            slowest_latency = latency
            slowest = row

    confirmed = slowest is not None and slowest_latency >= threshold_ms
    flow_ids: list[int] = []
    if slowest is not None and isinstance(slowest.get("flow_id"), int):
        flow_ids = [slowest["flow_id"]]
    payload = slowest.get("payload") if slowest else None
    evidence = (
        f"timing attack {attack_id}: slowest={slowest_latency}ms "
        f"(threshold {threshold_ms}ms) payload={payload!r}"
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
    seen = ", ".join(
        f"{h.protocol}<-{h.source_ip or '?'}" for h in hits
    )
    evidence = (
        f"oob correlation={correlation_id}: {len(hits)} callback(s) [{seen}]"
        if hits
        else f"oob correlation={correlation_id}: no callback within {timeout_secs}s"
    )
    return OracleResult(confirmed=confirmed, kind="oob", evidence=evidence, flow_ids=flow_ids)


async def marker(client: BurpwnClient, correlation_id: str) -> OracleResult:
    """Marker oracle: full-text search the (decrypted) captured history for a unique
    marker. A hit proves the marker landed somewhere observable (stored XSS sink,
    log-injection reflection, second-order propagation).
    """
    res = await client.req_search(correlation_id)
    if isinstance(res, dict):
        flow_ids = list(res.get("flow_ids", []))
    else:
        flow_ids = list(res)
    confirmed = bool(flow_ids)
    evidence = f"marker {correlation_id!r} found in flows {flow_ids}" if confirmed else (
        f"marker {correlation_id!r} not found in captured history"
    )
    return OracleResult(confirmed=confirmed, kind="marker", evidence=evidence, flow_ids=flow_ids)


async def two_identity(client: BurpwnClient, a_ref: int, b_ref: int) -> OracleResult:
    """Two-identity oracle for IDOR / BOLA / broken access control.

    ``a_ref`` = attacker (identity A) reaching identity B's object; ``b_ref`` = the
    legitimate owner (identity B) fetching the same object (ground truth). Confirmed
    when A's cross-object access *reproduces* B's object: A's response is 2xx and its
    body is byte-identical to B's, or contains every line B's does (a superset — B's
    object with attacker-specific chrome added). If A got 401/403 or a divergent body,
    access control held and the oracle rejects.
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
    evidence = (
        f"two_identity: A-authed access (flow {a_ref}, status {a_status}) vs owner "
        f"(flow {b_ref}, status {b_status}); identical={identical}, "
        f"victim_only_lines={len(only_in_b)} => "
        f"{'object reproduced' if confirmed else 'access controlled / divergent'}"
    )
    return OracleResult(
        confirmed=confirmed, kind="two_identity", evidence=evidence, flow_ids=[a_ref, b_ref]
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
    return OracleResult(
        confirmed=confirmed, kind="signature", evidence=evidence, flow_ids=[flow_id]
    )


def _pick(ctx: dict, spec: VerificationOracle, key: str, default: Any = None) -> Any:
    """Resolve an oracle parameter: ctx takes precedence over ``spec.expect``."""
    if key in ctx:
        return ctx[key]
    return spec.expect.get(key, default)


async def run_oracle(spec: VerificationOracle, ctx: dict) -> OracleResult:
    """Dispatch to the right deterministic oracle.

    ``ctx`` carries the live handles + relevant flow ids:
    ``{client, collaborator|collab, flow_a, flow_b, a_ref, b_ref, attack_id,
    flow_id, threshold_ms, correlation_id}``. Missing scalar params fall back to
    ``spec.expect``; ``correlation_id`` falls back to ``spec.correlation_id``.
    """
    kind = spec.kind
    client: BurpwnClient = ctx.get("client")
    collab: Collaborator = ctx.get("collaborator") or ctx.get("collab")

    if kind == "differential":
        return await differential(
            client, _pick(ctx, spec, "flow_a"), _pick(ctx, spec, "flow_b"), spec.expect
        )
    if kind == "timing":
        threshold = int(_pick(ctx, spec, "threshold_ms", default=5000))
        return await timing_blind(client, _pick(ctx, spec, "attack_id"), threshold)
    if kind == "oob":
        cid = spec.correlation_id or ctx.get("correlation_id")
        protocols = tuple(spec.expect.get("protocols", ("dns", "http", "rawtcp")))
        timeout_secs = int(spec.expect.get("timeout_secs", 30))
        return await oob(collab, cid, protocols=protocols, timeout_secs=timeout_secs)
    if kind == "marker":
        cid = spec.correlation_id or ctx.get("correlation_id")
        return await marker(client, cid)
    if kind == "two_identity":
        return await two_identity(client, _pick(ctx, spec, "a_ref"), _pick(ctx, spec, "b_ref"))
    if kind == "signature":
        return await signature(client, _pick(ctx, spec, "flow_id"), spec.signals)
    if kind == "llm_rubric":
        return OracleResult(
            confirmed=False,
            kind="llm_rubric",
            evidence="llm_rubric is adjudicated by the adversarial verifier agent; "
            "no deterministic oracle can confirm it (0-FP kernel abstains)",
        )
    raise ValueError(f"unknown oracle kind: {kind!r}")
