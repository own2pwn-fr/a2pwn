"""Native ``claude-agent-sdk`` executor/verifier loop (in-process MCP tools).

This is the drop-in alternative to the LangGraph ``create_react_agent`` executor. Over the
Claude Code subscription, prompted-JSON tool-calling makes the model treat the text-rendered
tool transcript as prompt injection and refuse to act on it. Running the SAME burpwn/oracle/
finding tool surface as a NATIVE agent-SDK MCP server (Claude calls the tools, the SDK executes
our async fns in-process and feeds results back) removes that transcript-as-injection failure
mode entirely.

The tool bodies are thin wrappers over an already-connected :class:`~a2pwn.burpwn.BurpwnClient`
and the deterministic oracles — identical behaviour to the LangChain adapters in
``a2pwn.tools.*`` — and ``report_finding`` builds a :class:`~a2pwn.models.Finding` byte-for-byte
the same way as ``a2pwn.tools.finding_tools`` so findings are interchangeable between the two
executor paths.

This file is part of a2pwn and is distributed under the GNU Affero General Public License v3.0
or later; see the repository ``LICENSE`` for the full text.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    SystemMessage,
    TextBlock,
    ToolUseBlock,
    create_sdk_mcp_server,
    query,
    tool,
)

from a2pwn import progress
from a2pwn.artifacts import ArtifactStore
from a2pwn.burpwn import BurpwnClient, FlowBatchManager
from a2pwn.coverage import Probe
from a2pwn.directives import DirectiveBus
from a2pwn.identity import IdentityStore
from a2pwn.jsaudit import decode_jwt_claims
from a2pwn.models import Finding, FlowBatchRef, TaskSpec, normalise_chain_edges
from a2pwn.oracles import VerificationOracle, run_oracle
from a2pwn.scope import ScopeGuard, host_of
from a2pwn.throttle import Throttle
from a2pwn.toolcore import build_tool_specs
from a2pwn.tools.artifact_tools import ARTIFACT_TOOL_SPECS
from a2pwn.tools.coverage_tools import PROBE_SCHEMA, RECORD_PROBE_DESC, build_probe
from a2pwn.tools.research_tools import (
    CVE_LOOKUP_DESC,
    CVE_LOOKUP_SCHEMA,
    JS_ANALYZE_DESC,
    JS_ANALYZE_SCHEMA,
    JWT_DECODE_DESC,
    JWT_DECODE_SCHEMA,
    RESEARCH_FETCH_DESC,
    RESEARCH_FETCH_SCHEMA,
    run_js_analyze,
)

# Child of the "a2pwn" logger so the TUI's WARNING-silencing still applies, but `--plain` (INFO) and
# `-v` (DEBUG) surface the sub-agent's otherwise-invisible tool calls, results and refusals.
_log = logging.getLogger("a2pwn.executor")

# Kept byte-identical to a2pwn.tools.finding_tools so findings clamp the same way.
_ORACLES = {
    "differential",
    "oob",
    "marker",
    "signature",
    "timing",
    "two_identity",
    "state_change",
    "llm_rubric",
}
_SEVERITIES = {"info", "low", "medium", "high", "critical"}

# The fields ``report_finding`` accepts, as a module-level constant so the parity test can compare
# it against the LangChain tool's actual signature. A field added to one path and forgotten on the
# other is the exact shape of the ``state_change`` data-loss bug, so it is asserted, not assumed.
REPORT_FINDING_SCHEMA: dict[str, Any] = {
    "vuln_class": str,
    "severity": str,
    "target": str,
    "evidence": str,
    "flow_ids": list,
    "oracle_kind": str,
    "param": str,
    "sub_variant": str,
    "workspace": str,
    "tag": str,
    "key_flow": int,
    "exec_ids": list,
    "oracle_signals": list,
    "correlation_id": str,
    "oracle_expect": dict,
    "enables": list,
    "chain_edges": list,
    "cvss_vector": str,
    "cwe_ids": list,
    "remediation": str,
    "identity": str,
}

# A single MCP text block should not carry an unbounded body (a req_show can be multi-MiB);
# cap it well above anything the model needs to reason over.
_MAX_TEXT = 200_000
# Head length for the human-readable transcript lines.
_HEAD = 240

# Anthropic's own Claude Code CLI boilerplate for a safety-flagged message (observed live: a
# dispatch that had already made real tool calls hit this mid-turn on a specific request). The SDK
# then surfaces the eventual ResultMessage/exception under the same generic "executor loop error"
# label as a genuine crash (its own text is misleadingly "returned an error result: success"), so a
# --plain run can't tell a model refusal from a technical failure without this heuristic.
_REFUSAL_MARKERS = ("safety measures", "flagged this message", "Cyber Verification Program")


def _is_model_refusal_text(text: str) -> bool:
    return any(m in text for m in _REFUSAL_MARKERS)


@dataclass
class SdkExecOutcome:
    """Everything the fork boundary needs back from one native-SDK executor run."""

    candidate_findings: list[Finding] = field(default_factory=list)
    flow_batches: list[FlowBatchRef] = field(default_factory=list)
    discovered_hosts: list[TaskSpec] = field(default_factory=list)
    # Coverage declarations: what this dispatch TESTED, including the classes it cleared. Without
    # them a probed-and-clean asset is indistinguishable from one no dispatch ever reached.
    probes: list[Probe] = field(default_factory=list)
    # How many times the SDK compacted its own transcript during this dispatch. A non-zero count
    # is the explanation for a long dispatch that appears to have lost the plot.
    compactions: int = 0
    summary: str = ""
    tool_calls: int = 0
    transcript: list[str] = field(default_factory=list)
    # REAL spend for this run, read off the SDK's own ResultMessage — this is what makes the
    # engagement's --max-usd/--max-tokens ceilings mean anything (a dispatch COUNT is a poor proxy:
    # one dispatch is anywhere from 3 turns to 60 turns with a 150k-token compaction).
    cost_usd: float = 0.0
    tokens: int = 0


def _usage_tokens(usage: Any) -> int:
    """Total tokens from an SDK usage payload (input+output+cache), shape-defensive."""
    if not isinstance(usage, dict):
        return 0
    total = 0
    for key in (
        "input_tokens",
        "output_tokens",
        "cache_creation_input_tokens",
        "cache_read_input_tokens",
    ):
        try:
            total += int(usage.get(key) or 0)
        except (TypeError, ValueError):
            continue
    return total


def _text_result(text: str) -> dict:
    """The mandatory MCP tool-result envelope: a single text content block."""
    if len(text) > _MAX_TEXT:
        text = text[:_MAX_TEXT] + f"\n… [truncated at {_MAX_TEXT} chars]"
    return {"content": [{"type": "text", "text": text}]}


def _json_result(value) -> dict:
    return _text_result(json.dumps(value, default=str))


def _slug(name: str) -> str:
    """``skill.name`` -> a safe tool-name fragment (non-alnum -> ``_``)."""
    return re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_") or "skill"


def _head(text: str, n: int = _HEAD) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n] + "…"


_ARTIFACT_TOOLS = {"artifact_grep", "artifact_slice", "artifact_list", "artifact_drop"}


def _offload(name: str, result: dict, artifacts) -> dict:
    """Route a bulky tool result into the artifact store instead of the transcript.

    The old behaviour truncated at 200 000 characters, which is the worst of both worlds: the model
    pays for 200 kB of noise and still cannot see the part it needed, because the interesting string
    in a minified bundle is almost never in the first 200 kB. Here it gets a short envelope and
    greps into the blob, paying only for what it reads.
    """
    if artifacts is None or name in _ARTIFACT_TOOLS:
        return result
    blocks = result.get("content") if isinstance(result, dict) else None
    if not isinstance(blocks, list) or len(blocks) != 1:
        return result
    block = blocks[0]
    if not isinstance(block, dict) or block.get("type") != "text":
        return result
    text = block.get("text") or ""
    if len(text) <= artifacts.inline_limit:
        return result
    return {"content": [{"type": "text", "text": artifacts.maybe_store(text, origin=name)}]}


def _annotate_directives(result: dict, directives, dispatch_id: str) -> dict:
    """Deliver pending directives on the back of a tool result.

    Chosen over a "check your messages" tool the agent might never call, and over an interrupt the
    checkpointerless child cannot take: an agent that is still working is still reading tool
    results, so this reaches it without needing its cooperation.
    """
    if directives is None or not dispatch_id:
        return result
    blocks = result.get("content") if isinstance(result, dict) else None
    if not isinstance(blocks, list) or not blocks:
        return result
    block = blocks[0]
    if not isinstance(block, dict) or block.get("type") != "text":
        return result
    annotated = directives.annotate(dispatch_id, block.get("text") or "")
    if annotated == block.get("text"):
        return result
    return {"content": [{**block, "text": annotated}, *blocks[1:]]}


def _observe_tool(name: str, handler, blocked: set, artifacts=None, directives=None, dispatch_id=""):
    """Wrap a tool handler with the active-exploit hard block + observability.

    Every call, its result head and any failure are logged (INFO/DEBUG/WARNING) and a tool error is
    surfaced to the model as an error result instead of vanishing into an opaque SDK exception. This
    is what makes a ``--plain`` run show *whether burpwn is actually being driven* and *why it fails*
    — the gap behind "the agent can't use burpwn but I have no logs".
    """

    async def _fn(args: dict) -> dict:
        did = progress.current_dispatch()
        if name in blocked:
            _log.info("[%s] tool %s BLOCKED (active-exploit not authorised)", did, name)
            return _text_result(f"BLOCKED: active exploitation not authorised for {name}")
        _log.info("[%s] tool %s %s", did, name, _head(json.dumps(args, default=str), 160))
        try:
            result = await handler(args)
        except Exception as exc:  # noqa: BLE001 - log + feed the model an error, never swallow silently
            _log.warning("[%s] tool %s FAILED: %s", did, name, exc)
            progress.emit("activity", stage="error", text=f"{name} FAILED: {_head(str(exc), 120)}")
            return _text_result(f"ERROR from {name}: {exc}")
        _log.debug("[%s] tool %s -> %s", did, name, _head(json.dumps(result, default=str), 200))
        return _annotate_directives(_offload(name, result, artifacts), directives, dispatch_id)

    return _fn


async def run_sdk_agent(
    *,
    model: str,
    system_prompt: str,
    task: str,
    client: BurpwnClient,
    collab,
    skills: list,
    max_turns: int = 60,
    active_exploit_blocked: list[str] | None = None,
    options_extra: dict | None = None,
    engagement: Any = None,
    identities: IdentityStore | None = None,
    throttle: Throttle | None = None,
    fuzz_cap: int = 0,
    dispatch_id: str = "",
    artifacts: ArtifactStore | None = None,
    directives: DirectiveBus | None = None,
    research: Any = None,
) -> SdkExecOutcome:
    """Run the pentest executor/verifier as a native claude-agent-sdk agent loop.

    Exposes the burpwn hot loop, the deterministic ``run_oracle`` kernel, a ``report_finding``
    emitter (identical construction to the LangChain path), a ``propose_targets`` recon-follow-up
    emitter, and one on-demand info tool per catalog skill, all as in-process SDK MCP tools. The SDK
    drives the full loop: the model calls the tools, we execute them here, results are fed back
    until the task is done.

    ``active_exploit_blocked`` lists tool names (e.g. ``"burpwn_exec"``, ``"burpwn_fuzz"``) that
    must hard-refuse — their bodies return an error result without touching the target.
    ``engagement`` (optional) drives the scope guard: every target-facing tool refuses out-of-scope
    or explicitly excluded destinations before running, and ``propose_targets`` drops a proposal
    outside the allow-list so a hallucinated host never even reaches the planner's queue. This
    client-side refusal previously existed on the LangChain path ONLY — i.e. it was off on the
    default ``claude-code`` backend — and now comes from the same shared
    :func:`~a2pwn.toolcore.build_tool_specs` definition both paths adapt.

    ``identities`` exposes the identity tools and the ``as_identity`` parameter (what makes the
    ``two_identity`` oracle reachable at all); ``throttle``/``fuzz_cap`` apply the engagement's
    traffic policy.
    """
    blocked = set(active_exploit_blocked or [])
    findings: list[Finding] = []
    discovered: list[TaskSpec] = []
    probes: list[Probe] = []
    guard = ScopeGuard.from_engagement(engagement)
    fbm = FlowBatchManager(client)

    # ---- shared tool definitions (identical to the LangChain path, by construction) -----
    shared_specs = build_tool_specs(
        client, guard=guard, identities=identities, throttle=throttle, fuzz_cap=fuzz_cap
    )

    def _adapt(fn):
        async def _handler(args: dict) -> dict:
            return _json_result(await fn(**{k: v for k, v in (args or {}).items() if v is not None}))

        return _handler

    # ---- deterministic oracle (mirrors a2pwn.tools.oracle_tools) ------------------------
    async def _run_oracle(args: dict) -> dict:
        spec = VerificationOracle(
            kind=args["kind"],  # type: ignore[arg-type]
            expect=args.get("expect") or {},
            signals=args.get("signals") or [],
            correlation_id=args.get("correlation_id"),
        )
        ctx = {
            "client": client,
            "collaborator": collab,
            "collab": collab,
            "flow_a": args.get("flow_a"),
            "flow_b": args.get("flow_b"),
            "attack_id": args.get("attack_id"),
            "flow_id": args.get("flow_id"),
            "threshold_ms": args.get("threshold_ms"),
            "correlation_id": args.get("correlation_id"),
        }
        result = await run_oracle(spec, ctx)
        return _json_result(result.model_dump())

    # ---- finding emitter (mirrors a2pwn.tools.finding_tools EXACTLY) --------------------
    async def _report_finding(args: dict) -> dict:
        vuln_class = args["vuln_class"]
        severity = args["severity"]
        target = args["target"]
        evidence = args["evidence"]
        flow_ids = list(args.get("flow_ids") or [])
        oracle_kind = args.get("oracle_kind", "signature")
        param = args.get("param")
        sub_variant = args.get("sub_variant")
        workspace = args.get("workspace")
        tag = args.get("tag") or vuln_class
        key_flow = args.get("key_flow")
        exec_ids = args.get("exec_ids")
        oracle_signals = args.get("oracle_signals")
        correlation_id = args.get("correlation_id")
        oracle_expect = args.get("oracle_expect")
        enables = args.get("enables")
        chain_edges = normalise_chain_edges(args.get("chain_edges"))
        cvss_vector = args.get("cvss_vector")
        cwe_ids = args.get("cwe_ids")
        remediation = args.get("remediation")
        identity = args.get("identity")

        oracle_kind = oracle_kind if oracle_kind in _ORACLES else "signature"
        severity = severity if severity in _SEVERITIES else "medium"
        ref = FlowBatchRef(
            workspace=workspace or f"{vuln_class}-poc",
            tag=tag,
            color="red",
            flow_ids=flow_ids,
            exec_ids=list(exec_ids or []),
            key_flow=key_flow or (flow_ids[0] if flow_ids else None),
        )
        try:  # best-effort highlight; a burpwn hiccup must not lose the finding
            if flow_ids:
                ref = await fbm.seal(
                    ref, flow_ids, tag=tag, color="red", note_body=evidence, key_flow=ref.key_flow
                )
        except Exception:  # noqa: BLE001
            pass
        finding = Finding(
            key=Finding.make_key(vuln_class, target, param),
            vuln_class=vuln_class,
            sub_variant=sub_variant,
            severity=severity,
            target=target,
            param=param,
            evidence=FlowBatchManager.strip_nul(evidence),
            oracle_kind=oracle_kind,
            oracle_signals=list(oracle_signals or []),
            correlation_id=correlation_id,
            oracle_expect=dict(oracle_expect or {}),
            flow_batch=ref,
            enables=list(enables or []),
            chain_edges=chain_edges,
            cvss_vector=cvss_vector,
            cwe_ids=list(cwe_ids or []),
            remediation=remediation,
            identity=identity,
        )
        findings.append(finding)
        progress.emit(
            "finding",
            status="candidate",
            vuln_class=finding.vuln_class,
            severity=finding.severity,
            target=finding.target,
            param=finding.param,
        )
        summary = (
            f"recorded candidate {finding.key} (severity={finding.severity}, "
            f"oracle={oracle_kind}, flows={flow_ids or 'NONE — will be rejected'})"
        )
        return _text_result(summary)

    # ---- recon-follow-up emitter (mirrors a2pwn.tools.recon_tools EXACTLY) --------------
    async def _propose_targets(args: dict) -> dict:
        proposed = 0
        for entry in args.get("hosts") or []:
            raw = str(entry.get("host") or "").strip()
            if not raw:
                continue
            host = host_of(raw) or raw
            if not guard.allows(host):
                continue
            note = str(entry.get("note") or "").strip()
            url = raw if "://" in raw else f"https://{host}"
            task_text = f"Recon and (if warranted) exploit {host}."
            if note:
                task_text += f" Context from discovery: {note}"
            discovered.append(TaskSpec(task=task_text, target=url, hints=[note] if note else []))
            proposed += 1
        return _text_result(
            f"proposed {proposed} follow-up target(s)" if proposed else "no new targets proposed"
        )

    # ---- coverage declaration (mirrors a2pwn.tools.coverage_tools EXACTLY) --------------
    async def _record_probe(args: dict) -> dict:
        probe = build_probe(args, dispatch_id)
        if probe is None:
            return _text_result("record_probe needs at least host and vuln_class")
        probes.append(probe)
        return _text_result(f"recorded {probe.vuln_class} = {probe.verdict} on {probe.asset_key}")

    # ---- static tool specs: (name, description, input_schema, handler) ------------------
    # The burpwn hot loop comes from the SHARED definition so this path and the LangChain path can
    # never drift; only the oracle/finding/recon emitters are SDK-local.
    specs: list[tuple[str, str, dict, object]] = [
        (spec.name, spec.description, spec.schema, _adapt(spec.fn)) for spec in shared_specs
    ] + [
        (
            "run_oracle",
            "Deterministically confirm a candidate finding via the named oracle "
            "(differential/timing/oob/marker/signature/two_identity/state_change/llm_rubric). "
            'For state_change, expect={"must_appear": "<token>"} or '
            '{"must_disappear": "<token>"}, with flow_a=before-flow and flow_b=after-flow. '
            "Returns an OracleResult.",
            {
                "kind": str,
                "expect": dict,
                "signals": list,
                "correlation_id": str,
                "flow_a": int,
                "flow_b": int,
                "attack_id": int,
                "flow_id": int,
                "threshold_ms": int,
            },
            _run_oracle,
        ),
        (
            "report_finding",
            "Declare ONE proven candidate vulnerability, backed by captured burpwn flows. "
            "flow_ids MUST be the captured_request_ids that prove it and exec_ids the exec_id values "
            "those calls returned; oracle_kind is how it can be deterministically re-confirmed. Thread "
            "oracle_signals/correlation_id/oracle_expect so the verifier can replay the oracle. "
            "ALWAYS include cvss_vector (a CVSS 3.1 vector, e.g. "
            '"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" — the report re-derives the numeric score from '
            'this string itself, your own score estimate is ignored) and cwe_ids (e.g. ["CWE-306"]) '
            "so the report can cite them; omit only if genuinely no CWE applies. ALWAYS include "
            "remediation: two or three sentences of concrete, code-level fix guidance for THIS bug "
            "on THIS endpoint (not generic advice) — it is the first thing the report's reader "
            "looks for. When the finding was proven while acting as a declared identity, set "
            "identity to that name: an access-control finding is unreadable without it. When this "
            "finding hands you leverage over another one, add chain_edges: a list of "
            '{"to_key": "<enabled finding key>", "kind": "credential|token|session|internal_host|'
            'file_read|code_exec|privilege|information|other", "material": "<the actual leverage, '
            'verbatim>", "note": "<optional>"}. The dispatch that pursues the chain starts from an '
            "empty transcript and can see nothing but that material.",
            REPORT_FINDING_SCHEMA,
            _report_finding,
        ),
        (
            "propose_targets",
            "Propose concrete follow-up tasks for hosts discovered during recon (e.g. via subfinder "
            "+ httpx). Call this once per genuinely live, distinct host worth testing — skip "
            "parked/dead/CDN-only/duplicate entries. hosts is a list of "
            '{"host": "<hostname or URL>", "note": "<why this host matters, e.g. status/tech seen>"}.',
            {"hosts": list},
            _propose_targets,
        ),
        (
            "record_probe",
            RECORD_PROBE_DESC,
            PROBE_SCHEMA,
            _record_probe,
        ),
    ]

    # ---- research + deep JS analysis (mirrors a2pwn.tools.research_tools EXACTLY) --------------
    if artifacts is not None:

        async def _js_analyze(args: dict) -> dict:
            return _json_result(await run_js_analyze(artifacts, str(args.get("artifact_id") or "")))

        specs.append(("js_analyze", JS_ANALYZE_DESC, JS_ANALYZE_SCHEMA, _js_analyze))

    if research is not None:

        async def _cve_lookup(args: dict) -> dict:
            return _json_result(
                await research.osv_query(
                    str(args.get("ecosystem") or "npm"),
                    str(args.get("package") or ""),
                    str(args.get("version") or ""),
                )
            )

        async def _research_fetch(args: dict) -> dict:
            return _json_result(await research.fetch(str(args.get("url") or "")))

        async def _jwt_decode(args: dict) -> dict:
            return _json_result({"claims": decode_jwt_claims(str(args.get("token") or ""))})

        specs += [
            ("cve_lookup", CVE_LOOKUP_DESC, CVE_LOOKUP_SCHEMA, _cve_lookup),
            ("research_fetch", RESEARCH_FETCH_DESC, RESEARCH_FETCH_SCHEMA, _research_fetch),
            ("jwt_decode", JWT_DECODE_DESC, JWT_DECODE_SCHEMA, _jwt_decode),
        ]

    # ---- artifact access (only when a store is wired; mirrors a2pwn.tools.artifact_tools) ------
    if artifacts is not None:
        _art_handlers = {
            "artifact_grep": lambda a: _text_result(
                artifacts.grep(str(a.get("id") or ""), str(a.get("pattern") or ""), int(a.get("max_matches") or 40))
            ),
            "artifact_slice": lambda a: _text_result(
                artifacts.slice(str(a.get("id") or ""), int(a.get("offset") or 0), int(a.get("limit") or 8000))
            ),
            "artifact_list": lambda a: _text_result(artifacts.listing()),  # noqa: ARG005
            "artifact_drop": lambda a: _text_result(
                artifacts.drop(str(a.get("id") or ""), str(a.get("reason") or ""))
            ),
        }

        def _make_art(fn):
            async def _run(args: dict) -> dict:
                return fn(args)

            return _run

        for _name, _desc, _schema in ARTIFACT_TOOL_SPECS:
            specs.append((_name, _desc, _schema, _make_art(_art_handlers[_name])))

    sdk_tools = []
    tool_names: list[str] = []
    for name, description, schema, handler in specs:
        sdk_tools.append(
            tool(name, description, schema)(
                _observe_tool(name, handler, blocked, artifacts, directives, dispatch_id)
            )
        )
        tool_names.append(name)

    # ---- one on-demand info tool per skill (loads methodology when the agent asks) ------
    def _make_skill_tool(bound):
        async def _skill_fn(args: dict) -> dict:  # noqa: ARG001 - no inputs
            try:
                return _text_result(bound.body())
            except Exception as exc:  # noqa: BLE001 - a missing SKILL.md must not crash the loop
                return _text_result(f"(skill {bound.name!r} body unavailable: {exc})")

        return _skill_fn

    for skill in skills or []:
        sname = f"skill_{_slug(getattr(skill, 'name', 'skill'))}"
        if sname in tool_names:  # dedupe collisions from slugging
            continue
        desc = (getattr(skill, "description", "") or f"Methodology for {skill.name}")[:800]
        sdk_tools.append(tool(sname, f"Load methodology skill: {desc}", {})(_make_skill_tool(skill)))
        tool_names.append(sname)

    # ---- assemble the SDK MCP server + options -----------------------------------------
    server = create_sdk_mcp_server("a2pwn", "0.1.0", tools=sdk_tools)
    allowed = [f"mcp__a2pwn__{name}" for name in tool_names]

    # Force subscription billing: never let a stray ANTHROPIC_API_KEY route this to metered API.
    env = os.environ.copy()
    env.pop("ANTHROPIC_API_KEY", None)

    opts = ClaudeAgentOptions(
        model=model,
        system_prompt=system_prompt,
        mcp_servers={"a2pwn": server},
        allowed_tools=allowed,
        permission_mode="bypassPermissions",
        max_turns=max_turns,
        env=env,
        **(options_extra or {}),
    )

    # ---- drive the native loop ----------------------------------------------------------
    tool_calls = 0
    summary = ""
    transcript: list[str] = []
    cost_usd = 0.0
    tokens = 0
    compactions = 0
    try:
        async for msg in query(prompt=task, options=opts):
            if isinstance(msg, AssistantMessage):
                for block in msg.content or []:
                    if isinstance(block, ToolUseBlock):
                        tool_calls += 1
                        tname = block.name.split("__")[-1]
                        arg_head = _head(json.dumps(block.input, default=str), 90)
                        transcript.append(f"tool {block.name} {_head(json.dumps(block.input, default=str))}")
                        progress.emit("activity", stage="exploit", text=f"{tname} {arg_head}")
                    elif isinstance(block, TextBlock):
                        if block.text and block.text.strip():
                            summary = block.text
                            transcript.append(f"say {_head(block.text)}")
                            if _is_model_refusal_text(block.text):
                                _log.warning(
                                    "[%s] MODEL REFUSAL (not a bug — the model itself declined): %s",
                                    progress.current_dispatch(),
                                    _head(block.text, 200),
                                )
                            else:
                                _log.info("[%s] say %s", progress.current_dispatch(), _head(block.text, 200))
                            progress.emit("thought", text=_head(block.text, 140))
            elif isinstance(msg, SystemMessage) and getattr(msg, "subtype", "") == "compact_boundary":
                # The SDK compacts its own conversation when the context window fills; a2pwn's
                # `compaction.py` hook only ever applied to the LangChain path. Compaction is the
                # moment a long exploit leg loses detail — including, potentially, the wording of
                # the task itself, which lives in the (compactable) first user turn rather than the
                # system prompt. When a dispatch "forgets" what it was doing, this is the event that
                # explains it, so record it instead of letting it pass silently.
                meta = (getattr(msg, "data", None) or {}).get("compact_metadata") or {}
                compactions += 1
                _log.info(
                    "[%s] SDK auto-compacted the transcript (trigger=%s, pre_tokens=%s)",
                    progress.current_dispatch(),
                    meta.get("trigger", "?"),
                    meta.get("pre_tokens", "?"),
                )
                transcript.append(f"compact trigger={meta.get('trigger', '?')}")
                progress.emit(
                    "activity",
                    stage="exploit",
                    text=f"context compacted ({meta.get('pre_tokens', '?')} tokens)",
                )
            elif isinstance(msg, ResultMessage):
                if getattr(msg, "result", None):
                    summary = msg.result
                    transcript.append(f"result {_head(msg.result)}")
                # Real spend, straight from the SDK — never an estimate.
                try:
                    cost_usd += float(getattr(msg, "total_cost_usd", None) or 0.0)
                except (TypeError, ValueError):
                    pass
                tokens += _usage_tokens(getattr(msg, "usage", None))
    except Exception as exc:  # noqa: BLE001 - salvage partial work; only re-raise on a total loss
        transcript.append(f"error {_head(repr(exc))}")
        _log.warning("[%s] executor loop error: %s", progress.current_dispatch(), _head(repr(exc), 200))
        if not (findings or tool_calls or summary):
            raise

    # A run that called NO tools and reported NO findings is the signature of a model refusal
    # ("cannot execute … under current tool constraints") — flag it loudly so it isn't invisible.
    if tool_calls == 0 and not findings:
        _log.warning(
            "[%s] executor made 0 tool calls and found nothing — likely a model refusal; last text: %s",
            progress.current_dispatch(),
            _head(summary, 240) or "(none)",
        )

    return SdkExecOutcome(
        candidate_findings=findings,
        flow_batches=[f.flow_batch for f in findings],
        discovered_hosts=discovered,
        probes=probes,
        compactions=compactions,
        summary=summary,
        tool_calls=tool_calls,
        transcript=transcript,
        cost_usd=cost_usd,
        tokens=tokens,
    )
