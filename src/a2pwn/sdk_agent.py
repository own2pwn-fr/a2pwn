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
import os
import re
from dataclasses import dataclass, field

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    create_sdk_mcp_server,
    query,
    tool,
)

from a2pwn import progress
from a2pwn.burpwn import BurpwnClient, FlowBatchManager
from a2pwn.models import Finding, FlowBatchRef
from a2pwn.oracles import VerificationOracle, run_oracle

# Kept byte-identical to a2pwn.tools.finding_tools so findings clamp the same way.
_ORACLES = {"differential", "oob", "marker", "signature", "timing", "two_identity", "llm_rubric"}
_SEVERITIES = {"info", "low", "medium", "high", "critical"}

# A single MCP text block should not carry an unbounded body (a req_show can be multi-MiB);
# cap it well above anything the model needs to reason over.
_MAX_TEXT = 200_000
# Head length for the human-readable transcript lines.
_HEAD = 240


@dataclass
class SdkExecOutcome:
    """Everything the fork boundary needs back from one native-SDK executor run."""

    candidate_findings: list[Finding] = field(default_factory=list)
    flow_batches: list[FlowBatchRef] = field(default_factory=list)
    summary: str = ""
    tool_calls: int = 0
    transcript: list[str] = field(default_factory=list)


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


async def run_sdk_agent(
    *,
    model: str,
    system_prompt: str,
    task: str,
    client: BurpwnClient,
    collab,
    skills: list,
    max_turns: int = 40,
    active_exploit_blocked: list[str] | None = None,
    options_extra: dict | None = None,
) -> SdkExecOutcome:
    """Run the pentest executor/verifier as a native claude-agent-sdk agent loop.

    Exposes the burpwn hot loop, the deterministic ``run_oracle`` kernel, a ``report_finding``
    emitter (identical construction to the LangChain path), and one on-demand info tool per
    catalog skill, all as in-process SDK MCP tools. The SDK drives the full loop: the model
    calls the tools, we execute them here, results are fed back until the task is done.

    ``active_exploit_blocked`` lists tool names (e.g. ``"burpwn_exec"``, ``"burpwn_fuzz"``) that
    must hard-refuse — their bodies return an error result without touching the target.
    """
    blocked = set(active_exploit_blocked or [])
    findings: list[Finding] = []
    fbm = FlowBatchManager(client)

    # ---- burpwn hot-loop tools (thin async wrappers over the bound client) -------------
    async def _burpwn_exec(args: dict) -> dict:
        return _json_result(
            await client.exec(
                args["argv"],
                workspace=args.get("workspace"),
                timeout_secs=args.get("timeout_secs"),
            )
        )

    async def _burpwn_req_list(args: dict) -> dict:
        return _json_result(
            await client.req_list(
                workspace_id=args.get("workspace_id"),
                host=args.get("host"),
                protocol=args.get("protocol"),
                status=args.get("status"),
                method=args.get("method"),
                limit=args.get("limit"),
            )
        )

    async def _burpwn_req_show(args: dict) -> dict:
        return _json_result(await client.req_show(args["id"], raw=bool(args.get("raw", False))))

    async def _burpwn_req_search(args: dict) -> dict:
        return _json_result(await client.req_search(args["query"]))

    async def _burpwn_req_replay(args: dict) -> dict:
        return _json_result(
            await client.req_replay(
                args["id"],
                set_headers=args.get("set_headers") or [],
                set_body=args.get("set_body"),
                method=args.get("method"),
            )
        )

    async def _burpwn_fuzz(args: dict) -> dict:
        return _json_result(
            await client.fuzz(
                args["flow"],
                args["positions"],
                args["payloads"],
                mode=args.get("mode", "sniper"),
                concurrency=args.get("concurrency"),
                delay_ms=args.get("delay_ms"),
                marker=args.get("marker"),
                name=args.get("name"),
            )
        )

    async def _burpwn_fuzz_results(args: dict) -> dict:
        return _json_result(
            await client.fuzz_results(
                args["attack_id"], sort=args.get("sort", "anomaly"), limit=args.get("limit")
            )
        )

    async def _burpwn_compare(args: dict) -> dict:
        return _json_result(
            await client.compare(args["flow_a"], args["flow_b"], what=args.get("what", "all"))
        )

    async def _burpwn_tag_add(args: dict) -> dict:
        return _json_result(await client.tag_add(args["flow_id"], args["name"], color=args.get("color")))

    async def _burpwn_note_add(args: dict) -> dict:
        return _json_result(await client.note_add(args["flow_id"], args["body"]))

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
        )
        findings.append(finding)
        progress.emit(
            "finding", status="candidate", vuln_class=finding.vuln_class,
            severity=finding.severity, target=finding.target,
        )
        summary = (
            f"recorded candidate {finding.key} (severity={finding.severity}, "
            f"oracle={oracle_kind}, flows={flow_ids or 'NONE — will be rejected'})"
        )
        return _text_result(summary)

    # ---- static tool specs: (name, description, input_schema, handler) ------------------
    specs: list[tuple[str, str, dict, object]] = [
        (
            "burpwn_exec",
            "Run a target-facing command inside the burpwn sandbox (all traffic captured/MITM'd). "
            "argv is the command vector; workspace groups this run's captured flows; "
            "timeout_secs caps a long network exec.",
            {"argv": list, "workspace": str, "timeout_secs": int},
            _burpwn_exec,
        ),
        (
            "burpwn_req_list",
            "List captured flows, optionally filtered by workspace_id, host, protocol, status, method, limit.",
            {
                "workspace_id": int,
                "host": str,
                "protocol": str,
                "status": int,
                "method": str,
                "limit": int,
            },
            _burpwn_req_list,
        ),
        (
            "burpwn_req_show",
            "Show one captured flow (decrypted request+response); raw=true adds verbatim bytes.",
            {"id": int, "raw": bool},
            _burpwn_req_show,
        ),
        (
            "burpwn_req_search",
            "Full-text search across all decrypted request/response history; returns matching flow ids.",
            {"query": str},
            _burpwn_req_search,
        ),
        (
            "burpwn_req_replay",
            "Repeater: replay a flow with edited headers/body/method.",
            {"id": int, "set_headers": list, "set_body": str, "method": str},
            _burpwn_req_replay,
        ),
        (
            "burpwn_fuzz",
            "Intruder: fuzz payload positions in a flow; results ranked by status/len/time anomaly.",
            {
                "flow": int,
                "positions": list,
                "payloads": list,
                "mode": str,
                "concurrency": int,
                "delay_ms": int,
                "marker": str,
                "name": str,
            },
            _burpwn_fuzz,
        ),
        (
            "burpwn_fuzz_results",
            "Fetch Intruder results for an attack, anomaly-ranked (the blind oracle).",
            {"attack_id": int, "sort": str, "limit": int},
            _burpwn_fuzz_results,
        ),
        (
            "burpwn_compare",
            "Structured status/header/body diff + reflection check between two flows.",
            {"flow_a": int, "flow_b": int, "what": str},
            _burpwn_compare,
        ),
        (
            "burpwn_tag_add",
            "Tag/highlight a flow (marks it as belonging to a finding batch).",
            {"flow_id": int, "name": str, "color": str},
            _burpwn_tag_add,
        ),
        (
            "burpwn_note_add",
            "Attach an evidence note to a flow.",
            {"flow_id": int, "body": str},
            _burpwn_note_add,
        ),
        (
            "run_oracle",
            "Deterministically confirm a candidate finding via the named oracle "
            "(differential/timing/oob/marker/signature/two_identity/llm_rubric). Returns an OracleResult.",
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
            "oracle_signals/correlation_id/oracle_expect so the verifier can replay the oracle.",
            {
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
            },
            _report_finding,
        ),
    ]

    def _wrap(name: str, handler) -> object:
        """Apply the active-exploitation hard block around a handler."""

        async def _fn(args: dict) -> dict:
            if name in blocked:
                return _text_result(f"BLOCKED: active exploitation not authorised for {name}")
            return await handler(args)

        return _fn

    sdk_tools = []
    tool_names: list[str] = []
    for name, description, schema, handler in specs:
        sdk_tools.append(tool(name, description, schema)(_wrap(name, handler)))
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
                            progress.emit("thought", text=_head(block.text, 140))
            elif isinstance(msg, ResultMessage):
                if getattr(msg, "result", None):
                    summary = msg.result
                    transcript.append(f"result {_head(msg.result)}")
    except Exception as exc:  # noqa: BLE001 - salvage partial work; only re-raise on a total loss
        transcript.append(f"error {_head(repr(exc))}")
        if not (findings or tool_calls or summary):
            raise

    return SdkExecOutcome(
        candidate_findings=findings,
        flow_batches=[f.flow_batch for f in findings],
        summary=summary,
        tool_calls=tool_calls,
        transcript=transcript,
    )
