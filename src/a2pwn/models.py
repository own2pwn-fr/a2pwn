"""All shared domain pydantic models incl. the SubAgentInput fork payload and compacted context view."""

from typing import Literal

from pydantic import BaseModel, Field

from a2pwn.config import EngagementSpec

_EVIDENCE_SNIPPET = 240
_SUMMARY_SNIPPET = 400


class QAPair(BaseModel):
    """One clarify question and the isolated fork's answer."""

    question: str
    answer: str


class TaskSpec(BaseModel):
    """A unit of work dispatched to a stateless sub-agent."""

    task: str
    intent: Literal["recon", "exploit", "chain", "verify"] = "exploit"
    hints: list[str] = Field(default_factory=list)
    target: str | None = None  # None or recon => treated read-only for partitioning
    mutates: bool = True  # False => never serialized against siblings


class ContinuationVerdict(BaseModel):
    """A continuation judge's ruling when the master would otherwise stop: is the engagement
    genuinely complete, or is there important in-scope surface still worth pursuing?"""

    complete: bool
    rationale: str = ""
    # Concrete follow-up tasks to run if not complete (fed straight into the master's pending queue).
    remaining_work: list[TaskSpec] = Field(default_factory=list)


class FlowBatchRef(BaseModel):
    """A burpwn workspace of captured flows that is the evidence backing a finding."""

    workspace: str
    workspace_id: int | None = None
    tag: str
    color: str = "red"
    flow_ids: list[int] = Field(default_factory=list)
    exec_ids: list[str] = Field(default_factory=list)
    key_flow: int | None = None
    note: str | None = None


class Finding(BaseModel):
    """A single vulnerability observation, grounded in a captured flow batch."""

    key: str  # canonical == f'{vuln_class}|{target}|{param or "*"}'
    vuln_class: str
    sub_variant: str | None = None
    severity: Literal["info", "low", "medium", "high", "critical"]
    target: str
    param: str | None = None
    evidence: str  # NUL-stripped before persistence
    confirmed: bool = False
    independently_verified: bool = False
    oracle_kind: Literal[
        "differential",
        "oob",
        "marker",
        "signature",
        "timing",
        "two_identity",
        "llm_rubric",
    ]
    # Oracle inputs threaded from the tool that reported the finding into the deterministic
    # adjudicator (fail-closed). All optional/additive: defaults preserve old behaviour.
    oracle_signals: list[str] = Field(default_factory=list)
    correlation_id: str | None = None
    oracle_expect: dict = Field(default_factory=dict)
    flow_batch: FlowBatchRef
    enables: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    @staticmethod
    def make_key(vuln_class: str, target: str, param: str | None) -> str:
        return f'{vuln_class}|{target}|{param or "*"}'

    def rank(self) -> int:
        """3 = independently verified, 2 = confirmed, 1 = candidate."""
        return 3 if self.independently_verified else 2 if self.confirmed else 1


class VerifierReport(BaseModel):
    """Adversarial verifier's per-candidate verdict for one sub-agent task."""

    accepted: bool
    confirmed: list[Finding] = Field(default_factory=list)
    rejected: list[Finding] = Field(default_factory=list)
    not_done: list[str] = Field(default_factory=list)
    capture_ok: bool = True
    notes: str = ""


class CleanResult(BaseModel):
    """The ONLY value the fork boundary reads back from a sub-agent."""

    dispatch_id: str
    status: Literal["confirmed", "partial", "no_finding", "blocked"]
    findings: list[Finding] = Field(default_factory=list)
    flow_batches: list[FlowBatchRef] = Field(default_factory=list)
    residual_gaps: list[str] = Field(default_factory=list)
    next_hops: list[TaskSpec] = Field(default_factory=list)
    summary: str = ""


class DispatchRecord(BaseModel):
    """A canonical, curated history entry: task -> result, with no sub-agent chatter."""

    dispatch_id: str
    kind: Literal["single", "batch", "verify_workflow"]
    task: str
    result: CleanResult


class MasterContextView(BaseModel):
    """Immutable projection of canonical master state handed to forks."""

    objective: str
    engagement: EngagementSpec
    history: list[DispatchRecord]
    known_findings: list[Finding]

    def compact(self, k: int = 8) -> "MasterContextView":
        """Recent-k DispatchRecords + trimmed finding summaries only.

        Bounds the payload handed to every isolated fork so that fanning out one fork per
        clarify question cannot blow up as O(history * questions).
        """
        recent = self.history[-k:] if k > 0 else []
        slim_history = [
            rec.model_copy(update={"result": _slim_result(rec.result)}) for rec in recent
        ]
        slim_findings = [_slim_finding(f) for f in self.known_findings]
        return MasterContextView(
            objective=self.objective,
            engagement=self.engagement,
            history=slim_history,
            known_findings=slim_findings,
        )


class SubAgentInput(BaseModel):
    """Per-invocation fork payload — never the full MasterState."""

    dispatch_id: str
    intent: Literal["task", "verify"]
    spec: TaskSpec | None = None
    candidate: Finding | None = None
    master_ctx: MasterContextView


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _slim_finding(f: Finding) -> Finding:
    return f.model_copy(update={"evidence": _truncate(f.evidence, _EVIDENCE_SNIPPET)})


def _slim_result(res: CleanResult) -> CleanResult:
    return res.model_copy(
        update={
            "findings": [_slim_finding(f) for f in res.findings],
            "summary": _truncate(res.summary, _SUMMARY_SNIPPET),
        }
    )
