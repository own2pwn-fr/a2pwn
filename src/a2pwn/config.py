"""All configuration pydantic models + role-model separation validation."""

from typing import Literal

from pydantic import BaseModel, Field, model_validator

Provider = Literal[
    "claude-code",
    "anthropic",
    "openai",
    "azure_openai",
    "bedrock_converse",
    "google_vertexai",
    "google_genai",
    "litellm",
    "codex",
    "antigravity",
]


class BackendConfig(BaseModel):
    """A single role's model backend selection and passthrough options."""

    provider: Provider = "claude-code"
    model: str | None = None
    kwargs: dict = Field(default_factory=dict)
    options: dict = Field(default_factory=dict)  # ClaudeAgentOptions passthrough for claude-code


class RoleModels(BaseModel):
    """Per-role backends. The verifier must be adversarially independent of the executor."""

    master: BackendConfig = Field(default_factory=BackendConfig)
    clarifier: BackendConfig = Field(default_factory=BackendConfig)
    # Executor defaults to the subscription backend (claude-code -> sonnet).
    executor: BackendConfig = Field(default_factory=BackendConfig)
    # Opus-class default, distinct from the executor to keep the adversarial verify honest — but
    # still on the default subscription backend so the out-of-the-box config runs with NO API key.
    verifier: BackendConfig = Field(
        default_factory=lambda: BackendConfig(provider="claude-code", model="opus")
    )

    @model_validator(mode="after")
    def _verifier_distinct(self) -> "RoleModels":
        # Enforce role-model separation: verifier must not equal executor (provider + model).
        if (self.verifier.provider, self.verifier.model) == (
            self.executor.provider,
            self.executor.model,
        ):
            spec = f"{self.executor.provider}:{self.executor.model}"
            raise ValueError(
                f"verifier backend ({spec}) must differ from the executor ({spec}) for adversarial "
                "independence — override --verifier-model or --executor-model "
                "(e.g. keep the executor default and pass --verifier-model opus)."
            )
        return self


class EngagementSpec(BaseModel):
    """Scope + authorization envelope for one engagement."""

    name: str
    targets: list[str]
    in_scope: list[str] = Field(default_factory=list)
    authorization_acknowledged: bool = False
    active_exploit_allowed: bool = False
    # Advisory only: dos_allowed is surfaced to the planner/executor prompts as guidance; a2pwn does
    # NOT deterministically block DoS-class traffic at the tool layer, so DoS restraint is prompt-only.
    dos_allowed: bool = False
    oob_listener: str | None = None  # external collaborator base (host:port) if provided
    session: str  # burpwn session name (== name by default)


class A2pwnConfig(BaseModel):
    """Top-level run configuration."""

    engagement: EngagementSpec
    models: RoleModels = Field(default_factory=RoleModels)
    max_clarify_rounds: int = 4
    max_verify_rounds: int = 3
    max_phases: int = 12
    max_batch_width: int = 6  # hard cap on parallel Sends per phase
    max_dispatches: int = 200  # global budget ceiling
    # Turn budget for ONE executor sub-agent. It must fit exhausting *every* vuln class co-located on
    # a surface (a param vulnerable to XSS *and* SQLi *and* SSRF), not just proving the first one, so
    # the "report the moment you have proof, then stop" discipline never truncates coverage.
    executor_max_turns: int = 40
    # When the master would naturally STOP (no work left, "done"), a continuation judge decides
    # whether the engagement is genuinely complete or should push further. This caps how many times
    # the judge may override "done" and re-open the engagement, so it cannot loop forever.
    max_continuations: int = 2
    # Auto-compaction: once a ReAct sub-agent's transcript passes this many approx tokens, feed the
    # model the base prompt + a running summary + recent turns so a long exploitation runs to
    # completion instead of overflowing the context window. 0 disables it.
    compaction_token_threshold: int = 150_000
    checkpoint_uri: str | None = None  # None => SqliteSaver default box path
    # Optional wall-clock safety net (seconds) for the whole engagement. The dispatch/phase budgets
    # bound the *count* of work, not its duration; a slow target or model could still stall a phase.
    # When set, run_engagement aborts the drive loop past this deadline and still builds the report
    # from whatever was proven. None disables it (the per-call burpwn/model timeouts still apply).
    max_wall_secs: int | None = None
    # One-time authorization acknowledgement (the CLI ToS gate). Distinct from per-dispatch approval.
    disclaimer_ack: bool = False
    # Interactive step-through: prompt the operator to approve EACH dispatch. Off by default, so
    # approval is upfront-only (the one-time ack) and the run proceeds autonomously. Only takes effect
    # when active exploitation is not pre-authorized (active_exploit_allowed=False keeps the gate).
    step_through: bool = False
