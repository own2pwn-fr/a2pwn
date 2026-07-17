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
    executor: BackendConfig = Field(default_factory=BackendConfig)
    # Opus-class default: distinct from the executor to keep the adversarial verify honest.
    verifier: BackendConfig = Field(
        default_factory=lambda: BackendConfig(provider="anthropic", model="claude-opus-4-5")
    )

    @model_validator(mode="after")
    def _verifier_distinct(self) -> "RoleModels":
        # Enforce role-model separation: verifier must not equal executor (provider + model).
        if (self.verifier.provider, self.verifier.model) == (
            self.executor.provider,
            self.executor.model,
        ):
            raise ValueError("verifier model must differ from executor (adversarial independence)")
        return self


class EngagementSpec(BaseModel):
    """Scope + authorization envelope for one engagement."""

    name: str
    targets: list[str]
    in_scope: list[str] = Field(default_factory=list)
    authorization_acknowledged: bool = False
    active_exploit_allowed: bool = False
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
    checkpoint_uri: str | None = None  # None => SqliteSaver default box path
    disclaimer_ack: bool = False
