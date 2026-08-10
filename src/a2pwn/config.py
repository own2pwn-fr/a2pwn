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


class LoginRecipe(BaseModel):
    """Replay-based login: one HTTP request issued through the burpwn sandbox, then token capture.

    Covers APIs and ordinary form logins without any browser. ``extract`` maps a placeholder name to
    a regex with ONE capture group, applied to the login response body then its headers; ``inject``
    maps a header name to a template that may reference those placeholders (``{token}``). Any
    ``Set-Cookie`` on the response is harvested automatically unless ``harvest_cookies`` is off.
    """

    url: str
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    extract: dict[str, str] = Field(default_factory=dict)
    inject: dict[str, str] = Field(default_factory=dict)
    harvest_cookies: bool = True


class IdentitySpec(BaseModel):
    """One named identity the executor can act as.

    Access-control classes (IDOR/BOLA, cross-tenant CRUD, privilege escalation) are only provable
    with more than one identity — the ``two_identity`` oracle needs an attacker A, a victim/owner B
    and ideally an unauthenticated negative control C. Declaring identities here is what makes those
    oracles reachable at all; without them a run can only ever test the unauthenticated surface.

    Credentials come from static ``headers``/``cookies`` and/or a replay ``login`` recipe. Resolution is lazy and cached (see
    :mod:`a2pwn.identity`), and re-runs on a 401/403 so a long engagement survives session expiry.
    """

    name: str
    description: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    login: LoginRecipe | None = None
    # Marks the deliberate unauthenticated identity used as the two_identity negative control.
    anonymous: bool = False

    @property
    def authenticated(self) -> bool:
        return bool(self.headers or self.cookies or self.login)


class EngagementSpec(BaseModel):
    """Scope + authorization envelope for one engagement."""

    name: str
    targets: list[str]
    in_scope: list[str] = Field(default_factory=list)
    # Carve-outs from the allow-list, always winning over it. Entries are host globs
    # ("legacy.example.com", "*.internal.example.com"), URLs with a path subtree
    # ("https://app.example.com/admin/billing"), or bare path globs ("/admin", "/*.bak").
    # Real scopes are routinely "*.example.com EXCEPT these" — and since a2pwn now discovers hosts
    # by itself (subdomain enumeration seeded at bootstrap), an allow-list-only model would happily
    # queue a host the client explicitly carved out.
    exclude: list[str] = Field(default_factory=list)
    # Named identities the executor can act as (see IdentitySpec). Empty => unauthenticated testing
    # only, which is the historical behaviour.
    identities: list[IdentitySpec] = Field(default_factory=list)
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
    # the "report the moment you have proof, then stop" discipline never truncates coverage. 40 was
    # observed exhausting repeatedly (16 times in one real multi-API engagement) on ordinary
    # recon->exploit->verify-retry sequences against a handful of REST endpoints — raised to 60.
    executor_max_turns: int = 60
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
    # REAL spend ceilings, as opposed to max_dispatches which only counts dispatches. One dispatch
    # is anywhere between a handful of turns and 60 turns with a 150k-token compaction, so a
    # dispatch count is a poor proxy for cost — two runs at the same max_dispatches can differ by an
    # order of magnitude in tokens spent. When set, the routers stop the engagement and build the
    # report from what was proven, exactly like the dispatch cap. None disables the ceiling.
    max_usd: float | None = None
    max_tokens: int | None = None
    # Traffic policy, enforced in the tool wrappers on BOTH executor paths (not prompt guidance).
    # max_rps throttles every target-facing call to a global rate; fuzz_max_requests clamps how many
    # payloads one Intruder attack may fire. None/0 disables the corresponding limit.
    max_rps: float | None = None
    fuzz_max_requests: int = 5_000
    # Circuit breaker: after this many CONSECUTIVE blocked-looking responses (429 / 403 wall / WAF
    # interstitial) the target is considered to be blocking us. Further target-facing calls refuse
    # with an explanation instead of burning the remaining budget against a WAF — a blocked target
    # otherwise produces a 0-finding report indistinguishable from a clean one. 0 disables it.
    block_threshold: int = 25
    # One-time authorization acknowledgement (the CLI ToS gate). Distinct from per-dispatch approval.
    disclaimer_ack: bool = False
    # Interactive step-through: prompt the operator to approve EACH dispatch. Off by default, so
    # approval is upfront-only (the one-time ack) and the run proceeds autonomously. Only takes effect
    # when active exploitation is not pre-authorized (active_exploit_allowed=False keeps the gate).
    step_through: bool = False
