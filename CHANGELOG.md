# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — unreleased

### Added

- **Orchestration core.** Two-graph LangGraph design: a dispatch-only `MASTER` and stateless
  `SUB-AGENT` children, with a structural fork boundary that keeps the master history clean by
  construction (only `(task → clean result)` records; no sub-agent transcript can leak in).
- **Clarify fork.** Sub-agents ask clarifying questions answered in parallel by isolated forks seeded
  with a compacted snapshot of the master context, folded into one self-contained refined prompt.
- **Auto-compaction.** Once a ReAct sub-agent's transcript passes a token budget
  (`compaction_token_threshold`, default 150k), a `pre_model_hook` feeds the model the base prompt +
  a running summary of what has been done + the recent turns, so a long exploitation runs to
  completion instead of overflowing the context window. The full transcript stays in state, so the
  finding-harvest never loses a `report_finding` artifact.
- **Continuation judge.** When the master would naturally stop (planner out of work), a judge agent
  decides autonomously whether the engagement is genuinely complete or should push further — replacing
  the human "here is what I did; want me to continue?" prompt — and injects concrete follow-up tasks
  when surface remains untested. Bounded by `max_continuations`; hard stops (budget / phase cap /
  TaskStop) always win.
- **Adversarial verification.** An intra-task verifier on a distinct, stronger role-model re-derives
  every candidate through a deterministic oracle (differential / OOB / marker / timing / two-identity)
  and rejects any finding without real captured evidence; a separate independent-verify dispatch
  reproduces confirmed findings from a clean slate. Reconciliation is monotone (promotes, never drops).
- **burpwn integration.** `BurpwnClient` (stdio MCP hot-loop + CLI lifecycle/export) and
  `FlowBatchManager` (batch == finding evidence, tagging/highlighting, capture assertion,
  tls-passthru detection, NUL stripping).
- **Backends.** `make_model` factory: Claude Code subscription (default, OAuth via `claude-agent-sdk`,
  API key scrubbed), Anthropic, OpenAI, Bedrock, Vertex, Google GenAI, litellm, plus best-effort
  Codex/Antigravity.
- **OOB collaborator.** In-sandbox listener (captured as flows) + external Interactsh-style client for
  blind SSRF/XXE/deserialization/SQLi.
- **Skill & tool catalog.** Self-describing skills with FTS/tag retrieval, payload references to pinned
  vendored sources, and tool wrappers that always run through `burpwn exec`.
- **Cost/termination safety.** Global dispatch budget, `TaskStop` kill switch, and hard caps on
  clarify/verify rounds, phases and batch width.
- **Deterministic scope enforcement.** In-scope hosts (from `--target`) are registered with the
  burpwn sandbox at bootstrap (`intercept_scope`) and enforced by the tool wrappers, so a
  hallucinated/redirected/injected URL cannot drive off-scope traffic (incl. cloud metadata).
- **CLI.** `a2pwn run` with a ToS/authorization acknowledgement gate, SQLite checkpointing by default
  (Postgres drop-in), streamed telemetry and resume.

### Changed

- **burpwn preflight.** `a2pwn run` (and `bootstrap`) now check `burpwn` is on `PATH` and abort with
  an actionable install message *before* constructing models or spending LLM calls, instead of
  failing lazily deep inside the ReAct loop.
- **Honest approval semantics.** Authorization is a one-time upfront acknowledgement; per-dispatch
  approval is now opt-in via `--step-through` (previously the ack silently auto-approved every
  interrupt). `--dos` is documented as advisory/prompt-only (not a tool-layer block).
- **Robust teardown.** `run_engagement` closes the burpwn client and the checkpointer independently
  in `finally`, so a failing client close no longer orphans the checkpointer's worker thread; the
  checkpoint stays durable and the run resumable by thread id.

### Notes

- The default `claude-code` backend uses a personal Claude Code subscription for programmatic use,
  which is a gray area under Anthropic's terms. a2pwn runs locally, with your login, for your own use.
