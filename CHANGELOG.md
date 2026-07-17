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
- **CLI.** `a2pwn run` with a ToS/authorization acknowledgement gate, SQLite checkpointing by default
  (Postgres drop-in), streamed telemetry and resume.

### Notes

- The default `claude-code` backend uses a personal Claude Code subscription for programmatic use,
  which is a gray area under Anthropic's terms. a2pwn runs locally, with your login, for your own use.
