# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **burpwn onboarding.** burpwn is a prebuilt release binary, not a Python package, so
  `git clone → uv sync → uv run` left first-time users without it and the agent failed at the first
  sandbox call. Two new commands close the gap: **`a2pwn install-burpwn`** resolves the host arch
  triple, downloads the matching release tarball from the burpwn repo and installs the binary onto a
  writable `PATH` dir (`--dest` / `--version` / `--force`; Linux only, extracts only the single
  `burpwn` member to avoid tarball path-traversal); **`a2pwn doctor`** is a standalone preflight (no
  auth gate, no model spend) that reports whether burpwn is on `PATH` and whether the host supports
  rootless user/network namespaces. `a2pwn run`/`resume` now run the burpwn preflight **before** the
  authorization gate, and the missing-binary hint points at `a2pwn install-burpwn`. README quickstart
  now includes the install + doctor steps.

- **`state_change` oracle** — a deterministic proof path for business-logic / CSRF findings (a
  targeted value provably appears/disappears/changes across a before/after pair), replacing the
  abstaining `llm_rubric` the kernel always rejected.
- **Seven new detection skills** — command-injection, nosql-injection, ldap-xpath-injection,
  file-upload, graphql, authentication, csrf (25 → 32 skills).
- **Opt-in wall-clock deadline** (`max_wall_secs`): a whole-engagement time cap that still builds the
  report from what was proven.
- **Structured report output.** Alongside `report.md`, every run now writes `report.json`
  (full `Report` model), `report.sarif` (valid SARIF 2.1.0, driver `a2pwn`, one result per finding
  with `proofTier`) and a self-contained `report.html` (inline CSS, all user/finding text escaped).
  `--format md,json,sarif,html` selects which to write (md+json always). The `Report` now carries
  engagement metadata (objective, targets, model labels, dispatches spent, started-at, duration) and
  the written `report_paths`.
- **Confirmed-not-reproduced tier.** Findings the oracle CONFIRMED but that the independent-verify
  dispatch could not replay (races / one-shot tokens / TOCTOU) are no longer silently dropped: they
  are surfaced in a distinct, clearly-labelled `Report.confirmed_findings` tier across md/json/sarif/
  html. The strict `findings` tier stays independently-verified-only.
- **Run-plan panel.** `a2pwn run` prints targets / objective / active-exploit (red when ON) / dos /
  executor+verifier models / caps / output dir **before** the authorization gate (a compact
  one-liner under `--yes`).
- **`a2pwn list`** enumerates prior runs (verified / confirmed-only counts, severity tally, objective,
  last updated). **`a2pwn resume --name X [--objective …]`** re-drives an existing thread id (the
  checkpointer resumes), recovering targets/objective from the prior run's `report.json`.
- **`--max-wall-secs`** flag maps to `cfg.max_wall_secs`.
- **TUI/plain polish.** Live findings dedup key now includes `param`; the header shows phase
  `round/max_phases` as the primary progress with the dispatch spend relabelled a "cost cap" gauge;
  the first Ctrl-C shows a graceful-finalize notice; `--plain` now prints the full findings summary.

### Fixed (latent bugs)

- **OOB oracle was dead.** The collaborator was constructed but its in-sandbox listener was never
  started, so the `oob` oracle — the strongest 0-FP signal — could never confirm a blind
  SSRF/XXE/deserialization/SQLi. It is now started at bootstrap and stopped on teardown (serialised
  behind a lock).
- **`marker` oracle auto-confirmed.** A full-text hit always matched the injection request's own
  echo of the marker; it now requires the marker in the **response** of a *different* flow that did
  not inject it (genuine stored / second-order propagation).
- **Verify fan-out ignored the caps.** The independent-verify branch emitted one sub-agent per
  queued finding regardless of `max_batch_width` / remaining budget; it is now clamped like the task
  branch, with the overflow carried to the next phase.
- **burpwn liveness.** Every MCP call is now bounded by a read timeout (`exec` gets a generous,
  exec-aware bound); a crashed `burpwn mcp` is detected via a returncode health-check and
  transparently respawned (crash-loop guarded); over-limit / EOF / broken-pipe lines degrade to a
  clean error instead of wedging; the `burpwn --json` CLI calls got a timeout.
- **Postgres checkpointer** now exits its async context manager symmetrically (was leaking pooled
  connections).

### Changed (detection quality)

- **`timing` oracle** requires the slowest sample to exceed the baseline (median of the rest) by a
  large fraction of the threshold — rejecting jitter and uniformly-slow endpoints instead of
  confirming on a single slow response.
- **`two_identity` oracle** accepts an optional anonymous/unauthorised control that must be denied,
  so a *public* resource can no longer masquerade as an IDOR.
- **`differential` oracle** length-delta noise floor raised off 1 byte.
- **Executor coverage.** "Report the moment you have proof, then stop" no longer truncates a surface:
  the executor must walk a co-located vuln-class checklist for every sink it touched before declaring
  it exhausted, and the per-sub-agent turn budget is configurable (`executor_max_turns`, default 40).

## [0.1.0] — 2026-07-17

First release. Validated end to end against the sanctioned BrokenCrystals lab: a single autonomous
run found, chained and independently verified 11 findings (8 critical / 3 high), led by a
cross-chained RCE → leaked Keycloak secret → forged admin token → Admin-API takeover.

### Added

- **Orchestration core.** Two-graph LangGraph design: a dispatch-only `MASTER` and stateless
  `SUB-AGENT` children, with a structural fork boundary that keeps the master history clean by
  construction (only `(task → clean result)` records; no sub-agent transcript can leak in).
- **Native SDK executor.** On the Claude Code subscription backend the executor drives the target
  through the `claude-agent-sdk`'s native in-process tool loop (trusted `tool_use`/`tool_result`),
  so the model exploits to depth instead of treating a replayed text transcript as prompt injection.
- **Live TUI.** A colored `rich` dashboard (default on an interactive terminal): header with
  target/model/phase/budget/elapsed, a panel of the concurrent sub-agent dispatches and their current
  activity, a findings panel that fills in by severity as candidates are confirmed and verified, a
  live tool-call feed, and a final summary with report/HAR paths. `--plain` for log output.
- **Docker image.** `own2pwnfr/a2pwn` bundles a2pwn, all deps, the burpwn sandbox and a Claude Code
  CLI; run with `--privileged` and either a mounted `~/.claude` or an `ANTHROPIC_API_KEY`.
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
