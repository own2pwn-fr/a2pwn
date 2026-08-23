# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Named identities — authenticated testing, and the `two_identity` oracle made reachable.** The
  single largest gap in the tool: `EngagementSpec` carried no way to supply a credential, so the
  whole authenticated surface was untestable and five skills built on it (`access-control`,
  `idor-bola`, `jwt-auth`, `csrf`, `authentication`) could only fire if the executor happened to
  self-register accounts. The `two_identity` oracle is written around an attacker **A** reaching
  owner **B**'s object with an unauthenticated **C** as the negative control — three identities
  nothing could provide. `IdentitySpec` now declares identities with static headers/cookies, a
  replay `login` recipe (one HTTP request through the sandbox, regex capture off the response, a
  header template to inject). **The burpwn-is-the-only-egress invariant holds for both** — every
  login request goes through `burpwn exec`. New `a2pwn.identity` resolves
  lazily, caches, shares one login across a parallel fan-out (per-name lock), and invalidates on a
  401/403 so a session expiring mid-engagement self-heals instead of turning every later probe into
  a false "access control held" negative. Exposed as `as_identity` on `burpwn_exec`/`burpwn_req_replay`
  plus new `identity_list` / `identity_request` tools, on **both** executor paths.
- **Scope carve-outs (`exclude`, `--exclude`).** The allow-list was the only scope primitive, but
  real scopes are stated as "`*.example.com` **except** these" — and since a2pwn now discovers hosts
  by itself (subdomain enumeration seeded at bootstrap, previous release), an allow-list-only model
  would happily queue a host the client explicitly carved out. Entries are host globs
  (`legacy.example.com`, `*.internal.example.com`), URL path subtrees
  (`https://app.example.com/admin`) or bare path globs (`/admin/billing`). Exclusions are checked
  after the allow-list and always win. Path matching respects segment boundaries, so `/admin` does
  not carve out an unrelated `/administration`.
- **Real spend ceilings (`--max-usd`, `--max-tokens`).** `max_dispatches` counts dispatches, which
  is a poor proxy for cost — one dispatch is anywhere from 3 turns to 60 with a 150k-token
  compaction, so two runs at the same cap can differ by an order of magnitude. (The TUI even
  labelled the dispatch bar "cost cap", which it was not.) `MasterState` gains `spent_usd` /
  `spent_tokens` `operator.add` channels alongside `spent`, fed from the SDK's own `ResultMessage`
  (`total_cost_usd` / `usage`) — never an estimate. Both are enforced by the same routers as the
  dispatch cap and reported in md/html/json.
- **Traffic policy: `--max-rps`, `--fuzz-max-requests`, and a blocked-target circuit breaker**
  (`a2pwn.throttle`). `concurrency`/`delay_ms` previously existed only as Intruder parameters the
  model chose for itself, so nothing bounded the aggregate rate across a parallel fan-out. More
  importantly: once a WAF answers 429/403 to everything, every oracle legitimately fails to
  re-derive, every candidate is rejected, and the run spends its remaining budget producing a
  0-finding report **indistinguishable from a genuinely secure target**. The breaker trips after a
  run of consecutive WAF-shaped blocks, refuses further target-facing calls with an explanation the
  model can act on, and the report carries a loud "TESTING WAS BLOCKED — the absence of findings is
  NOT evidence of security" banner. A plain 403 without a WAF body signature deliberately does not
  count, since healthy access-control testing produces those constantly by design.
- **`a2pwn retest --baseline <report.json|run>`** — the second half of the pentest cycle, which
  `run` alone could not express. Seeds one dispatch per baseline finding (deterministic: no baseline
  finding can be quietly skipped because the planner judged it uninteresting), re-derives each
  through the same fail-closed oracle kernel, and reports the delta. Findings that no longer
  reproduce are reported as **"fixed or unreproducible"**, never flatly as fixed: a moved endpoint
  or an expired test credential is indistinguishable from a real fix, and signing a live bug off as
  remediated is the one mistake this command must not make.
- **Declarative engagement files (`--config engagement.yaml`).** Flags stopped scaling at a 25-host
  scope (the pain that drove the subdomain-enumeration work, only half-solved by it), and
  credentials must not go in shell history or the process table. Every key mirrors a flag and an
  explicit flag still wins; an unknown top-level key is an **error**, because a typo'd `exlude:`
  silently widening the tested scope is precisely what the file exists to prevent. Identities are
  validated at load time, so a malformed credential block fails before the authorization gate and
  before any model spend.
- **Durable `run.jsonl` for every run** — dispatches, tool calls, tool failures, model refusals and
  each adjudication's **reject reason**, written whether or not the TUI is on. The event bus was
  display-only, which is why the three silently-dropped-finding bugs fixed last release could only
  be found by re-reading raw model transcripts by hand.
- **`remediation` and `identity` on every finding.** The report carried severity, CVSS, CWE and a
  reproduction — everything needed to *confirm* a bug and nothing about closing it, which is the
  first thing its reader looks for. `identity` names who the finding was proven as: "A reached B's
  order" is unreadable if the report never says who A and B were. Rendered in md/html and exported
  in sarif.
- **Five new skills** (37 total): `recon/subdomain-takeover` (directly complementary to the
  automatic subdomain enumeration — recon output *is* the vulnerability there), `web/oauth-oidc`,
  `web/mass-assignment`, `web/websocket`, `web/api-business-logic`. The last three are the API
  classes the `state_change` and `two_identity` oracles could already prove but no skill taught.

- **Automatic subdomain enumeration, seeded before the first planning phase.** Previously the
  master only ever saw whatever single hostname the operator typed — auditing
  `*.thinginthefuture.com` this session needed the operator to manually enumerate subdomains via
  crt.sh/hackertarget entirely outside a2pwn, then pass 25 `--target` flags by hand. Bootstrap now
  seeds one deterministic recon task (`subfinder` + `httpx`, run through the normal sandboxed
  fork boundary) per apex-shaped target host (`a2pwn.scope.is_apex_host`: <=2 labels, e.g.
  `example.com`; an already-specific host like `coreapi.example.com` is left alone) directly into
  `pending`, so phase 0 is pure deterministic recon with no LLM planner call at all. The executor
  calls a new `propose_targets` tool once per genuinely live, distinct host worth testing; each
  proposal is threaded through exactly like a cross-chain follow-up (`CleanResult.next_hops` →
  `pending`), so by the time the planner's LLM runs for the first time it already has concrete,
  discovered hosts queued instead of a single bare apex domain. Available on both executor paths
  (SDK native tools + LangChain `a2pwn.tools.recon_tools`); a discovered host outside the
  engagement's targets/in_scope is dropped defensively before ever reaching the queue.
- Fixed a pre-existing gap surfaced while wiring the above: `runtime.py`'s LangChain-path tool
  assembly called `burpwn_tools(client)` without `engagement`, so the documented Python-level
  scope refusal ("the tool wrappers deterministically refuse traffic to out-of-scope hosts") was
  never actually engaged in a real run on that executor path — only burpwn's own server-side
  sandbox containment applied. Now wired as `burpwn_tools(client, cfg.engagement)`. The follow-up
  this entry flagged as still open — the default `claude-code`/native-SDK executor path
  (`sdk_agent.py`) having no client-side scope check at all — **is closed in this same release**;
  see "The client-side scope refusal was OFF on the default backend" under Fixed.

- **CVSS 3.1 + CWE on every finding, deterministic repro in every report format.** Writing a
  client-facing report by hand after a real engagement required manually computing CVSS scores and
  querying burpwn flow-by-flow for curl/raw-HTTP reproductions — the generated report had neither.
  `report_finding` now accepts `cvss_vector`/`cwe_ids` (both tool paths; the executor is instructed
  to always include them); a new `a2pwn.cvss.parse_cvss31` re-derives the numeric base score
  straight from the FIRST.org formula so the report never trusts the model's own arithmetic (same
  discipline as the oracle kernel) — an unparseable vector is surfaced as-is, never hidden. At
  report-build time, each finding's key flow is fetched from burpwn and rendered as a verbatim raw
  HTTP request/response block plus a reconstructed `curl` reproduction (both best-effort: a fetch
  failure degrades to no repro block, never drops the finding). Rendered in md/html (new CVSS/CWE
  column + repro sections) and sarif (`cvssScore`/`cweIds`/the GitHub-convention
  `security-severity` property).

### Changed

- **One tool definition, two adapters** (new `a2pwn.toolcore`). The LangChain wrappers and the
  native-SDK wrappers were independent hand-maintained copies of the same surface, and every
  divergence shipped as a bug — the `state_change` allow-list, the fuzz-contract fixes written
  twice, and the scope refusal below. Both are now thin adapters over one `ToolSpec` list, and
  `tests/test_tool_parity.py` asserts they still agree (tool names, `report_finding` fields, oracle
  allow-lists vs the `Finding` model *and* the dispatcher).
- **`graph.py` split along the fork boundary** into `graph.py` (master state, routers, fork
  boundary; 621 lines) and `subgraph.py` (everything that dies with one dispatch: clarify Q&A, the
  ReAct loop, the verifier critique, the fail-closed adjudicator; 559 lines), down from a single
  1117-line file. `graph.py` re-exports the sub-agent names, so existing imports are unaffected.

### Added (exhaustiveness as a data structure, not a prompt)

- **Attack-surface inventory and a coverage matrix** (`a2pwn.coverage`). Until now the answer to
  "did we test everything?" lived entirely in prose: the executor prompt said to "walk the
  co-located class checklist", the continuation judge was told to "bias toward THOROUGHNESS", and
  no structure anywhere recorded which endpoint had been probed for which class. The master carried
  tasks, findings and a budget — a *negative* result left no trace at all, so an endpoint probed and
  found clean was indistinguishable from one no dispatch ever reached, and a 0-finding report could
  not say which of the two it was describing.
  - `Asset` is one addressable unit of surface (host, endpoint, parameter, JS bundle, WebSocket,
    GraphQL). Assets are harvested **deterministically from captured burpwn flows**, not from the
    model's narration: the traffic cannot invent an endpoint nobody reached, and cannot forget one
    the model neglected to mention. Path segments that look like ids (numeric, UUID, long hex)
    collapse to `{id}`, so a paginated site yields one endpoint rather than ten thousand.
  - `Probe` is one `(asset, vuln_class)` cell with a verdict. The cross product of applicable
    classes over discovered assets **is** the coverage matrix, and its untested cells are a
    work-list. Classes are attached at the coarsest level that makes sense — `cors` is a property
    of an origin and is tested once per host, not once per parameter — so the matrix stays a
    work-list rather than a combinatorial explosion.
  - The `surface` channel is reduced monotonically, exactly like `findings`: a cell only moves
    toward more knowledge, so a parallel `Send` fan-out cannot let one sibling erase another's
    coverage.
- **`record_probe`**, on both executor paths. This is how a sub-agent writes a *negative* result
  down — the thing the oracle kernel structurally could not record, since it only ever promotes
  proof. A class the model claims as `proven` here is **downgraded to `probed`**: only the
  deterministic oracle promotes a cell, so a model cannot talk its way into a covered matrix.
- **Deterministic coverage expansion.** When the planner returns no tasks, `plan` expands untested
  matrix cells into concrete dispatches instead of letting the run stop. The LLM planner is a good
  *prioritiser* and a poor *enumerator* — it sees eight history records and is asked to remember
  every endpoint it has seen and every class it has not yet tried. The matrix remembers instead, so
  exhaustiveness stops depending on the planner's recall. The planner and the continuation judge
  both now receive a `coverage` digest naming exactly which cells have no verdict, and the planner
  finally sees its own remaining budget (it was told to "stop when the budget is near exhaustion"
  while being shown no budget at all).
- **A "Coverage" section in every report artifact.** The deliverable had no "what was tested"
  statement at all, so a 0-finding report read exactly like a report on a target nobody visited —
  the biggest credibility gap in the output. `Report.coverage` now freezes the matrix as plain JSON
  (stats plus a per-asset verdict breakdown), markdown renders assets by kind, cells/covered%/
  untested and an explicit **list of what was NOT tested** (asset → classes), the HTML gets the
  same as a table and the SARIF run object carries the stats in `properties` (run-level, not
  per-result). When the traffic circuit breaker tripped, the section repeats the blocked banner and
  says outright that the percentage is a floor, not a measurement. The live TUI footer and the
  final summary show covered% and the untested count for the same reason.

- **An artifact store, and the ability to forget** (`a2pwn.artifacts`). Bulky tool output used to be
  truncated at 200 000 characters straight into the transcript — the worst of both worlds: the model
  pays for 200 kB of noise and still cannot see the part it needed, because the interesting string in
  a minified bundle is almost never in the first 200 kB. Results past a threshold are now stored out
  of band and replaced with a short envelope; the agent reaches in with `artifact_grep` /
  `artifact_slice`, paying only for what it reads. `artifact_drop` is the other half: having
  concluded a 3 MB blob is a vendor bundle with no app code, the agent replaces it with that one
  sentence, so neither this turn nor a later retry round pays to rediscover it. The store is shared
  across dispatches and keyed by content hash, so two sub-agents probing the same host do not each
  pull the same bundle through the sandbox, and it spills next to the run's other evidence so a
  bulky body stays inspectable after the run.
- **SDK auto-compaction is now visible.** `compaction.py`'s `pre_model_hook` only ever applied to the
  LangChain path; the default `claude-code` backend compacts inside the SDK, where a2pwn could not
  see it. Compaction is the moment a long exploit leg loses detail — potentially including the task
  statement itself, which lives in the compactable first user turn rather than the system prompt — so
  a `compact_boundary` is logged, counted on the dispatch outcome and emitted to `run.jsonl`. When a
  dispatch appears to have lost the plot, this is the event that explains it.

### Fixed (coverage: the executor was working almost blind)

- **The executor was seeded with 1 skill out of 37.** `_seed_skills` built its FTS query from the
  engagement name and its target **hostnames**, then asked the catalog for the most *relevant*
  skills. Hostnames share no vocabulary with a methodology corpus, so the match scored 36 of the 37
  skills to zero: a real run against `ginandjuice.shop` seeded `burpwn` and nothing else, and every
  dispatch went out with no SQLi, XSS, SSRF, IDOR, JWT, GraphQL, race-condition or smuggling
  methodology at all. Relevance filtering is the wrong shape here anyway — which classes apply is
  not known until the target has been seen, which is the whole point of a pentest. New
  `catalog.all_cards()` seeds the entire catalog; skills are cheap (one zero-arg tool each, ~800
  chars of description, the SKILL.md body loaded only when the model calls the tool).
- **Independent verification could pass by doing nothing.** `accepted = not rejected` made "the
  fresh child reported no candidates" indistinguishable from "the fresh child reproduced it": a
  verify dispatch that gave up, refused, exhausted its turns or crashed on a swallowed retry round
  produced zero candidates, hence zero rejections, hence `accepted=True` — and distill then promoted
  the **original** candidate to `independently_verified`. That is a hole straight through the
  product's headline 0-FP guarantee. A verify dispatch must now re-derive **the** candidate it was
  sent to check (matched on the canonical key, falling back to vuln_class+target), so stumbling onto
  an unrelated bug no longer verifies the one that was asked about.
- **Planned tasks evaporated between phases.** `integrate` rebuilt the queue as
  `deferred + next_hops`, discarding everything that was planned but not dispatched. A phase is
  clamped to `max_batch_width`, and a phase with anything in the verify queue dispatches verifies
  **only** — so in the common case the entire task batch was dropped and the run looked complete
  with whole planned tasks never attempted. `CleanResult` now echoes back the `TaskSpec` that was
  dispatched, and the queue keeps every entry no dispatch answered.
- **History recorded what happened, never what was asked.** `DispatchRecord.task` was filled with
  the *result summary*; the dispatched `TaskSpec` was never persisted anywhere. The continuation
  judge — whose entire job is spotting in-scope work that was not done — was therefore reading a
  history that contained no requests. It now records the requested task.
- **Nothing stopped the same work being dispatched twice.** `next_hops` (cross-chain edges,
  `propose_targets` discoveries) and the continuation judge all append into the queue with no memory
  of each other, and the only guard against repeats was an English sentence in the planner prompt. A
  host discovered by two dispatches, or a chain edge re-emitted each time its origin finding is
  re-confirmed, burned budget the untested surface needed. Repeat work is now dropped deterministically
  on an intent+target+normalised-text signature.
- **`a2pwn resume` re-authorised excluded scope.** It rebuilt the `EngagementSpec` from `targets`
  alone, silently dropping every `exclude` carve-out — so resuming a run probed exactly the hosts and
  paths the client had put off-limits, the one direction a scope mistake must never go. It also lost
  all identities, making the whole authenticated surface untestable without saying so. The scope
  envelope (`in_scope`, `exclude`) is now recorded in `report.json` and restored; **credentials are
  deliberately still never written there** (a report is a deliverable that gets mailed around), so
  `resume` gains `--config` to re-supply them and warns loudly, naming the identities, when a prior
  run used some and none were provided. `--exclude` can add carve-outs on resume.
- **`a2pwn retest` ignored the baseline's scope and traffic policy.** Carve-outs were dropped unless
  restated in `--config`, and `block_threshold` / `max_tokens` / `fuzz_max_requests` were pinned to
  their defaults no matter what the config said — even though a retest hits the same WAF as the run
  it re-checks.

### Fixed

- **Two bugs found by validating against a live sandbox rather than fakes.** Both had shipped:
  (a) `identity.py` assumed a burpwn `exec` result carries stdout — it does **not**, it carries only
  `captured_request_ids`/`exec_id`/`exit_code`, so the replay login's fallback path was dead and a
  login that captured no flow surfaced as a misleading "extraction did not match the response"
  instead of "the request never reached the target"; (b) the traffic circuit breaker observed the
  `exec` result dict directly, which contains no status, so it was **inert against exec-driven
  traffic** — most of a run's traffic — and a WAF-blocked engagement would never have tripped it.
  The breaker now reads the last captured flow (one extra `req_show`, only while armed). The unit
  tests that "covered" both had invented a `stdout` key the tool never returns; they now encode the
  real shape.
- **A headless-browser (Playwright) identity login was built, tested live, and removed.** Chromium
  cannot start inside the burpwn sandbox: it launches and is immediately killed with SIGTRAP because
  its namespace/seccomp layer cannot nest inside bubblewrap, and
  `--no-sandbox`/`--no-zygote`/`--single-process` do not help. Running it *outside* the sandbox
  cannot capture its traffic either — burpwn's proxy is a unix socket that aborts an unattributed
  CONNECT. Reviving it requires a burpwn-side change (a TCP proxy listener, or a Chromium-compatible
  sandbox profile), so `BrowserLogin`/`BrowserStep` and the `browser` extra are not shipped rather
  than shipped broken.
- **The client-side scope refusal was OFF on the default backend.** Noted as open last release and
  now closed: `sdk_agent.py` — the `claude-code`/native-SDK path, i.e. what a normal run uses — had
  no scope check on `burpwn_exec`/`req_replay`/`fuzz` at all, so the containment documented in
  CLAUDE.md ("the tool wrappers deterministically refuse traffic to out-of-scope hosts") was not
  actually running in a real engagement; only burpwn's own server-side sandbox applied. Both paths
  now share one `ScopeGuard`, and the parity test pins it.

### Fixed (lessons from a live full-scope engagement)

- **`--name` defaulted to the literal `"a2pwn"`.** Every unnamed run silently shared a checkpoint
  and burpwn session with any other unnamed run — observed live as stray "Deserializing
  unregistered type" warnings and reused session state at bootstrap. Unnamed runs now get a
  timestamped, unique name (`a2pwn-YYYYMMDD-HHMMSS`); pass `--name` explicitly when you intend to
  `a2pwn resume` a specific run.
- **`burpwn_fuzz`/`burpwn_compare` had the same undocumented-contract bug as `oracle_expect`.**
  `positions` needs `"start:end"` BYTE OFFSETS into the raw request, and `what` must be exactly one
  of `headers`/`body`/`all` — neither constraint was stated anywhere the model could see it, so it
  routinely guessed field names or comma-lists instead (16 of 23 tool failures on one real
  engagement were this class of error, mostly `burpwn_fuzz`). Both tool descriptions (SDK and
  LangChain paths) now spell out the exact expected format.
- **A genuine model safety refusal was indistinguishable from a technical crash in the logs.** The
  `claude-agent-sdk` surfaces both under the same generic exception (with a misleading label —
  `"returned an error result: success"` for an actual refusal, observed live). The executor now
  detects Claude Code's own refusal boilerplate and logs it as a distinct `MODEL REFUSAL` warning
  instead of a generic error.
- **`executor_max_turns` default (40) was routinely exhausted** — 16 times in one real multi-API
  engagement, on ordinary recon→exploit→verify-retry sequences against a handful of REST endpoints.
  Raised to 60 (all fallback defaults in `agents.py`/`sdk_agent.py` aligned for consistency; the
  live path already threads `cfg.executor_max_turns` through explicitly).

### Fixed (real findings silently dropped from the report)

Found on a live full-scope engagement: the LLM transcripts showed 4+ well-evidenced HIGH-severity
candidates (JWT signature bypass, unauthenticated destructive DELETE, unauthenticated cross-tenant
webhook-subscriber CRUD on two environments) but the final report showed 0 verified findings and
only 1 unrelated LOW — a direct violation of the "reconciliation only ever promotes, never silently
drops" design invariant. Root-caused to three independent bugs:

- **`state_change` oracle was silently corrupted to `signature`.** The oracle allow-lists in both
  executor paths (`sdk_agent.py`, `tools/finding_tools.py`) — and the `Finding.oracle_kind` Pydantic
  `Literal` itself in `models.py` — never included `"state_change"`, even though it shipped as a
  documented oracle kind and `VerificationOracle.kind` (the actual dispatcher) already supported it.
  Every finding the executor reported with `oracle_kind="state_change"` was rewritten to
  `"signature"` before adjudication, so the deterministic re-check ran the WRONG oracle against the
  wrong flow shape and rejected genuinely-proven business-logic/CSRF/CRUD findings with zero signal
  to the operator. This is almost certainly why every cross-tenant subscriber-CRUD finding vanished.
- **A verify-retry-round crash wiped the whole dispatch, not just the retried candidate.** The
  sub-agent graph is `checkpointer=False` by design; when a multi-candidate dispatch confirmed some
  candidates but not others, the verify loop retried the executor for the unproven ones — and if
  THAT retry's executor invocation raised (e.g. the SDK's "Reached maximum number of turns (40)"
  with zero new activity), the exception propagated uncaught out of the whole sub-agent invocation,
  landing in `run_subagent`'s outer handler, which degraded the ENTIRE dispatch to `"blocked"` —
  discarding every already-confirmed candidate from earlier rounds of the SAME dispatch, not just
  the one still being retried. `_execute` now catches an exception on retry rounds only (round 0
  still propagates, preserving the existing isolated-failure contract) and treats it as "no new
  activity this round", so prior-round confirmations survive to `distill`.
- **Adjudication reject reasons were invisible outside the TUI.** `_verify`'s REJECT reason (capture
  alarm, tls-passthru block, or the oracle simply not re-deriving) only ever reached the
  TUI-only progress event bus — a `--plain` run had no way to tell why a candidate never made the
  report short of reverse-engineering it from source and raw burpwn state, which is exactly what
  this bug required to diagnose. Every reject reason is now logged at WARNING.

### Added

- **Executor observability.** The native-SDK sub-agent used to run blind: its burpwn tool calls,
  their results and any failures only reached the live TUI (via the display event bus), so a
  `--plain` run showed nothing — "the agent can't use burpwn but I have no logs". Every tool call is
  now logged on the `a2pwn.executor` logger (INFO = the call + args, visible in `--plain`; DEBUG =
  result head with `-v`), a tool that raises is **logged at WARNING and surfaced to the model as an
  error result** instead of vanishing into an opaque SDK exception, and a run that makes zero tool
  calls and finds nothing (the signature of a model refusal — "cannot execute … under current tool
  constraints") is flagged at WARNING with the model's last text. Makes environment failures (a
  broken burpwn sandbox: glibc/namespace) and model refusals distinguishable from a headless run.

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

- **`req_list`/`fuzz_results` choked on `limit=-1`.** Executors routinely pass `limit=-1` to mean
  "no cap"; burpwn's MCP schema hard-rejected it (`invalid value: integer -1, expected u16`) and the
  whole list call failed. `limit` is now sanitised to the u16 domain at the client boundary
  (`_u16_or_none`): any negative → omitted (server default / all), overflow clamped to 65535. Caught
  live on a real engagement via the new executor tool logging.
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
