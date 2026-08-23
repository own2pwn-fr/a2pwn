<h1 align="center">a2pwn</h1>

<p align="center">
  <b>An autonomous, evidence-grounded web-pentest orchestrator.</b><br>
  A LangGraph <i>master</i> dispatches adversarially-verified sub-agents that recon and exploit real
  targets — every request routed through the <a href="https://github.com/own2pwn-fr/burpwn">burpwn</a>
  sandbox, every finding re-derived by a deterministic oracle before it is allowed into the report.
</p>

---

> [!WARNING]
> **Authorized testing only.** a2pwn actively probes and exploits the targets you give it. Run it
> **only** against systems you own or have explicit written permission to test. You are responsible
> for staying within scope and the law. a2pwn helps: it registers your in-scope hosts with the burpwn
> sandbox at startup and the tool wrappers deterministically refuse traffic to out-of-scope hosts
> (including cloud metadata like `169.254.169.254`) — but scope enforcement is a backstop, not a
> substitute for your authorization.

## What it is

a2pwn is to an autonomous agent what a full engagement methodology is to a human pentester: it does
not stop at security headers and two probes. It goes deep — reflected/stored/DOM/mutation XSS, blind
and OOB SQLi, SSTI, SSRF (cloud-metadata / DNS-rebinding / gopher), request smuggling (CL.TE / TE.CL /
CL.CL / TE.TE), HTTP/2+ and HTTP/3 desync, hop-by-hop header injection, cache poisoning / CPDoS, web
cache deception, host-header attacks, CORS, JWT/auth flaws, IDOR/BOLA, cross-chain access control,
prototype pollution, deserialization, XXE, path traversal / LFI, open redirect, race conditions, and
JS supply-chain (de-bundle the app → identify a library → pull it → check known CVEs → prove it on the
live site) — chaining primitives across findings.

DOM XSS, CSP-in-practice and postMessage are reached with a **real browser** driven inside the
sandbox, so page traffic stays captured; WebSockets are driven by a stdlib RFC 6455 client that can
replay a captured, already-authorised channel with tampered content. CVE research runs against public
vulnerability databases over the one narrowly-bounded channel that does not go through the sandbox
(`--no-research` disables it).

Two mandates drive every design decision:

1. **Clean history by construction.** The master reasons over an append-only chain of
   `(task → clean result)` records only. A sub-agent's clarification Q&A, ReAct transcript, verifier
   critiques and retries live and die inside a stateless child graph — they can *never* merge into the
   master's canonical history. The master always sees a sub-agent that "succeeded first try". This is
   enforced structurally (the master state has no channel a transcript could leak into), not by
   discipline.
2. **0-FP evidence.** A finding is `confirmed` only when a deterministic oracle
   (differential / OOB-callback / marker / timing / two-identity / state-change / signature) re-derives it *inside the sandbox*
   **and** a non-empty burpwn flow batch proves the traffic was actually captured. A network operation
   that captured zero flows is a loud alarm (traffic escaped the sandbox), never silent evidence.

## Proof it works — a real engagement

Run autonomously against the sanctioned [BrokenCrystals](https://github.com/NeuraLegion/brokencrystals)
lab (`a2pwn run -t https://brokencrystals.com/ -o "..." --active-exploit --yes`), a2pwn found, chained
and **independently verified 11 findings — 8 critical, 3 high** — end to end (recon → exploit → read
response → deterministic-oracle verify → report + per-workspace HAR), with zero false positives.

The headline is a fully **cross-chained** takeover the agent assembled on its own:

> **OS command injection** (`GET /api/spawn?command=id` → `uid=0(root)`) → pivoted via the RCE to
> `cat /proc/self/environ`, leaking `KEYCLOAK_ADMIN_CLIENT_SECRET` → performed an OAuth2
> `client_credentials` grant with the leaked secret, **forging an admin Bearer token** with
> `manage-users` → replayed that token *from the internet* against the Keycloak Admin REST API →
> **full realm user list (PII) and account-takeover primitive**.

Every step is backed by a tagged burpwn flow batch and reproduced by an independent verify sub-agent
before it reaches the report. The rest of the run, each proven and verified:

| Severity | Finding |
|----------|---------|
| CRITICAL | RCE → leaked Keycloak secret → forged admin token → Admin-API takeover *(the chain above)* |
| CRITICAL | Broken access control — OIDC password-reset / user impersonation |
| CRITICAL | Unauth OS command injection (root) via `/api/spawn` |
| CRITICAL | Path traversal / arbitrary file read via `/api/file?path=` (reaches `/etc`, `/proc`) |
| CRITICAL | JWT RS256 **signing-key disclosure** via path traversal (enables token forgery) |
| CRITICAL | Kubernetes **serviceaccount-token** + cluster topology disclosure via LFI |
| HIGH | Env-var credential leak (command injection + LFI) enabling third-party API abuse |
| HIGH | Config-secrets leak via `/api/config` |
| HIGH | RCE-chained internal **SSRF** pivot |

Evidence is exported as HAR (here, a 198-entry capture) alongside the markdown report under the run
directory. On the default subscription backend the executor drives the target through the
`claude-agent-sdk`'s native tool loop, so tool results are trusted and the agent exploits to depth
instead of stopping at recon.

> Reproduce responsibly: use only sanctioned labs like BrokenCrystals or PortSwigger's
> `ginandjuice.shop`.

## Install & run

a2pwn drives **all** traffic through the [burpwn](https://github.com/own2pwn-fr/burpwn) sandbox — a
prebuilt release binary, **not** a Python package, so `uv`/`pip` cannot pull it. Install it once
(Linux only; on macOS/Windows use the [Docker image](#docker-batteries-included)), then verify the
host with `a2pwn doctor`:

```bash
# one-shot, no clone (uv installs into an ephemeral env)
uvx a2pwn install-burpwn      # fetch the burpwn sandbox binary onto your PATH (~/.local/bin)
uvx a2pwn doctor              # verify burpwn is on PATH + the host supports rootless namespaces
uvx a2pwn run --target https://app.example.com --objective "find and prove exploitable web vulns"
```

or from a checkout:

```bash
uv sync
uv run a2pwn install-burpwn   # the one dependency `uv sync` can't install
uv run a2pwn doctor           # preflight: burpwn present + rootless user/network namespaces OK
uv run a2pwn run --target https://ginandjuice.shop --objective "audit the shop end to end" --yes
```

`a2pwn install-burpwn` resolves your architecture, downloads the matching release tarball and drops
the `burpwn` binary in a bin dir on your `PATH` (override with `--dest`, pin a tag with `--version`).
Already have burpwn elsewhere? Skip it — `a2pwn doctor` will find it. Prefer to install by hand?
Grab a release from the [burpwn repo](https://github.com/own2pwn-fr/burpwn) and put it on `PATH`.

Findings land under the run directory as `report.md` plus machine-readable `report.json`,
`report.sarif` (GitHub code-scanning / CI) and a self-contained `report.html`, alongside a per-batch
HAR export. Pick the set with `--format md,json,sarif,html`. A **Run plan** panel (targets,
objective, active-exploit state, models, budgets, output dir) prints before the authorization gate.

The report separates two proof tiers: **verified** findings (independently reproduced from a clean
slate) and **confirmed-but-not-reproduced** ones — oracle-proven but not replayable (races, one-shot
OTP/tokens, TOCTOU) — which are surfaced for manual re-check instead of being dropped.

```bash
uv run a2pwn list                        # prior runs: verified/confirmed counts, severity tally
uv run a2pwn resume --name <run>         # resume an interrupted run from its checkpoint
uv run a2pwn retest --baseline <run>     # re-check a prior run's findings after remediation
uv run a2pwn run ... --max-wall-secs 3600  # optional whole-engagement wall-clock cap
```

Every run also writes `run.jsonl` next to the report — a durable event log of dispatches, tool
calls, tool failures, model refusals and each adjudication's reject reason. It is written whether or
not the TUI is on, so a finished run stays answerable after the fact.

### Engagement files, scope carve-outs and identities

Flags stop scaling at a real scope, and credentials must not go in shell history. `--config` takes a
YAML engagement file; explicit flags still override it, and an unknown key is an error rather than a
silent scope change.

```yaml
# engagement.yaml
name: acme-q3
objective: audit the customer portal end to end
targets: [https://app.example.com]
in_scope: [example.com]
exclude:                       # always wins over the allow-list
  - legacy.example.com         # host (and its subdomains)
  - "*.internal.example.com"   # host glob
  - /admin/billing             # path subtree, every in-scope host

identities:                    # what makes the access-control classes reachable
  - name: alice                # static credentials you already hold
    headers: {Authorization: "Bearer eyJ…"}
  - name: bob                  # or a replay login through the sandbox
    login:
      url: https://app.example.com/api/login
      body: '{"user":"bob","pass":"…"}'
      extract: {token: '"token":"([^"]+)"'}
      inject: {Authorization: "Bearer {token}"}
  - name: anon                 # the two_identity negative control
    anonymous: true

max_usd: 25                    # REAL spend ceiling, not a dispatch count
max_rps: 5                     # global traffic throttle, enforced at the tool layer
```

```bash
uv run a2pwn run --config engagement.yaml --active-exploit --yes
```

Identities are resolved lazily, cached, shared across a parallel fan-out, and re-authenticated on a
401/403 so a long engagement survives session expiry. Every login request goes through `burpwn exec`,
so the "burpwn is the only egress" invariant holds.

There is deliberately **no headless-browser login**: it was built and removed after live testing.
Chromium cannot start inside the burpwn sandbox (killed with SIGTRAP — its namespace/seccomp layer
cannot nest inside bubblewrap, and `--no-sandbox`/`--no-zygote`/`--single-process` do not help), and
burpwn's proxy is a unix socket that rejects an unattributed client, so running the browser outside
the sandbox cannot capture its traffic either. For a JS/SPA/OAuth flow, log in by hand once and pass
the resulting cookie or token as a static identity.

Declaring at least two authenticated identities plus `anon` is what makes the `two_identity` oracle
usable: A reaching B's object, B fetching its own (ground truth), and the anonymous control being
denied (which rules out a merely public resource).

### Spend and traffic ceilings

`--max-dispatches` counts dispatches, which is a poor proxy for cost — one dispatch ranges from a few
turns to 60 with a 150k-token compaction. `--max-usd` / `--max-tokens` bound the **real** spend
reported by the backend; past either, the report is built from what was proven. `--max-rps` throttles
all target-facing traffic, and `--fuzz-max-requests` clamps one Intruder attack (the clamp is
reported, never silent).

a2pwn also trips a circuit breaker after a run of consecutive 429/403-with-WAF-signature responses,
stops probing, and says so loudly in the report. That distinction matters: a blocked run and a clean
target both produce zero findings, and only one of them means the target is secure.

`a2pwn run` also self-guards: every burpwn call is bounded by a timeout, a crashed sandbox is
respawned, and the first Ctrl-C finalizes the report gracefully (a second forces the abort).

### Docker (batteries included)

The published image bundles a2pwn, all Python deps, the burpwn sandbox, and (via
`claude-agent-sdk`) a Claude Code CLI — nothing else to install. The sub-agents build a rootless
user/network namespace, so the container needs `--privileged` (or the equivalent caps):

```bash
# subscription backend — mount your Claude Code login:
docker run --rm -it --privileged \
  -v "$HOME/.claude:/root/.claude" \
  -v "$PWD/out:/root/.local/share/a2pwn" \
  own2pwnfr/a2pwn run -t https://ginandjuice.shop -o "find and prove web vulns" --yes

# API backend instead (no subscription):
docker run --rm -it --privileged -e ANTHROPIC_API_KEY=sk-... \
  own2pwnfr/a2pwn run -t https://brokencrystals.com -o "..." \
  --executor-model anthropic:claude-sonnet-4-5 --verifier-model anthropic:claude-opus-4-5 --yes
```

Reports and HAR captures land in the mounted `out/` directory. The live TUI runs on an interactive
terminal (`-it`); add `--plain` for log-style output in CI.

### Requirements

- [burpwn](https://github.com/own2pwn-fr/burpwn) on `PATH` (the sandbox + intercepting proxy).
  Install it with `a2pwn install-burpwn` and confirm the host with `a2pwn doctor` (checks the binary
  is present and that rootless user/network namespaces work). `a2pwn run` also preflights this
  **before** the authorization gate and aborts immediately with an install hint if the binary is
  missing — it never spends model calls on a run that cannot capture traffic. Linux only; on
  macOS/Windows use the Docker image.
- A model backend (see below). The default needs a working Claude Code login — nothing else.

### Authorization & scope

- Authorization is a **one-time** acknowledgement taken upfront (`--yes` or an interactive
  `I AGREE`); by default the run then proceeds autonomously.
- Pass `--step-through` to interactively approve **each** dispatch instead (upfront ack still
  required). This is the honest per-dispatch gate — the default is upfront-only, not per-dispatch.
- In-scope hosts come from `--target` (repeatable). They are registered with burpwn and enforced by
  the tool layer, so a hallucinated/redirected/injected URL cannot drive off-scope traffic.
- `--dos` is **advisory only**: it is surfaced to the planner/executor prompts as guidance and is
  not a deterministic tool-layer block.

## Backends

a2pwn talks to any LangChain chat model through one factory (`a2pwn.backends.make_model`). Pick a
provider per role (`master`, `clarifier`, `executor`, `verifier`); the verifier defaults to an
Opus-class model and is required to differ from the executor, so verification stays adversarial.

| `provider`        | Auth                        | Extra           |
|-------------------|-----------------------------|-----------------|
| `claude-code`     | **Claude Code subscription (OAuth, default)** | built-in |
| `anthropic`       | `ANTHROPIC_API_KEY`         | built-in        |
| `openai`          | `OPENAI_API_KEY`            | `a2pwn[openai]` |
| `bedrock_converse`| AWS credentials             | `a2pwn[aws]`    |
| `google_vertexai` | GCP ADC                     | `a2pwn[vertex]` |
| `litellm`         | per-provider                | `a2pwn[litellm]`|
| `codex` / `antigravity` | subscription (best-effort, falls back to key) | built-in |

> [!NOTE]
> The default `claude-code` backend drives your **Claude Code subscription** over the
> `claude-agent-sdk` (OAuth, no API key — `ANTHROPIC_API_KEY` is scrubbed from the child env so it can
> never silently bill the API). Using a personal subscription for programmatic/automated use is a gray
> area under Anthropic's terms; a2pwn runs entirely on your machine, with your login, for your own use.
> If in doubt, use an API provider.

## How it works

```
MASTER graph  (dispatch-only; never touches a target)
  bootstrap → plan → route_dispatch ──▶ [Send × N]  run_subagent  ──▶ integrate → plan | report
                                              │  (FORK BOUNDARY)
                                              ▼
              SUB-AGENT graph  (own state, checkpointer=False, dies on return)
                clarify → [Send × question] answer_one → compose_prompt
                        → execute (ReAct: skills + tools + burpwn) → verify (adversarial, oracle)
                        → distill → clean result
```

- The master can dispatch a **single** task, a **batch** in parallel, or a **verify-workflow**.
- **Clarify fork ("the Bitcoin fork"):** the child asks as many questions as it needs; each question is
  answered in parallel by an isolated fork seeded with a *compacted* snapshot of the master's context.
  None of it reaches master history.
- **Adversarial verify:** a different, stronger model re-derives every candidate through its oracle and
  rejects anything without real captured evidence. An **independent** second dispatch reproduces
  confirmed findings from a clean slate; reconciliation only ever *promotes* (never silently drops) a
  finding.
- **Evidence = a highlighted burpwn batch.** Each finding's requests are grouped in a dedicated
  workspace, tagged (e.g. `xss`, red) and annotated — so "this batch == the XSS" is queryable and
  exports cleanly to HAR.

### Coverage: what was tested, not just what was found

A 0-finding report is meaningless unless it can say what it looked at. a2pwn maintains an
**attack-surface inventory harvested from the traffic burpwn actually captured** — hosts, endpoints,
query/body/JSON parameters, JS bundles, WebSocket channels — crossed with the vulnerability classes
applicable to each. Every `(asset × class)` cell carries a verdict, and sub-agents record the
*negative* results too (`record_probe`), which the oracle kernel structurally cannot: it only ever
promotes proof.

That matters twice. The report gains a **Coverage** section stating plainly what was never probed
(untested cells are not evidence of security). And when the planner runs dry, untested cells are
expanded into real dispatches automatically — the model prioritises, the matrix enumerates, so
thoroughness stops depending on an LLM remembering every endpoint it has seen.

`a2pwn doctor` additionally proves **capture** works before a run, not just that the sandbox starts:
an uncaptured engagement still probes, still rejects every candidate for an empty flow batch, and
still reports a clean target.

## Skills & tools

- **Skills** (`skills/`) are curated, self-describing security knowledge — Claude-Code-faithful
  frontmatter plus a2pwn extensions (tags, tools, payload sources, a `verify.py` oracle). The **whole**
  catalog is seeded on every engagement — each skill is one zero-argument tool whose body loads only
  when the agent asks — so no relevance filter can decide, from a hostname, that a class is not worth
  teaching.
- **Payloads** are *referenced* (for attribution), never copied, from pinned vendored sources
  ([PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) MIT,
  [HackTricks](https://github.com/HackTricks-wiki/hacktricks) CC-BY-SA, nuclei-templates MIT). They
  are populated only in a **checkout** via `git submodule update --init`; the `uvx` wheel does not
  bundle `vendor/`. See `ATTRIBUTION.md`.
- **Tools** (nuclei, katana, hydra, nmap, ffuf, sqlmap, subfinder, httpx, webcrack…) run *through*
  `burpwn exec` so their traffic is captured. Tools that can't be captured (e.g. Docker in its own
  netns) run with a warning and never claim evidence.

## Status

`0.1.0` — early, but the full loop works end to end: the orchestration core, native-SDK executor,
backends, burpwn integration, deterministic oracles, catalog, continuation judge, auto-compaction,
identities, scope carve-outs, spend/traffic ceilings, the retest cycle, the coverage matrix, browser
and WebSocket testing, CVE research, reporting and CLI are in place and exercised by 800+ tests (clean-history / reconciliation / capture-alarm /
fail-closed-adjudication / executor-path-parity invariants included). Validated against a live
sanctioned lab (see [Proof it works](#proof-it-works--a-real-engagement)). The seed skill library is
being expanded toward full depth on each class.

## License

[AGPL-3.0-or-later](LICENSE).
