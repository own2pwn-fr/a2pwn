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

Two mandates drive every design decision:

1. **Clean history by construction.** The master reasons over an append-only chain of
   `(task → clean result)` records only. A sub-agent's clarification Q&A, ReAct transcript, verifier
   critiques and retries live and die inside a stateless child graph — they can *never* merge into the
   master's canonical history. The master always sees a sub-agent that "succeeded first try". This is
   enforced structurally (the master state has no channel a transcript could leak into), not by
   discipline.
2. **0-FP evidence.** A finding is `confirmed` only when a deterministic oracle
   (differential / OOB-callback / marker / timing / two-identity) re-derives it *inside the sandbox*
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

```bash
# one-shot, no clone (uv installs into an ephemeral env)
uvx a2pwn run --target https://app.example.com --objective "find and prove exploitable web vulns"
```

or from a checkout:

```bash
uv sync
uv run a2pwn run --target https://ginandjuice.shop --objective "audit the shop end to end" --yes
```

Findings and a per-batch HAR export land under the run directory.

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

- [burpwn](https://github.com/own2pwn-fr/burpwn) on `PATH` (the sandbox + intercepting proxy). Run
  `burpwn doctor` once to confirm the host supports rootless user/network namespaces. a2pwn
  preflights this and aborts immediately with an install hint if the binary is missing — it never
  starts spending model calls on a run that cannot capture traffic.
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

## Skills & tools

- **Skills** (`skills/`) are curated, self-describing security knowledge — Claude-Code-faithful
  frontmatter plus a2pwn extensions (tags, tools, payload sources, a `verify.py` oracle). Sub-agents
  discover them by an FTS/tag prefilter, then load the relevant one(s).
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
reporting and CLI are in place and exercised by 250+ tests (clean-history / reconciliation /
capture-alarm / fail-closed-adjudication invariants included). Validated against a live sanctioned lab
(see [Proof it works](#proof-it-works--a-real-engagement)). The seed skill library is being expanded
toward full depth on each class.

## License

[AGPL-3.0-or-later](LICENSE).
