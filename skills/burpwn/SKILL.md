---
name: burpwn
description: >
  How a2pwn sub-agents drive burpwn — the capturing MITM sandbox that every
  target-facing command must run through. USE FOR ALL remote/network operations in
  a web/API pentest: route each network command through `burpwn exec` so traffic is
  captured, HTTPS-decrypted, searchable, replayable, and live-interceptable. Covers
  sessions, workspaces (== finding batches), exec capture, req list/show/search,
  replay, fuzz, compare, encode/decode, intercept, tag/note highlighting, and HAR
  export. Never wrap the agent's own LLM traffic (excluded by construction).
tags: [burpwn, proxy, mitm, capture, tooling, driver]
license: AGPL-3.0-or-later
version: 1.0.0
---
# Driving burpwn from an a2pwn sub-agent

burpwn runs a child command inside a rootless user+network namespace whose entire
network is forced through burpwn’s MITM proxy. HTTPS is decrypted with a
per-install CA; every request/response is captured to a per-session SQLite store
you can query, filter, replay, and live-edit. **The agent process stays OUTSIDE
the sandbox, so its own LLM/API traffic is never captured** — you never need to
do anything to exclude it. Linux only. Prefer MCP tools for the hot loop; shell
the CLI (`--json`, envelope `{ok,data,error}` on stdout) for lifecycle/export.

## The one standing rule
Route **every** target-facing command through `burpwn exec -- <cmd>` (`curl`,
`httpx`, `nmap`, `ffuf`, `katana`, `nuclei`, `sqlmap`, custom scripts). A raw
network command that bypasses `exec` is **invisible**: no capture, no decrypted
HTTPS, no evidence trail — treat it as a mistake to redo. Never wrap non-target
traffic (there is nothing to wrap; the agent is already outside the sandbox).

## Sessions (CLI-only lifecycle)
- `burpwn session new --name <engagement>` — one session per engagement; it’s the
  DB all flows land in. `session list` / `session use <NAME>` / `session rm <NAME>`.
- `session stats` — **capture health**: a network exec that captured **zero**
  flows means traffic escaped the sandbox → alarm, do not claim evidence.
- Preflight with `burpwn doctor` (userns/nftables/bubblewrap); fix failures before
  remote work rather than falling back to un-captured commands.
- For the a2pwn hot loop, pin a long-lived MCP server: `burpwn mcp --session
  <engagement>` (stdio; 31 tools; the `exec` tool returns
  `{exit_code, captured_request_ids, exec_id}` on the normal JSON channel).

## Workspaces == finding batches
Attribute a batch of captures to a finding by running it under a named workspace:
`exec --workspace <slug> -- <cmd>` (MCP `exec {workspace}`). Then `req list
--workspace <slug>` (CLI takes the **name**; MCP `req_list` takes the workspace
**id** — resolve via `workspace_list`). This makes “this whole run of requests”
one queryable set == the evidence for one finding.

## Query the capture
- `req list [--workspace N] [--host H] [--protocol h1|h2|ws|dns|rawtcp|tls-passthru]
  [--status S] [--method M]` — the flow inventory.
- `req show <id> [--raw]` — full request/response (+ verbatim head/body with `--raw`),
  plus that flow’s `tags`/`notes`.
- `req search <FTS5 query>` — full-text over **decrypted** urls/headers/bodies of
  the whole session → `{flow_ids:[...]}`. The killer for stored/second-order finds.

## Act on the capture
- `req replay <id> --set-header 'K: V' --set-body 'STR|@file' --method POST` —
  Repeater; raw header/body/method control (CRLF-guarded).
- `fuzz run --flow <id> --position 40:47|§marker§ --payloads words.txt|--payload X
  --mode sniper|battering-ram|pitchfork|cluster-bomb --concurrency N --delay MS
  --name X` — Intruder; results **anomaly-ranked by status/length/time**
  (`fuzz list`, `fuzz show <attack_id> --sort anomaly|status|len`). This is the
  native blind oracle (timing/length).
- `compare <flow_a> <flow_b> [--what headers|body|all]` — structured diff **plus a
  reflection check**; the differential oracle for boolean-SQLi, IDOR, cache-poison,
  SSPP.
- `encode|decode <scheme> <value>` — base64/url/hex/jwt (read/re-craft tokens).
- `intercept enable` → trigger via `exec` → `await_intercept` (long-poll) →
  `intercept forward <id> --set-header/--set-body` or `intercept drop <id>`; scope
  with `intercept scope <host> --path P --method M`. Park and hand-edit in flight.
- `match-replace add <scope> header|body|url|host <pattern> <replacement>
  --on request|response` — auto-rewrite across all flows (inject a canary/Origin/
  Host at scale). Enable/disable/rm are CLI-only.
- `session auth set/refresh/status` — login macro: mints a token, injects it as a
  header, auto-refreshes on 401/403. Use it to hold two identities for IDOR/access-
  control differentials.

## Highlight a finding batch (the a2pwn pattern)
1. Run the batch under a dedicated workspace: `exec --workspace <finding-slug>`.
2. Take the returned `captured_request_ids`.
3. `tag add <flow_id> <vuln-class>` (MCP `tag_add` supports a `color` for the
   highlight; CLI has no color) on each flow.
4. `note add <key_flow_id> "<finding writeup>"` on the key flow (the evidence).
   The workspace groups the batch, the coloured tag is the visible highlight, the
   note is the writeup.

## Out-of-band (blind) oracles
burpwn captures the **client tooling’s** egress (DNS/TCP), not the target
server’s outbound callbacks. For server-initiated OOB either (1) use an external
collaborator you own, or (2) host a listener **inside the sandbox** via `burpwn
exec` on a reachable interface so the target’s callback lands as a `dns`/`rawtcp`
flow in the same session (`req list --protocol dns|rawtcp`).

## Export
`burpwn export har` (CLI-only) → one HAR per workspace for the report; `burpwn ca
export` to trust the CA in a docker fallback container.

## Gotchas
- Confirm capture actually happened (`session stats`); a network exec with 0 flows
  = traffic escaped.
- `protocol == tls-passthru` on a flow means the target is cert-pinned/QUIC and
  MITM was refused → that host is not testable this session; say so, don’t fake it.
- MCP `req_list` filters by workspace **id** (i64); `exec`/CLI take the workspace
  **name** — resolve the mapping via `workspace_list`.
- Strip NUL bytes from any evidence before persisting (binary bodies abort ingestion).
