---
name: web-websocket
description: >
  Test WebSocket endpoints. USE WHEN the app upgrades to ws:// or wss:// (chat,
  notifications, live dashboards, collaborative editing, trading feeds). Covers
  cross-site WebSocket hijacking (CSWSH) via missing Origin validation, authorization
  applied only at handshake, message-level injection (XSS/SQLi through the socket),
  IDOR on subscription topics, and rate/flood limits absent on the message channel.
tags: [web, websocket, ws, cswsh, origin, realtime, access-control, injection]
tools: [curl, websocat, python3]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Web Sockets/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
verification:
  kind: two_identity
references:
  - "https://portswigger.net/web-security/websockets"
  - "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking"
license: AGPL-3.0-or-later
version: 1.0.0
---
# WebSockets — the channel the request-based tooling misses

Everything after the HTTP upgrade is invisible to a crawler and to most parameter
fuzzing: the app's real API often lives entirely inside the socket. Two structural
weaknesses recur, and both are checkable in minutes.

## Preconditions / triggers
- A `101 Switching Protocols` response, an `Upgrade: websocket` request, or a JS
  bundle constructing `new WebSocket(...)` / socket.io / SignalR / Phoenix Channels.

## Methodology

### 1. Capture and understand the handshake
Find the upgrade flow with `burpwn_req_search` for `Upgrade: websocket` or
`101`. Note precisely **where authorization lives**: a cookie on the handshake, a
token in the query string, or a first `auth` message inside the socket. That
answer determines which of the two bugs below applies.

### 2. Cross-site WebSocket hijacking (CSWSH)
If the handshake authenticates with a **cookie**, replay it with a foreign
`Origin:` header (`Origin: https://attacker.tld`) and everything else identical.
A server that still returns `101` and then serves the victim's data has no Origin
validation: any site can open an authenticated socket in the victim's browser and
read the stream. Cookies are attached cross-site on WS handshakes, and `SameSite=Lax`
does NOT protect this.

Prove it with `two_identity`, treating the origin-swapped handshake as identity A's
access to identity B's data:
- flow A = handshake with foreign Origin + the data frame it received
- flow B = the legitimate handshake + the same data (ground truth)
- flow C = the anonymous control (no cookie) — it must be REJECTED

### 3. Authorization only at the handshake
Very common: the handshake checks who you are, then every message is trusted.
Connect as identity A and send a message referencing identity B's resource —
`{"action":"subscribe","room":"<B's room>"}`, `{"type":"get_order","id":<B's id>}`.
If B's data comes back, it is IDOR over the socket. Also try actions the UI never
sends for your role (`admin_broadcast`, `set_role`, `delete`).

### 4. Message-level injection
Every message field is an input sink that skipped the HTTP-layer WAF entirely.
Push the standard payload sets through it: SQLi (time-based works well — the
`timing` oracle applies unchanged), command injection, SSTI, and stored XSS where
the message is rendered into another user's DOM. A marker delivered to a SECOND
identity's session is the `marker` oracle, and is the strongest stored-XSS proof
available on this channel.

## Driving a socket inside the sandbox
Use `burpwn_exec` so the traffic is captured like everything else — a raw socket
opened outside the sandbox is uncaptured and its evidence is worthless:

```
burpwn_exec argv=["websocat", "-H=Origin: https://attacker.tld", "wss://target/ws"]
```

When `websocat` is unavailable, drive it with a short `python3 -c` script using
`websockets`/`websocket-client`. Either way it runs through `burpwn_exec`.

## Oracle
- `two_identity` for CSWSH and cross-subscription IDOR (always include the
  anonymous negative control).
- `marker` for stored XSS delivered to another identity's session.
- `timing` for blind injection through a message field.
- `differential` for Origin validation alone (legitimate Origin vs foreign Origin
  handshake, comparing the upgrade outcome).

## Pitfalls
- A `101` with a foreign Origin is **not yet a finding** — the server may still
  refuse to send data. Capture an actual data frame containing the victim's content.
- Some stacks answer `403` to a foreign Origin but accept a MISSING Origin header;
  test both.
- If flows come back `tls-passthru`, the socket is not MITM-able: mark BLOCKED, not
  clean.
