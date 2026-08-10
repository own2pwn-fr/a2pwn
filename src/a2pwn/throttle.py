"""Engagement-level traffic policy: a global rate limit and a target-is-blocking circuit breaker.

Two failure modes this closes, both observed as *silent* quality problems rather than crashes:

* **Unbounded request rate.** ``concurrency``/``delay_ms`` existed only as Intruder parameters the
  model chose for itself, so nothing bounded the aggregate rate across a parallel dispatch fan-out.
  A client who asked for a gentle test had no knob to enforce it.
* **A blocked target reads as a clean target.** Once a WAF starts answering 429/403 to everything,
  every subsequent oracle legitimately fails to re-derive, every candidate is rejected, and the run
  spends its whole remaining budget producing a 0-finding report that is *indistinguishable from a
  genuinely secure target*. The breaker stops the traffic and makes the reason explicit, in the
  logs, in the tool results the model sees, and in the report.

Both live in the tool-wrapper layer so they apply identically on both executor paths, and neither is
prompt guidance the model can talk itself out of.

This file is part of a2pwn and is distributed under the GNU Affero General Public License v3.0
or later; see the repository ``LICENSE`` for the full text.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

_log = logging.getLogger("a2pwn.throttle")

# Statuses that mean "the edge refused us", as opposed to an application-level denial. 403 is
# deliberately included: a WAF wall and a legitimate authorization denial look identical per
# response, which is exactly why the breaker keys on a long CONSECUTIVE run rather than a single hit.
_BLOCKED_STATUSES = {401, 403, 406, 418, 429, 503}
# Only these are strong enough to count on their own; 401/403 need a body signature too, since a
# healthy access-control test produces them constantly by design.
_HARD_BLOCKED_STATUSES = {429, 503}
_WAF_SIGNATURES = (
    "access denied",
    "attention required",
    "cloudflare",
    "request blocked",
    "you have been blocked",
    "web application firewall",
    "incapsula",
    "akamai reference",
    "mod_security",
    "forbidden by administrative rules",
)


def _looks_blocked(status: Any, body: str) -> bool:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return False
    if code in _HARD_BLOCKED_STATUSES:
        return True
    if code not in _BLOCKED_STATUSES:
        return False
    low = (body or "").lower()
    return any(sig in low for sig in _WAF_SIGNATURES)


def _iter_statuses(payload: Any, depth: int = 0) -> list[tuple[Any, str]]:
    """(status, body) pairs found anywhere in a burpwn tool result (shape-defensive, depth-capped)."""
    found: list[tuple[Any, str]] = []
    if depth > 4:
        return found
    if isinstance(payload, dict):
        if "status" in payload:
            body = payload.get("body")
            found.append((payload.get("status"), body if isinstance(body, str) else ""))
        for key in ("response", "flows", "results", "entries", "hits"):
            value = payload.get(key)
            if value is not None:
                found += _iter_statuses(value, depth + 1)
    elif isinstance(payload, list):
        for item in payload[:200]:  # a fuzz result set can be huge; a sample is enough to trip
            found += _iter_statuses(item, depth + 1)
    return found


class Throttle:
    """Global request-rate limiter plus the blocked-target circuit breaker.

    One instance per engagement, shared by every tool wrapper on both executor paths. ``max_rps``
    of ``None``/0 disables pacing; ``block_threshold`` of 0 disables the breaker.
    """

    def __init__(self, max_rps: float | None = None, block_threshold: int = 25) -> None:
        self.max_rps = float(max_rps) if max_rps else 0.0
        self.block_threshold = int(block_threshold or 0)
        self._interval = 1.0 / self.max_rps if self.max_rps > 0 else 0.0
        self._next_slot = 0.0
        self._lock = asyncio.Lock()
        self.consecutive_blocked = 0
        self.observed = 0
        self.blocked_total = 0
        self.tripped = False
        self.trip_reason = ""

    # ---- pacing ----------------------------------------------------------------------
    async def acquire(self) -> None:
        """Wait until this call is allowed to issue traffic under the configured rate."""
        if self._interval <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self._interval
            delay = slot - now
        if delay > 0:
            await asyncio.sleep(delay)

    # ---- circuit breaker -------------------------------------------------------------
    def observe(self, payload: Any) -> None:
        """Feed a tool result to the breaker; trips once the consecutive-block run hits the cap."""
        if not self.block_threshold or self.tripped:
            return
        for status, body in _iter_statuses(payload):
            self.observed += 1
            if _looks_blocked(status, body):
                self.blocked_total += 1
                self.consecutive_blocked += 1
                if self.consecutive_blocked >= self.block_threshold:
                    self.tripped = True
                    self.trip_reason = (
                        f"{self.consecutive_blocked} consecutive blocked responses "
                        f"(last status {status}) — the target appears to be rate-limiting or "
                        "WAF-blocking this engagement"
                    )
                    _log.warning("traffic circuit breaker TRIPPED: %s", self.trip_reason)
                    return
            else:
                self.consecutive_blocked = 0

    def refusal(self, where: str) -> dict:
        """The envelope target-facing tools return once the breaker has tripped."""
        return {
            "error": "target-blocking",
            "refused": True,
            "message": (
                f"REFUSED: {where} was not run. {self.trip_reason}. Continuing would spend the "
                "engagement's remaining budget against a block page and produce a misleading "
                "0-finding report. Report what you have; the operator needs to get the source IP "
                "allow-listed or lower the rate (--max-rps) before testing can continue."
            ),
        }

    def reset(self) -> None:
        """Clear the breaker (operator-driven retry after the block is lifted)."""
        self.consecutive_blocked = 0
        self.tripped = False
        self.trip_reason = ""

    def stats(self) -> dict:
        """Display/report-facing snapshot of what the throttle saw."""
        return {
            "max_rps": self.max_rps or None,
            "responses_observed": self.observed,
            "blocked_responses": self.blocked_total,
            "consecutive_blocked": self.consecutive_blocked,
            "tripped": self.tripped,
            "trip_reason": self.trip_reason,
        }


def clamp_fuzz_payloads(payloads: list[str], cap: int) -> tuple[list[str], str | None]:
    """Clamp an Intruder payload list to ``cap``, returning the clamp notice (or ``None``).

    Silent truncation would read as "we fuzzed everything"; the notice is surfaced to the model AND
    logged so a partial attack is never mistaken for an exhaustive one.
    """
    payloads = list(payloads or [])
    if cap <= 0 or len(payloads) <= cap:
        return payloads, None
    dropped = len(payloads) - cap
    _log.warning("fuzz payload list clamped to %d (%d dropped) by fuzz_max_requests", cap, dropped)
    return payloads[:cap], (
        f"NOTE: payload list clamped to the engagement's fuzz_max_requests={cap}; {dropped} payload(s) "
        "were NOT sent. Narrow the payload set or raise the cap if you need full coverage."
    )
