"""Out-of-transcript storage for bulky tool output — and the agent's ability to forget.

A pentest agent reads things that are enormous and mostly irrelevant: a 3 MB minified bundle, a
directory-brute wordlist result, a 40 k-line HAR. Two bad outcomes follow from putting that in the
conversation:

* it evicts the useful context (the transcript is the only working memory a stateless sub-agent
  has), and
* it stays there forever. The old behaviour was a blunt truncation — the first 200 000 characters
  of a tool result went into the transcript verbatim and the rest was discarded. That is the worst
  of both: the model pays for 200 k characters of noise AND still cannot see the part it needed,
  because the interesting string in a bundle is rarely in the first 200 kB.

The store inverts it. Bulky results never enter the transcript at all: the model gets a small
envelope (id, size, a head snippet) and reaches into the content with `artifact_grep` /
`artifact_slice`, paying only for what it actually reads. When a body turns out to be a dead end,
`artifact_drop` replaces it with a one-line tombstone stating why — so a later turn (or a later
retry round replaying the same reasoning) is told "already read, not relevant, do not re-read"
instead of fetching the whole thing again.

Nothing here talks to the network or the model; it is a byte store with a grep.
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

_log = logging.getLogger("a2pwn")

# Below this, an inline result is cheaper than the indirection and the extra tool round-trip.
DEFAULT_INLINE_LIMIT = 12_000
_HEAD_CHARS = 600
_MAX_SLICE = 40_000
_MAX_MATCHES = 40
_MATCH_CONTEXT = 160


@dataclass
class Artifact:
    """One stored blob. ``dropped_reason`` set means the content is gone on purpose."""

    id: str
    kind: str
    origin: str
    size: int
    sha256: str
    head: str
    text: str | None = None
    path: Path | None = None
    dropped_reason: str = ""

    def content(self) -> str:
        if self.dropped_reason:
            return ""
        if self.text is not None:
            return self.text
        if self.path is not None:
            try:
                return self.path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:  # noqa: BLE001 - a missing spill file is a miss, not a crash
                _log.warning("artifact %s unreadable: %s", self.id, exc)
        return ""


@dataclass
class ArtifactStore:
    """Per-engagement blob store. Shared across dispatches on purpose.

    Two sub-agents probing the same host fetch the same bundle; the second one should be able to
    grep what the first already pulled rather than re-downloading it through the sandbox. The store
    is keyed by content hash for exactly that reason — identical bytes get one id.
    """

    spill_dir: Path | None = None
    inline_limit: int = DEFAULT_INLINE_LIMIT
    _by_id: dict[str, Artifact] = field(default_factory=dict)
    _by_sha: dict[str, str] = field(default_factory=dict)
    _seq: int = 0

    def put(self, text: str, *, kind: str = "tool-result", origin: str = "") -> Artifact:
        sha = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        existing = self._by_sha.get(sha)
        if existing is not None:
            return self._by_id[existing]
        self._seq += 1
        art_id = f"art-{self._seq:04d}"
        head = text[:_HEAD_CHARS]
        artifact = Artifact(
            id=art_id, kind=kind, origin=origin, size=len(text), sha256=sha, head=head
        )
        if self.spill_dir is not None:
            try:
                self.spill_dir.mkdir(parents=True, exist_ok=True)
                target = self.spill_dir / f"{art_id}.txt"
                target.write_text(text, encoding="utf-8")
                artifact.path = target
            except OSError as exc:  # noqa: BLE001 - fall back to memory rather than lose the blob
                _log.warning("artifact spill failed for %s, keeping in memory: %s", art_id, exc)
                artifact.text = text
        else:
            artifact.text = text
        self._by_id[art_id] = artifact
        self._by_sha[sha] = art_id
        return artifact

    def get(self, art_id: str) -> Artifact | None:
        return self._by_id.get(art_id)

    def drop(self, art_id: str, reason: str) -> str:
        """Forget a blob's content, keeping a tombstone that says why.

        This is the agent-facing half of context hygiene: having established that a file is not
        relevant, the useful thing to carry forward is that *conclusion*, not the file.
        """
        artifact = self._by_id.get(art_id)
        if artifact is None:
            return f"no such artifact {art_id}"
        artifact.dropped_reason = reason or "not relevant"
        artifact.text = None
        if artifact.path is not None:
            try:
                artifact.path.unlink(missing_ok=True)
            except OSError:  # noqa: BLE001 - best effort; the tombstone is what matters
                pass
            artifact.path = None
        return f"dropped {art_id} ({artifact.size} chars): {artifact.dropped_reason}"

    def envelope(self, artifact: Artifact) -> str:
        """What the model sees in place of the content."""
        return (
            f"[artifact {artifact.id} | {artifact.kind} | {artifact.size} chars | from {artifact.origin}]\n"
            f"Too large to inline. Use artifact_grep(id='{artifact.id}', pattern=...) to search it, "
            f"artifact_slice(id='{artifact.id}', offset=..., limit=...) to read a window, or "
            f"artifact_drop(id='{artifact.id}', reason=...) once you have decided it is not relevant "
            "(that stops anyone re-reading it).\n"
            f"--- first {len(artifact.head)} chars ---\n{artifact.head}"
        )

    def slice(self, art_id: str, offset: int = 0, limit: int = 8_000) -> str:
        artifact = self._by_id.get(art_id)
        if artifact is None:
            return f"no such artifact {art_id}"
        if artifact.dropped_reason:
            return f"{art_id} was dropped as not relevant: {artifact.dropped_reason} — do not re-read it"
        text = artifact.content()
        start = max(0, offset)
        end = min(len(text), start + max(1, min(limit, _MAX_SLICE)))
        body = text[start:end]
        return f"[{art_id} chars {start}-{end} of {len(text)}]\n{body}"

    def grep(self, art_id: str, pattern: str, max_matches: int = _MAX_MATCHES) -> str:
        """Regex search returning windows around each hit — the only cheap way into a big bundle."""
        artifact = self._by_id.get(art_id)
        if artifact is None:
            return f"no such artifact {art_id}"
        if artifact.dropped_reason:
            return f"{art_id} was dropped as not relevant: {artifact.dropped_reason} — do not re-read it"
        try:
            rx = re.compile(pattern, re.I)
        except re.error as exc:
            return f"bad pattern: {exc}"
        text = artifact.content()
        hits: list[str] = []
        for m in rx.finditer(text):
            if len(hits) >= max(1, min(max_matches, _MAX_MATCHES)):
                hits.append("… more matches suppressed; narrow the pattern")
                break
            lo = max(0, m.start() - _MATCH_CONTEXT)
            hi = min(len(text), m.end() + _MATCH_CONTEXT)
            hits.append(f"@{m.start()}: …{text[lo:hi]}…")
        if not hits:
            return f"[{art_id}] no match for {pattern!r} in {len(text)} chars"
        return f"[{art_id}] {len(hits)} match window(s) for {pattern!r}:\n" + "\n".join(hits)

    def listing(self) -> str:
        if not self._by_id:
            return "no artifacts stored"
        lines = []
        for artifact in self._by_id.values():
            state = f"DROPPED: {artifact.dropped_reason}" if artifact.dropped_reason else "available"
            lines.append(f"{artifact.id} | {artifact.kind} | {artifact.size} chars | {artifact.origin} | {state}")
        return "\n".join(lines)

    def maybe_store(self, text: str, *, kind: str = "tool-result", origin: str = "") -> str:
        """Inline small results; replace big ones with an envelope.

        The threshold is the whole point: paying a tool round-trip to fetch a 2 kB response would
        be slower and dumber than just showing it.
        """
        if len(text) <= self.inline_limit:
            return text
        return self.envelope(self.put(text, kind=kind, origin=origin))
