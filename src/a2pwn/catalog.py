"""Skill retrieval/loading + uniform Tool wrapper/Runner + langchain tool adapters.

Two-stage retrieval (Claude-Code-faithful progressive disclosure):
  Stage A — deterministic tag/FTS5 prefilter over ``skills/_index.sqlite`` (graceful
            fallback to scanning SKILL.md frontmatter when the index is absent).
  Stage B — the LLM activates a shortlisted skill via ``load_skill(name)`` which parses
            the SKILL.md YAML frontmatter + body, resolves payload sources and the
            adjacent ``verify.py``.

Every Tool run shells through ``BurpwnClient.exec`` so traffic is captured/MITM'd; an
uncaptured net op raises an ALARM note, a docker-netns tool a WARN note (never evidence).
"""

from __future__ import annotations

import importlib.util
import json
import logging
import os
import re
import shlex
import shutil
import sqlite3
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import yaml
from langchain_core.tools import BaseTool, StructuredTool
from pydantic import BaseModel

from a2pwn.burpwn import BurpwnClient
from a2pwn.models import Finding
from a2pwn.oracles import VerificationOracle

_log = logging.getLogger(__name__)

_ORACLE_KINDS = {
    "differential",
    "timing",
    "oob",
    "marker",
    "signature",
    "two_identity",
    "llm_rubric",
}


# --------------------------------------------------------------------------- #
# skill / payload models                                                       #
# --------------------------------------------------------------------------- #
class PayloadSource(BaseModel):
    kind: Literal["file", "glob", "inline", "upstream_doc"]
    path: str | None = None
    inline: list[str] | None = None
    license: str
    credit: str

    def resolve(self, root: Path) -> list[Path]:
        """Resolve to concrete files under ``root`` (repo root). Inline sources yield []."""
        if self.kind == "inline" or self.path is None:
            return []
        root = Path(root)
        if self.kind == "glob":
            return sorted(root.glob(self.path))
        p = root / self.path
        return [p] if p.exists() else []


class Skill(BaseModel):
    name: str
    version: str
    description: str
    tags: list[str]
    tools: list[str] = []
    payloads: list[PayloadSource] = []
    verification: VerificationOracle
    references: list[str] = []
    license: str
    body_path: Path

    def body(self) -> str:
        """The methodology prose (SKILL.md minus its YAML frontmatter)."""
        _, body = parse_frontmatter(Path(self.body_path).read_text(encoding="utf-8"))
        return body

    def payload_files(self, root: Path) -> list[Path]:
        out: list[Path] = []
        for src in self.payloads:
            out.extend(src.resolve(root))
        return out

    def verify_script(self) -> Path | None:
        """Path to the skill's adjacent ``verify.py`` (stashed by :func:`load_skill`), if any."""
        script = self.verification.expect.get("script")
        return Path(script) if script else None

    def verifier(self) -> Callable | None:
        """Import the skill's ``verify.py`` and return its ``verify(ctx)`` coroutine, or None.

        This is the hook the confirmation path uses when a skill ships a bespoke oracle:
        the caller runs ``await skill.verifier()(ctx)`` (returning an ``OracleResult``)
        instead of the generic frontmatter oracle. When no ``verify.py`` exists the caller
        falls back to ``skill.verification`` (kind/signals/expect/correlation_id).
        """
        return import_verify(self.verification.expect.get("script"))


class SkillCard(BaseModel):
    name: str
    description: str
    tags: list[str]
    path: str


# --------------------------------------------------------------------------- #
# frontmatter + roots                                                          #
# --------------------------------------------------------------------------- #
def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Parse a Claude-Code SKILL.md: YAML between ``---`` fences + markdown body."""
    if not text.lstrip().startswith("---"):
        return {}, text
    stripped = text.lstrip()
    parts = stripped.split("---", 2)
    if len(parts) < 3:
        return {}, text
    try:
        meta = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        return {}, text
    if not isinstance(meta, dict):
        return {}, text
    return meta, parts[2].lstrip("\n")


def _skills_root() -> Path:
    env = os.environ.get("A2PWN_SKILLS_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    for cand in (here.parent / "_skills", here.parents[2] / "skills"):
        if cand.is_dir():
            return cand
    return here.parents[2] / "skills"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- #
# retrieval                                                                    #
# --------------------------------------------------------------------------- #
def _terms(text: str) -> list[str]:
    seen: list[str] = []
    for tok in re.findall(r"[a-z0-9]+", (text or "").lower()):
        if len(tok) > 2 and tok not in seen:
            seen.append(tok)
    return seen


def _san(tag: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (tag or "").lower())


def retrieve(task: str, tags: list[str] = [], k: int = 12) -> list[SkillCard]:  # noqa: B006
    """FTS5/tag prefilter over ``_index.sqlite``; fall back to frontmatter scan if absent."""
    root = _skills_root()
    db = root / "_index.sqlite"
    if db.exists():
        try:
            return _retrieve_fts(db, task, tags, k)
        except sqlite3.Error:
            pass
    return _retrieve_scan(root, task, tags, k)


def _fts_quote(tok: str) -> str:
    """Wrap a term as an FTS5 string literal so bareword operators (AND/OR/NOT/NEAR) and
    other punctuation are matched literally instead of parsed as query syntax."""
    return '"' + tok.replace('"', '""') + '"'


def _terms_clause(terms: list[str]) -> str:
    return "(" + " OR ".join(_fts_quote(t) for t in terms) + ")"


def _tags_clause(tagset: list[str]) -> str:
    return "(" + " OR ".join(f"tags:{_fts_quote(t)}" for t in tagset) + ")"


def _retrieve_fts(db: Path, task: str, tags: list[str], k: int) -> list[SkillCard]:
    terms = _terms(task)
    tagset = [t for t in (_san(x) for x in tags) if t]
    clauses: list[str] = []
    if terms:
        clauses.append(_terms_clause(terms))
    if tagset:
        clauses.append(_tags_clause(tagset))
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        rows = _fts_query(con, " AND ".join(clauses), k)
        if not rows and tagset:
            rows = _fts_query(con, _tags_clause(tagset), k)
        if not rows and terms:
            rows = _fts_query(con, _terms_clause(terms), k)
    finally:
        con.close()
    return [
        SkillCard(name=r["name"], description=r["description"], tags=r["tags"].split(), path=r["path"])
        for r in rows
    ]


def _fts_query(con: sqlite3.Connection, match: str, k: int) -> list[sqlite3.Row]:
    if not match:
        return con.execute(
            "SELECT name, description, tags, path FROM skills_fts LIMIT ?", (k,)
        ).fetchall()
    try:
        return con.execute(
            "SELECT name, description, tags, path FROM skills_fts "
            "WHERE skills_fts MATCH ? ORDER BY rank LIMIT ?",
            (match, k),
        ).fetchall()
    except sqlite3.OperationalError:
        return con.execute(
            "SELECT name, description, tags, path FROM skills_fts LIMIT ?", (k,)
        ).fetchall()


def _retrieve_scan(root: Path, task: str, tags: list[str], k: int) -> list[SkillCard]:
    terms = set(_terms(task))
    tagset = {t for t in (_san(x) for x in tags) if t}
    scored: list[tuple[int, SkillCard]] = []
    for md in sorted(root.rglob("SKILL.md")):
        meta, _ = parse_frontmatter(md.read_text(encoding="utf-8"))
        if "name" not in meta or "description" not in meta:
            continue
        mtags = {t for t in (_san(x) for x in meta.get("tags", []) or []) if t}
        if tagset and not (tagset & mtags):
            continue
        hay = f"{meta['name']} {meta['description']} {' '.join(meta.get('tags', []) or [])}"
        score = len(terms & set(_terms(hay))) + 5 * len(tagset & mtags)
        scored.append(
            (
                score,
                SkillCard(
                    name=meta["name"],
                    description=meta["description"],
                    tags=meta.get("tags", []) or [],
                    path=str(md.relative_to(root)),
                ),
            )
        )
    scored.sort(key=lambda x: (-x[0], x[1].name))
    if terms or tagset:
        hits = [s for s in scored if s[0] > 0]
        if hits:
            scored = hits
    return [c for _, c in scored[:k]]


def _oracle_from_meta(raw: dict | None) -> VerificationOracle:
    data = dict(raw or {})
    kind = data.pop("kind", "signature")
    if kind not in _ORACLE_KINDS:
        kind = "signature"
    signals = data.pop("signals", []) or []
    correlation_id = data.pop("correlation_id", None)
    confirm_prompt = data.pop("confirm_prompt", None)
    expect = dict(data.pop("expect", {}) or {})
    expect.update(data)  # leftover keys (script, threshold_ms, ...) fold into expect
    return VerificationOracle(
        kind=kind,
        expect=expect,
        signals=signals,
        correlation_id=correlation_id,
        confirm_prompt=confirm_prompt,
    )


def _skill_from_meta(meta: dict, body_path: Path) -> Skill:
    payloads = [PayloadSource(**p) for p in (meta.get("payloads", []) or [])]
    return Skill(
        name=meta["name"],
        version=str(meta.get("version", "0.0.0")),
        description=meta["description"],
        tags=meta.get("tags", []) or [],
        tools=meta.get("tools", []) or [],
        payloads=payloads,
        verification=_oracle_from_meta(meta.get("verification")),
        references=meta.get("references", []) or [],
        license=meta.get("license", "UNLICENSED"),
        body_path=Path(body_path),
    )


def load_skill(name: str) -> Skill:
    """Load the full skill: frontmatter + body + resolved payload sources + adjacent verify.py."""
    root = _skills_root()
    for md in sorted(root.rglob("SKILL.md")):
        meta, _ = parse_frontmatter(md.read_text(encoding="utf-8"))
        if meta.get("name") == name:
            skill = _skill_from_meta(meta, md)
            verify = md.parent / "verify.py"
            if verify.exists():
                skill.verification.expect = {**skill.verification.expect, "script": str(verify)}
            return skill
    raise KeyError(f"skill not found: {name}")


def import_verify(script: str | Path | None) -> Callable | None:
    """Dynamically import a skill's ``verify.py`` and return its ``verify`` callable.

    Returns ``None`` when no script is given, the file is missing, or it exposes no callable
    ``verify`` attribute — the caller then falls back to the frontmatter oracle. The returned
    coroutine has the contract ``async verify(ctx: dict) -> OracleResult`` (see the shipped
    ``skills/**/verify.py`` and the OOB/signature helpers in :mod:`a2pwn.oracles`).
    """
    if not script:
        return None
    path = Path(script)
    if not path.exists():
        return None
    # Deterministic, unique module name so distinct verify.py files never collide in sys.modules.
    slug = re.sub(r"[^a-z0-9]+", "_", str(path.resolve()).lower()).strip("_")
    mod_name = f"a2pwn_skill_verify_{slug}"
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001 - a broken verify.py must not crash the gate
        sys.modules.pop(mod_name, None)
        _log.warning("failed to import verify.py at %s: %s", path, exc)
        return None
    fn = getattr(module, "verify", None)
    return fn if callable(fn) else None


# --------------------------------------------------------------------------- #
# tools                                                                        #
# --------------------------------------------------------------------------- #
class _SafeArgs(dict):
    """str.format_map mapping that renders unknown/None placeholders as empty strings."""

    def __missing__(self, key: str) -> str:  # pragma: no cover - trivial
        return ""


def _as_arg_list(extra) -> list[str]:
    """Normalise ``extra_args`` (a shell-ish string or a list) into argv tokens."""
    if not extra:
        return []
    if isinstance(extra, str):
        return shlex.split(extra)
    return [str(a) for a in extra]


class ToolResult(BaseModel):
    tool: str
    availability: Literal["native", "release", "pkg", "docker", "skipped"]
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    exec_id: str | None = None
    captured_request_ids: list[int] = []
    findings: list[Finding] = []
    note: str | None = None


class Tool(BaseModel):
    name: str
    binary: str
    acquisition: list[str] = ["native", "release", "pkg", "docker"]
    release: dict | None = None
    pkg: str | None = None
    docker_image: str | None = None
    captures: bool = True
    # a2pwn extensions (ignored by the contract's cross-module imports):
    net: bool = True
    phase: Literal["recon", "exploit"] = "exploit"
    argv_template: list[str] = []

    def _release_binary(self) -> Path | None:
        if not self.release:
            return None
        base = Path(os.environ.get("A2PWN_BIN_DIR", Path.home() / ".local" / "share" / "a2pwn" / "bin"))
        cached = base / self.binary
        return cached if cached.exists() else None

    def resolve_tier(self) -> str:
        for tier in self.acquisition:
            if tier == "native" and shutil.which(self.binary):
                return "native"
            if tier == "release" and self._release_binary():
                return "release"
            if tier == "pkg" and self.pkg and shutil.which(self.pkg.split()[0]):
                return "pkg"
            if tier == "docker" and self.docker_image and shutil.which("docker"):
                return "docker"
        return "skipped"

    def build_argv(self, **kw) -> list[str]:
        """Render the tool's ``argv_template`` with caller inputs (``target``/``param``/
        ``payload``/…). A placeholder that resolves to an empty value drops its token — and a
        dangling flag that immediately precedes it — so an omitted optional never leaves a
        bare ``-u`` with no value. ``extra_args`` (str or list) is appended verbatim. When no
        template is defined the raw ``args`` list is passed through unchanged.
        """
        if self.argv_template:
            fmt = _SafeArgs({k: "" if v is None else str(v) for k, v in kw.items()})
            args: list[str] = []
            for part in self.argv_template:
                if "{" in part:
                    rendered = part.format_map(fmt)
                    if not rendered.strip():
                        if args and args[-1].startswith("-"):
                            args.pop()  # drop the now-value-less flag
                        continue
                    args.append(rendered)
                else:
                    args.append(part)
            args.extend(_as_arg_list(kw.get("extra_args")))
        else:
            args = [str(a) for a in kw.get("args", [])]
        return [self.binary, *args]

    def parse(self, stdout: str, stderr: str) -> tuple[list[Finding], dict]:
        """Structured passthrough. Confirmed findings are produced by the oracles, not here."""
        return [], {"stdout": stdout[:4000], "stderr": stderr[:1000]}

    async def run(self, client: BurpwnClient, workspace: str, **kw) -> ToolResult:
        tier = self.resolve_tier()
        if tier == "skipped":
            return ToolResult(
                tool=self.name,
                availability="skipped",
                exit_code=127,
                note=f"skipped: {self.binary} has no available tier (native/release/pkg/docker)",
            )
        args = self.build_argv(**kw)[1:]
        argv = self._tier_argv(tier, args)
        res = await client.exec(argv, workspace=workspace, timeout_secs=kw.get("timeout_secs"))
        captured = list(res.get("captured_request_ids", []) or [])
        stdout = res.get("stdout", "") or ""
        stderr = res.get("stderr", "") or ""
        findings, _ = self.parse(stdout, stderr)
        note: str | None = None
        # The docker tier runs in its OWN net namespace (docker run --network host uses the
        # host ns, not the burpwn sandbox ns where the nftables REDIRECT lives) -> its traffic
        # is NOT MITM'd. So a docker-tier run is uncaptured regardless of the manifest's
        # captures bool, which can only express the native/pkg tiers. Never claim evidence.
        uncaptured = (not self.captures) or (tier == "docker")
        if uncaptured:
            note = "WARN: docker netns, uncaptured"
            findings = []
            captured = []
        elif self.net and not captured:
            note = "ALARM: bypassed capture"
        return ToolResult(
            tool=self.name,
            availability=tier,  # type: ignore[arg-type]
            exit_code=int(res.get("exit_code", 0) or 0),
            stdout=stdout,
            stderr=stderr,
            exec_id=res.get("exec_id"),
            captured_request_ids=captured,
            findings=findings,
            note=note,
        )

    def _tier_argv(self, tier: str, args: list[str]) -> list[str]:
        if tier == "native":
            return [self.binary, *args]
        if tier == "release":
            return [str(self._release_binary()), *args]
        if tier == "pkg":
            return [*self.pkg.split(), *args]  # type: ignore[union-attr]
        return ["docker", "run", "--rm", "--network", "host", str(self.docker_image), *args]


def load_registry(path: Path | None = None) -> dict[str, Tool]:
    path = path or (Path(__file__).resolve().parent / "tools" / "registry.yaml")
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    tools: dict[str, Tool] = {}
    for name, spec in (data.get("tools") or {}).items():
        spec = dict(spec)
        spec.setdefault("name", name)
        spec.setdefault("binary", name)
        tools[name] = Tool(**spec)
    return tools


def _merge_findings(findings: list[Finding]) -> list[Finding]:
    by_key: dict[str, Finding] = {}
    for f in findings:
        cur = by_key.get(f.key)
        if cur is None or f.rank() >= cur.rank():
            by_key[f.key] = f
    return sorted(by_key.values(), key=lambda f: -f.rank())


class Runner:
    def __init__(self, client: BurpwnClient):
        self.client = client
        self.registry = load_registry()

    async def run_all(self, skill: Skill, workspace: str, **kw) -> list[Finding]:
        missing = [t for t in skill.tools if t not in self.registry]
        if missing:
            _log.warning(
                "skill %s references tools absent from the registry (dropped): %s — "
                "add a manifest to tools/registry.yaml",
                skill.name,
                missing,
            )
        tools = [self.registry[t] for t in skill.tools if t in self.registry]
        tools.sort(key=lambda t: 0 if t.phase == "recon" else 1)  # dep order: recon -> exploit
        acc: list[Finding] = []
        for tool in tools:
            res = await tool.run(self.client, workspace, **kw)
            acc.extend(res.findings)
        return _merge_findings(acc)


def as_langchain_tools(skills: list[Skill], client: BurpwnClient, collab) -> list[BaseTool]:
    """One BaseTool per skill; invoking it runs the skill's tool chain via the burpwn sandbox.

    The wrapper threads real inputs (``target`` and optional ``param``/``payload``/
    ``extra_args``) into every registry tool's ``argv_template`` so the chain runs against a
    concrete target instead of a bare binary. Traffic is captured through ``BurpwnClient.exec``;
    findings are only ever produced by the deterministic oracles (this returns tool output +
    per-tool capture notes, never a self-asserted verdict).
    """
    runner = Runner(client)
    tools: list[BaseTool] = []
    for skill in skills:

        def _make(bound: Skill):
            async def _run(
                target: str,
                workspace: str = "default",
                param: str | None = None,
                payload: str | None = None,
                extra_args: str | None = None,
            ) -> list[dict]:
                findings = await runner.run_all(
                    bound,
                    workspace,
                    target=target,
                    param=param,
                    payload=payload,
                    extra_args=extra_args,
                )
                return [f.model_dump() for f in findings]

            return _run

        safe = re.sub(r"[^a-z0-9_]", "_", ("skill_" + skill.name).lower())
        tool_names = ", ".join(skill.tools) or "(none)"
        contract = (
            f"\n\nINPUTS: target (URL/host, required), workspace (capture bucket), "
            f"param (fuzzed parameter), payload (payload/wordlist), extra_args (extra CLI). "
            f"Runs [{tool_names}] through the burpwn sandbox against `target`. "
            f"Returns tool output; a finding is only real once an oracle re-derives it."
        )
        tools.append(
            StructuredTool.from_function(
                coroutine=_make(skill),
                name=safe,
                description=(skill.description[:800] + contract),
            )
        )
    return tools


def build_index(
    skills_root: Path, repo_root: Path | None = None, verify_sources: bool = False
) -> dict:
    """Compile ``_index.json`` + ``_index.sqlite`` (FTS5) from every SKILL.md frontmatter.

    When ``verify_sources`` is set, records every payload glob that resolves to zero files
    under ``repo_root`` in the returned ``missing`` list (the CLI turns that into exit 1).
    """
    skills_root = Path(skills_root)
    repo_root = Path(repo_root or _repo_root())
    cards: list[dict] = []
    missing: list[str] = []
    for md in sorted(skills_root.rglob("SKILL.md")):
        meta, _ = parse_frontmatter(md.read_text(encoding="utf-8"))
        if "name" not in meta or "description" not in meta:
            continue
        rel = str(md.relative_to(skills_root))
        cards.append(
            {
                "name": meta["name"],
                "description": " ".join(str(meta["description"]).split()),
                "tags": meta.get("tags", []) or [],
                "path": rel,
                "version": str(meta.get("version", "")),
                "license": meta.get("license", ""),
            }
        )
        if verify_sources:
            for raw in meta.get("payloads", []) or []:
                try:
                    src = PayloadSource(**raw)
                except Exception:
                    missing.append(f"{rel}: invalid payload spec {raw!r}")
                    continue
                if src.kind in ("glob", "file", "upstream_doc") and not src.resolve(repo_root):
                    missing.append(f"{rel}: payload '{src.path}' resolves to 0 files")
    index_json = skills_root / "_index.json"
    index_json.write_text(
        json.dumps({"skills": cards}, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    index_sqlite = skills_root / "_index.sqlite"
    _write_fts(index_sqlite, cards)
    return {
        "count": len(cards),
        "index_json": str(index_json),
        "index_sqlite": str(index_sqlite),
        "missing": missing,
    }


def _write_fts(db: Path, cards: list[dict]) -> None:
    db = Path(db)
    if db.exists():
        db.unlink()
    con = sqlite3.connect(str(db))
    try:
        con.execute(
            "CREATE VIRTUAL TABLE skills_fts USING fts5(name, description, tags, path UNINDEXED)"
        )
        con.executemany(
            "INSERT INTO skills_fts(name, description, tags, path) VALUES (?, ?, ?, ?)",
            [(c["name"], c["description"], " ".join(c["tags"]), c["path"]) for c in cards],
        )
        con.commit()
    finally:
        con.close()
