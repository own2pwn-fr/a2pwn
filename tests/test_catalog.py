"""Tests for the skill/tool catalog: FTS + frontmatter retrieval, load_skill, Tool.run tiers."""

from __future__ import annotations

from pathlib import Path

import pytest

from a2pwn import catalog

_SKILL_MD = """---
name: web-sqli
description: >
  Detect SQL injection in web parameters when numeric or boolean responses shift under
  quote perturbation. Covers error-based, boolean-blind and time-based.
tags: [web, injection, sqli]
tools: [sqlmap]
payloads:
  - {kind: inline, inline: ["' OR 1=1-- -"], license: MIT, credit: test-corpus}
verification:
  kind: timing
  script: verify.py
  threshold_ms: 4000
  signals: ["you have an error in your SQL syntax"]
license: AGPL-3.0-or-later
version: 1.2.0
---
# web-sqli body

Methodology: fuzz a quote set, watch the timing anomaly, re-derive with verify.py.
"""


def _write_skill_tree(root: Path) -> None:
    d = root / "web" / "sqli"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (d / "verify.py").write_text("print('ok')\n", encoding="utf-8")


class FakeClient:
    """Stand-in for BurpwnClient: records exec calls and returns a canned envelope."""

    def __init__(self, envelope: dict):
        self.envelope = envelope
        self.calls: list[tuple[list[str], str | None]] = []

    async def exec(self, argv, workspace=None, timeout_secs=None):
        self.calls.append((argv, workspace))
        return self.envelope


# --------------------------------------------------------------------------- #
# retrieval + loading                                                          #
# --------------------------------------------------------------------------- #
def test_retrieve_frontmatter_fallback(tmp_path, monkeypatch):
    """No index present -> retrieve scans SKILL.md frontmatter and tag-prefilters."""
    monkeypatch.setenv("A2PWN_SKILLS_DIR", str(tmp_path))
    _write_skill_tree(tmp_path)
    assert not (tmp_path / "_index.sqlite").exists()

    cards = catalog.retrieve("sql injection in a query parameter", tags=["sqli"])
    assert any(c.name == "web-sqli" for c in cards)

    # tag prefilter excludes non-matching tags
    assert catalog.retrieve("something unrelated", tags=["xxe"]) == []


def test_retrieve_fts_index(tmp_path, monkeypatch):
    """Built _index.sqlite -> retrieve uses the FTS5 prefilter."""
    monkeypatch.setenv("A2PWN_SKILLS_DIR", str(tmp_path))
    _write_skill_tree(tmp_path)
    out = catalog.build_index(tmp_path, repo_root=tmp_path)
    assert out["count"] == 1
    assert (tmp_path / "_index.sqlite").exists()
    assert (tmp_path / "_index.json").exists()

    cards = catalog.retrieve("sql injection quote perturbation", tags=["web"])
    assert any(c.name == "web-sqli" for c in cards)
    # FTS path returns a SkillCard with the relative path
    card = next(c for c in cards if c.name == "web-sqli")
    assert card.path == "web/sqli/SKILL.md"


def test_load_skill(tmp_path, monkeypatch):
    monkeypatch.setenv("A2PWN_SKILLS_DIR", str(tmp_path))
    _write_skill_tree(tmp_path)

    skill = catalog.load_skill("web-sqli")
    assert skill.name == "web-sqli"
    assert skill.version == "1.2.0"
    assert "sqlmap" in skill.tools
    assert "Methodology" in skill.body()
    # timing oracle mapped through, leftover frontmatter keys folded into expect
    assert skill.verification.kind == "timing"
    assert skill.verification.expect["threshold_ms"] == 4000
    # adjacent verify.py resolved into the oracle's expect.script
    assert skill.verification.expect["script"].endswith("verify.py")
    assert Path(skill.verification.expect["script"]).exists()

    with pytest.raises(KeyError):
        catalog.load_skill("does-not-exist")


def test_load_skill_inline_payload_resolves_empty(tmp_path, monkeypatch):
    monkeypatch.setenv("A2PWN_SKILLS_DIR", str(tmp_path))
    _write_skill_tree(tmp_path)
    skill = catalog.load_skill("web-sqli")
    assert skill.payloads[0].kind == "inline"
    assert skill.payload_files(tmp_path) == []  # inline sources resolve to no files


# --------------------------------------------------------------------------- #
# build_index --verify-sources                                                 #
# --------------------------------------------------------------------------- #
def test_build_index_verify_sources_flags_missing(tmp_path):
    d = tmp_path / "web" / "x"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\n"
        "name: x\n"
        "description: test skill\n"
        "tags: [t]\n"
        "payloads:\n"
        '  - {kind: glob, path: "vendor/nope/*.txt", license: MIT, credit: c}\n'
        "verification: {kind: signature, signals: []}\n"
        "license: MIT\n"
        "version: 0.0.1\n"
        "---\nbody\n",
        encoding="utf-8",
    )
    out = catalog.build_index(tmp_path, repo_root=tmp_path, verify_sources=True)
    assert out["missing"], "a glob resolving to zero files must be reported"
    assert "vendor/nope/*.txt" in out["missing"][0]


def test_build_index_verify_sources_ok_when_present(tmp_path):
    (tmp_path / "vendor" / "here").mkdir(parents=True)
    (tmp_path / "vendor" / "here" / "a.txt").write_text("payload\n", encoding="utf-8")
    d = tmp_path / "web" / "y"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\n"
        "name: y\n"
        "description: test skill\n"
        "tags: [t]\n"
        "payloads:\n"
        '  - {kind: glob, path: "vendor/here/*.txt", license: MIT, credit: c}\n'
        "verification: {kind: signature, signals: []}\n"
        "license: MIT\n"
        "version: 0.0.1\n"
        "---\nbody\n",
        encoding="utf-8",
    )
    out = catalog.build_index(tmp_path, repo_root=tmp_path, verify_sources=True)
    assert out["missing"] == []


# --------------------------------------------------------------------------- #
# Tool.run tiers                                                               #
# --------------------------------------------------------------------------- #
async def test_tool_run_docker_captures_false_warns(monkeypatch):
    """A docker-netns tool (captures=False) => WARN note, no claimed evidence."""

    def fake_which(binary):
        return "/usr/bin/docker" if binary == "docker" else None

    monkeypatch.setattr(catalog.shutil, "which", fake_which)
    tool = catalog.Tool(
        name="hydra",
        binary="hydra",
        acquisition=["native", "docker"],
        docker_image="vanhauser/hydra:latest",
        captures=False,
    )
    client = FakeClient({"exit_code": 0, "captured_request_ids": [], "exec_id": "e1"})
    res = await tool.run(client, "ws-hydra", args=["-h"])

    assert res.availability == "docker"
    assert res.note and res.note.startswith("WARN")
    assert res.captured_request_ids == []
    assert res.findings == []
    # shelled through client.exec as a docker run
    assert client.calls[0][0][:3] == ["docker", "run", "--rm"]
    assert client.calls[0][1] == "ws-hydra"


async def test_tool_run_native_capture_alarm(monkeypatch):
    """A native net op that captured zero flows => ALARM note (traffic escaped)."""

    def fake_which(binary):
        return f"/usr/bin/{binary}"

    monkeypatch.setattr(catalog.shutil, "which", fake_which)
    tool = catalog.Tool(name="curl", binary="curl", acquisition=["native"])
    client = FakeClient({"exit_code": 0, "captured_request_ids": [], "exec_id": "e2"})
    res = await tool.run(client, "ws", args=["https://t/"])
    assert res.availability == "native"
    assert res.note == "ALARM: bypassed capture"


async def test_tool_run_native_capture_ok(monkeypatch):
    def fake_which(binary):
        return f"/usr/bin/{binary}"

    monkeypatch.setattr(catalog.shutil, "which", fake_which)
    tool = catalog.Tool(name="curl", binary="curl", acquisition=["native"])
    client = FakeClient({"exit_code": 0, "captured_request_ids": [11, 12], "exec_id": "e3"})
    res = await tool.run(client, "ws", args=["https://t/"])
    assert res.note is None
    assert res.captured_request_ids == [11, 12]


def test_tool_run_skipped_when_no_tier(monkeypatch):
    monkeypatch.setattr(catalog.shutil, "which", lambda b: None)
    tool = catalog.Tool(name="ghost", binary="ghost", acquisition=["native", "docker"])
    assert tool.resolve_tier() == "skipped"


def test_load_registry():
    reg = catalog.load_registry()
    assert "nuclei" in reg and "sqlmap" in reg and "hydra" in reg
    assert reg["hydra"].captures is False  # docker-only fallback
    assert reg["webcrack"].net is False
    assert reg["sqlmap"].pkg == "uvx sqlmap"


def test_load_registry_has_http_clients():
    """httpx/curl (referenced by nearly every skill) are real manifests now, no longer silently
    dropped from every skill's tool chain."""
    reg = catalog.load_registry()
    for name in ("httpx", "curl", "jsdebundle", "hashcat"):
        assert name in reg, f"{name} missing from registry"
    assert reg["curl"].captures is True
    # offline post-processing tools carry net:false so an empty capture set is not an ALARM
    assert reg["jsdebundle"].net is False and reg["hashcat"].net is False


async def test_tool_run_docker_tier_captures_true_still_uncaptured(monkeypatch):
    """A captures:true tool resolved to the docker tier is uncaptured (own netns) => WARN, no
    evidence — the manifest bool only describes the native/pkg tiers."""

    def fake_which(binary):
        return "/usr/bin/docker" if binary == "docker" else None

    monkeypatch.setattr(catalog.shutil, "which", fake_which)
    tool = catalog.Tool(
        name="nuclei",
        binary="nuclei",
        acquisition=["native", "docker"],
        docker_image="projectdiscovery/nuclei:latest",
        captures=True,
        argv_template=["-u", "{target}"],
    )
    # a non-empty capture set from unrelated flows must NOT let docker output pass as evidence
    client = FakeClient({"exit_code": 0, "captured_request_ids": [7, 8], "exec_id": "e9"})
    res = await tool.run(client, "ws", target="https://t/")
    assert res.availability == "docker"
    assert res.note and res.note.startswith("WARN")
    assert res.captured_request_ids == []
    assert res.findings == []


# --------------------------------------------------------------------------- #
# build_argv threading                                                         #
# --------------------------------------------------------------------------- #
def test_build_argv_threads_target_param_and_extra():
    tool = catalog.Tool(
        name="sqlmap",
        binary="sqlmap",
        argv_template=["-u", "{target}", "-p", "{param}", "--batch"],
    )
    argv = tool.build_argv(target="https://t/?id=1", param="id", extra_args="--level 3")
    assert argv == ["sqlmap", "-u", "https://t/?id=1", "-p", "id", "--batch", "--level", "3"]


def test_build_argv_drops_empty_placeholder_and_dangling_flag():
    """An omitted optional placeholder drops both the value token and its preceding flag."""
    tool = catalog.Tool(name="sqlmap", binary="sqlmap", argv_template=["-u", "{target}", "-p", "{param}"])
    argv = tool.build_argv(target="https://t/")  # param omitted
    assert argv == ["sqlmap", "-u", "https://t/"]  # no bare '-p'


# --------------------------------------------------------------------------- #
# FTS operator-token robustness                                                #
# --------------------------------------------------------------------------- #
def test_retrieve_fts_operator_tokens_do_not_degrade(tmp_path, monkeypatch):
    """A task containing FTS5 barewords (and/or/not/near) must still rank by relevance, not
    silently fall back to an arbitrary unranked SELECT that returns irrelevant skills."""
    monkeypatch.setenv("A2PWN_SKILLS_DIR", str(tmp_path))
    _write_skill_tree(tmp_path)  # web-sqli
    other = tmp_path / "recon" / "photos"
    other.mkdir(parents=True)
    (other / "SKILL.md").write_text(
        "---\nname: recon-photos\ndescription: landscape photography gallery crawler\n"
        "tags: [recon]\nverification: {kind: signature, signals: []}\n"
        "license: MIT\nversion: 0.0.1\n---\nbody\n",
        encoding="utf-8",
    )
    out = catalog.build_index(tmp_path, repo_root=tmp_path)
    assert out["count"] == 2

    cards = catalog.retrieve("sqli and injection near quote")
    names = [c.name for c in cards]
    assert "web-sqli" in names
    assert "recon-photos" not in names  # would leak in on the unranked fallback


# --------------------------------------------------------------------------- #
# per-skill verify.py wiring                                                   #
# --------------------------------------------------------------------------- #
_VERIFY_PY = (
    "async def verify(ctx):\n"
    "    from a2pwn.oracles import OracleResult\n"
    "    return OracleResult(confirmed=bool(ctx.get('hit')), kind='signature', evidence='t')\n"
)


def test_load_skill_exposes_verifier(tmp_path, monkeypatch):
    monkeypatch.setenv("A2PWN_SKILLS_DIR", str(tmp_path))
    d = tmp_path / "web" / "sqli"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (d / "verify.py").write_text(_VERIFY_PY, encoding="utf-8")

    skill = catalog.load_skill("web-sqli")
    assert skill.verify_script() is not None and skill.verify_script().name == "verify.py"
    fn = skill.verifier()
    assert callable(fn)


async def test_verifier_runs_and_returns_oracle_result(tmp_path, monkeypatch):
    monkeypatch.setenv("A2PWN_SKILLS_DIR", str(tmp_path))
    d = tmp_path / "web" / "sqli"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(_SKILL_MD, encoding="utf-8")
    (d / "verify.py").write_text(_VERIFY_PY, encoding="utf-8")

    fn = catalog.load_skill("web-sqli").verifier()
    hit = await fn({"hit": True})
    miss = await fn({"hit": False})
    assert hit.confirmed is True and miss.confirmed is False
    # frontmatter oracle spec is exposed alongside the bespoke verifier
    skill = catalog.load_skill("web-sqli")
    assert skill.verification.kind == "timing"
    assert "you have an error in your SQL syntax" in skill.verification.signals


def test_import_verify_missing_or_bad_returns_none(tmp_path):
    assert catalog.import_verify(None) is None
    assert catalog.import_verify(tmp_path / "nope.py") is None
    bad = tmp_path / "novrfy.py"
    bad.write_text("x = 1\n", encoding="utf-8")  # no verify attr
    assert catalog.import_verify(bad) is None


# --------------------------------------------------------------------------- #
# as_langchain_tools threads real inputs                                       #
# --------------------------------------------------------------------------- #
async def test_langchain_tool_threads_target_into_argv(tmp_path, monkeypatch):
    """The skill wrapper exposes a `target` input and threads it through run_all->run->argv.

    The registry is injected here (argv_template lives in the BURPWN-owned registry.yaml) so
    this exercises the CATALOG threading mechanism independently of that file's contents.
    """
    monkeypatch.setenv("A2PWN_SKILLS_DIR", str(tmp_path))
    _write_skill_tree(tmp_path)
    monkeypatch.setattr(catalog.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(
        catalog,
        "load_registry",
        lambda *a, **k: {
            "sqlmap": catalog.Tool(
                name="sqlmap",
                binary="sqlmap",
                acquisition=["native"],
                argv_template=["-u", "{target}", "-p", "{param}", "--batch"],
            )
        },
    )

    client = FakeClient({"exit_code": 0, "captured_request_ids": [1], "exec_id": "e0"})
    skill = catalog.load_skill("web-sqli")  # tools: [sqlmap]
    tools = catalog.as_langchain_tools([skill], client, collab=None)
    assert len(tools) == 1
    tool = tools[0]
    assert tool.name == "skill_web_sqli"
    assert "target" in tool.args  # real input surfaced to the agent

    await tool.ainvoke({"target": "https://victim/?id=1", "param": "id", "workspace": "ws"})
    argv, ws = client.calls[0]
    assert ws == "ws"
    assert "https://victim/?id=1" in argv and "id" in argv  # target/param reached the binary
