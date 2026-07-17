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
