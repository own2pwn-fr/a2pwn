"""burpwn installer: arch-triple mapping, URL construction, destination + PATH resolution.

Pure logic only — no network, no real download. The `install_burpwn` download path is exercised
end to end in test_cli_gate via a monkeypatched installer.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from a2pwn import installer


# --- release_triple --------------------------------------------------------- #
def test_release_triple_x86_64():
    assert installer.release_triple("Linux", "x86_64") == "x86_64-unknown-linux-gnu"


def test_release_triple_amd64_alias():
    assert installer.release_triple("Linux", "amd64") == "x86_64-unknown-linux-gnu"


def test_release_triple_aarch64():
    assert installer.release_triple("Linux", "aarch64") == "aarch64-unknown-linux-gnu"
    assert installer.release_triple("Linux", "arm64") == "aarch64-unknown-linux-gnu"


def test_release_triple_rejects_non_linux():
    with pytest.raises(installer.InstallError, match="Linux-only"):
        installer.release_triple("Darwin", "arm64")


def test_release_triple_rejects_unknown_arch():
    with pytest.raises(installer.InstallError, match="unsupported architecture"):
        installer.release_triple("Linux", "riscv64")


# --- release_url ------------------------------------------------------------ #
def test_release_url_latest():
    url = installer.release_url("x86_64-unknown-linux-gnu", "latest")
    assert url == (
        "https://github.com/own2pwn-fr/burpwn/releases/latest/download/burpwn-x86_64-unknown-linux-gnu.tar.gz"
    )


def test_release_url_pinned_version():
    url = installer.release_url("aarch64-unknown-linux-gnu", "v0.3.1")
    assert url == (
        "https://github.com/own2pwn-fr/burpwn/releases/download/v0.3.1/"
        "burpwn-aarch64-unknown-linux-gnu.tar.gz"
    )


# --- on_path / default_dest ------------------------------------------------- #
def test_on_path_true_when_listed(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", f"/usr/bin:{tmp_path}:/bin")
    assert installer.on_path(tmp_path) is True


def test_on_path_false_when_absent(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    assert installer.on_path(tmp_path) is False


def test_default_dest_prefers_local_bin_on_path(monkeypatch, tmp_path):
    home = tmp_path / "home"
    local_bin = home / ".local" / "bin"
    local_bin.mkdir(parents=True)
    monkeypatch.setattr(installer.Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("PATH", f"/usr/bin:{local_bin}")
    assert installer.default_dest() == local_bin


def test_default_dest_falls_back_to_local_bin_when_not_on_path(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(installer.Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("PATH", "/usr/bin:/bin")  # nothing under home
    assert installer.default_dest() == home / ".local" / "bin"


# --- install_burpwn extraction (no network: build a local tarball) ---------- #
def _make_tarball(path: Path, member_name: str, body: bytes) -> None:
    import io
    import tarfile

    with tarfile.open(path, "w:gz") as tf:
        info = tarfile.TarInfo(member_name)
        info.size = len(body)
        tf.addfile(info, io.BytesIO(body))


def test_install_burpwn_extracts_and_marks_executable(monkeypatch, tmp_path):
    src_tarball = tmp_path / "burpwn-x86_64-unknown-linux-gnu.tar.gz"
    _make_tarball(src_tarball, "burpwn-x86_64-unknown-linux-gnu/burpwn", b"#!/bin/sh\necho hi\n")

    # Route the download at the pure fetch boundary: urlopen returns a handle to our local tarball.
    monkeypatch.setattr(installer.urllib.request, "urlopen", lambda url: src_tarball.open("rb"))

    dest = tmp_path / "bin"
    out = installer.install_burpwn(dest, version="latest", triple="x86_64-unknown-linux-gnu")
    assert out == dest / "burpwn"
    assert out.read_bytes().startswith(b"#!/bin/sh")
    assert out.stat().st_mode & 0o111  # executable bits set


def test_install_burpwn_rejects_tarball_without_binary(monkeypatch, tmp_path):
    bad = tmp_path / "bad.tar.gz"
    _make_tarball(bad, "burpwn-x86_64-unknown-linux-gnu/README", b"nope")
    monkeypatch.setattr(installer.urllib.request, "urlopen", lambda url: bad.open("rb"))

    with pytest.raises(installer.InstallError, match="did not contain a 'burpwn' binary"):
        installer.install_burpwn(tmp_path / "bin", triple="x86_64-unknown-linux-gnu")
