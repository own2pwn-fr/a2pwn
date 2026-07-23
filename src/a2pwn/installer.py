"""Fetch and install the burpwn release binary — the one dependency ``uv sync`` cannot pull.

burpwn is a prebuilt GitHub-release binary (rootless-namespace sandbox + intercepting proxy), not a
Python package, so a ``git clone`` → ``uv sync`` → ``uv run`` flow leaves it missing and the agent
fails at the first sandbox tool call. ``a2pwn install-burpwn`` closes that gap: resolve the arch
triple, download the release tarball from the burpwn repo, and drop the ``burpwn`` binary somewhere
on ``PATH``. This mirrors the Dockerfile's ``curl | tar | install`` recipe for a host install.

The pure pieces (triple mapping, URL construction, destination resolution, PATH membership) are
factored out so they can be unit-tested without touching the network.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat
import tarfile
import tempfile
import urllib.request
from pathlib import Path

BURPWN_REPO = "https://github.com/own2pwn-fr/burpwn"

# uname machine → the release target triple burpwn publishes (GNU/glibc Linux builds only).
_ARCH_TRIPLES = {
    "x86_64": "x86_64-unknown-linux-gnu",
    "amd64": "x86_64-unknown-linux-gnu",
    "aarch64": "aarch64-unknown-linux-gnu",
    "arm64": "aarch64-unknown-linux-gnu",
}


class InstallError(RuntimeError):
    """burpwn install could not proceed (unsupported platform, download / extract / verify failure)."""


def release_triple(system: str | None = None, machine: str | None = None) -> str:
    """Map the host to the burpwn release target triple, or raise ``InstallError`` if unsupported.

    burpwn needs rootless user/network namespaces, so it is Linux-only; on macOS/Windows the answer
    is the Docker image, not a host binary.
    """
    sys_name = (system or platform.system()).lower()
    if sys_name != "linux":
        raise InstallError(
            f"burpwn is Linux-only (it needs rootless user/network namespaces); this host reports "
            f"{sys_name!r}. On macOS/Windows use the Docker image (own2pwnfr/a2pwn) instead."
        )
    mach = (machine or platform.machine()).lower()
    triple = _ARCH_TRIPLES.get(mach)
    if triple is None:
        raise InstallError(
            f"unsupported architecture {mach!r}; burpwn ships x86_64 and aarch64 Linux builds. "
            f"Build it from source instead: {BURPWN_REPO}"
        )
    return triple


def release_url(triple: str, version: str = "latest") -> str:
    """GitHub release download URL for a triple. ``latest`` uses the moving ``latest`` alias."""
    if version == "latest":
        return f"{BURPWN_REPO}/releases/latest/download/burpwn-{triple}.tar.gz"
    return f"{BURPWN_REPO}/releases/download/{version}/burpwn-{triple}.tar.gz"


def _path_dirs() -> list[str]:
    return [p for p in os.environ.get("PATH", "").split(os.pathsep) if p]


def default_dest() -> Path:
    """A user-writable bin dir for the binary, preferring one already on ``PATH``.

    Order: ``~/.local/bin`` if it is on ``PATH``; else the first ``PATH`` dir under ``$HOME`` we can
    write to; else ``~/.local/bin`` (created on install even if not yet on ``PATH`` — the caller
    warns and prints the ``export PATH`` hint).
    """
    home = Path.home()
    preferred = home / ".local" / "bin"
    dirs = _path_dirs()
    if str(preferred) in dirs:
        return preferred
    for d in dirs:
        p = Path(d)
        try:
            if p.is_relative_to(home) and os.access(p, os.W_OK):
                return p
        except ValueError:
            continue
    return preferred


def on_path(dest: Path) -> bool:
    """True when ``dest`` is on the current ``PATH`` (normalized comparison)."""
    normalized = {os.path.normpath(p) for p in _path_dirs()}
    return os.path.normpath(str(dest)) in normalized


def _find_binary_member(tf: tarfile.TarFile) -> tarfile.TarInfo:
    """The ``burpwn`` executable inside the release tarball (``burpwn-<triple>/burpwn``)."""
    for member in tf.getmembers():
        if member.isfile() and Path(member.name).name == "burpwn":
            return member
    raise InstallError("release tarball did not contain a 'burpwn' binary")


def install_burpwn(dest: Path, *, version: str = "latest", triple: str | None = None) -> Path:
    """Download, extract and install the burpwn binary into ``dest``; return the installed path.

    Only the single ``burpwn`` member is extracted, to a name we control — so a malicious tarball
    cannot path-traverse out of the temp dir. The binary is made executable before the final move.
    """
    triple = triple or release_triple()
    url = release_url(triple, version)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / "burpwn"

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        tarball = tmp_dir / "burpwn.tar.gz"
        try:
            with urllib.request.urlopen(url) as resp, tarball.open("wb") as fh:  # noqa: S310 - fixed https URL
                shutil.copyfileobj(resp, fh)
        except InstallError:
            raise
        except Exception as exc:  # noqa: BLE001 - surface a clean install error, not a raw urllib traceback
            raise InstallError(f"failed to download {url}: {exc}") from exc

        try:
            with tarfile.open(tarball) as tf:
                member = _find_binary_member(tf)
                src = tf.extractfile(member)
                if src is None:
                    raise InstallError("could not read the burpwn binary from the release tarball")
                extracted = tmp_dir / "burpwn.bin"
                with src, extracted.open("wb") as fh:
                    shutil.copyfileobj(src, fh)
        except InstallError:
            raise
        except Exception as exc:  # noqa: BLE001 - tarfile errors → clean install error
            raise InstallError(f"failed to extract {url}: {exc}") from exc

        extracted.chmod(extracted.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        shutil.move(str(extracted), str(target))

    return target
