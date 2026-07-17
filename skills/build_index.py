#!/usr/bin/env python3
"""Compile skills/_index.json + skills/_index.sqlite (FTS5) from every SKILL.md frontmatter.

Usage:
    python skills/build_index.py                 # (re)build the discovery index
    python skills/build_index.py --verify-sources # ALSO fail (exit 1) if any payload
                                                  # glob/file resolves to zero files under repo root

The heavy lifting lives in ``a2pwn.catalog.build_index`` so it is unit-testable; this
script is the thin CLI wrapper that also wires ``src/`` onto sys.path for in-tree runs.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent
if str(_REPO / "src") not in sys.path:
    sys.path.insert(0, str(_REPO / "src"))

from a2pwn.catalog import build_index  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "--verify-sources",
        action="store_true",
        help="fail if any referenced payload glob/file resolves to zero files",
    )
    ap.add_argument("--skills-root", default=str(_HERE), help="skills directory to index")
    ap.add_argument("--repo-root", default=str(_REPO), help="root for resolving payload paths")
    args = ap.parse_args(argv)

    out = build_index(
        Path(args.skills_root),
        repo_root=Path(args.repo_root),
        verify_sources=args.verify_sources,
    )
    print(f"indexed {out['count']} skills -> {out['index_json']}, {out['index_sqlite']}")
    if args.verify_sources and out["missing"]:
        for miss in out["missing"]:
            print(f"MISSING SOURCE: {miss}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
