"""Declarative engagement files (``--config engagement.yaml``).

Flags stopped scaling: a real scope is 25 hosts with carve-outs, and identities carry *secrets* —
putting a password in an ``--identity`` flag writes it into shell history and the process table.
A file solves both, and makes an engagement reproducible and reviewable (a client can read the YAML
and see exactly what was authorised).

Every key mirrors a CLI flag; explicit CLI flags always WIN over the file, so a file can set the
scope while the command line overrides a cap for one run. Unknown top-level keys are rejected rather
than ignored — a typo'd ``exlude:`` silently widening the tested scope is precisely the failure this
file is supposed to prevent.

This file is part of a2pwn and is distributed under the GNU Affero General Public License v3.0
or later; see the repository ``LICENSE`` for the full text.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from a2pwn.config import IdentitySpec

#: Top-level keys an engagement file may declare.
KNOWN_KEYS = frozenset(
    {
        "name",
        "objective",
        "targets",
        "in_scope",
        "exclude",
        "identities",
        "active_exploit",
        "dos",
        "oob_listener",
        "executor_model",
        "verifier_model",
        "max_phases",
        "max_dispatches",
        "max_wall_secs",
        "max_usd",
        "max_tokens",
        "max_rps",
        "fuzz_max_requests",
        "block_threshold",
        "checkpoint_uri",
        "format",
    }
)


class ConfigError(ValueError):
    """The engagement file is unreadable, malformed, or declares unknown/invalid keys."""


def _as_list(value: Any, key: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    raise ConfigError(f"{key!r} must be a string or a list of strings, got {type(value).__name__}")


def load_engagement_file(path: str | Path) -> dict:
    """Parse and validate an engagement YAML file into a plain dict of CLI-shaped values.

    ``identities`` entries are validated into :class:`~a2pwn.config.IdentitySpec` here rather than
    at use time, so a malformed credential block fails before the authorization gate and before any
    model spend — not three phases into a run.
    """
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read engagement file {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"engagement file {path} is not valid YAML: {exc}") from exc

    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ConfigError(f"engagement file {path} must be a mapping at the top level")

    unknown = sorted(set(raw) - KNOWN_KEYS)
    if unknown:
        raise ConfigError(
            f"engagement file {path} has unknown key(s) {unknown}. Known keys: "
            f"{sorted(KNOWN_KEYS)}. (A typo here would silently change the tested scope, so it is "
            "an error rather than a warning.)"
        )

    out: dict = dict(raw)
    for key in ("targets", "in_scope", "exclude"):
        if key in out:
            out[key] = _as_list(out[key], key)

    identities: list[IdentitySpec] = []
    for i, entry in enumerate(raw.get("identities") or []):
        if not isinstance(entry, dict):
            raise ConfigError(f"identities[{i}] must be a mapping")
        try:
            identities.append(IdentitySpec(**entry))
        except Exception as exc:  # noqa: BLE001 - surfaced as a config error with the index
            raise ConfigError(f"identities[{i}] is invalid: {exc}") from exc
    names = [i.name for i in identities]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise ConfigError(f"duplicate identity name(s) {dupes} — names are the key the model uses")
    out["identities"] = identities
    return out


def merge(file_values: dict, cli_values: dict, defaults: dict | None = None) -> dict:
    """Merge file + CLI, with an explicit CLI value winning.

    "Explicit" means "different from the flag's default": typer cannot distinguish an omitted flag
    from one passed at its default value, so ``defaults`` names what an unset flag looks like. A CLI
    value equal to its default never overrides the file — otherwise every file setting would be
    clobbered by flag defaults the operator never typed.
    """
    defaults = defaults or {}
    merged = dict(file_values)
    for key, value in cli_values.items():
        if value is None:
            continue
        if key in defaults and value == defaults[key]:
            continue
        merged[key] = value
    return merged
