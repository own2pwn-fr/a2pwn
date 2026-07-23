"""Deterministic CVSS 3.1 base-score computation from a vector string.

The executor supplies a CVSS 3.1 vector when it reports a finding, but its arithmetic is not
trusted any more than its oracle self-checks are — the same "compute, don't ask the model to do
the maths" discipline as ``a2pwn.oracles``. :func:`parse_cvss31` re-derives the base score straight
from the official CVSS 3.1 formula (FIRST.org) so the number in the report is always consistent
with the vector, never whatever score the model happened to claim.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}
_S = {"U", "C"}

_VECTOR_RE = re.compile(
    r"^CVSS:3\.[01]/"
    r"AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])/S:(?P<S>[UC])/"
    r"C:(?P<C>[NLH])/I:(?P<I>[NLH])/A:(?P<A>[NLH])"
)
# The vector is also accepted without the leading "CVSS:3.x/" prefix (models routinely omit it).
_VECTOR_RE_BARE = re.compile(
    r"^AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])/S:(?P<S>[UC])/"
    r"C:(?P<C>[NLH])/I:(?P<I>[NLH])/A:(?P<A>[NLH])"
)

_BANDS = ((9.0, "Critical"), (7.0, "High"), (4.0, "Medium"), (0.1, "Low"))


def _severity_band(score: float) -> str:
    if score <= 0:
        return "None"
    for floor, name in _BANDS:
        if score >= floor:
            return name
    return "None"  # pragma: no cover - unreachable, scores are always >= 0


@dataclass(frozen=True)
class CvssScore:
    vector: str
    base_score: float
    severity: str


def parse_cvss31(vector: str | None) -> CvssScore | None:
    """Parse a CVSS 3.1 vector and compute its base score deterministically.

    Returns ``None`` for a missing/unparseable vector — callers must treat that as "no score to
    show", never fall back to a model-claimed number. Accepts both the full ``CVSS:3.1/...`` form
    and the bare ``AV:.../AC:.../...`` form (models routinely omit the version prefix).
    """
    if not vector:
        return None
    v = vector.strip()
    m = _VECTOR_RE.match(v) or _VECTOR_RE_BARE.match(v)
    if not m:
        return None
    g = m.groupdict()
    c, i, a = _CIA[g["C"]], _CIA[g["I"]], _CIA[g["A"]]
    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    scope = g["S"]
    if scope == "U":
        impact = 6.42 * isc_base
        pr = _PR_U[g["PR"]]
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        pr = _PR_C[g["PR"]]
    if impact <= 0:
        return CvssScore(vector=v, base_score=0.0, severity="None")
    exploitability = 8.22 * _AV[g["AV"]] * _AC[g["AC"]] * pr * _UI[g["UI"]]
    raw = impact + exploitability if scope == "U" else 1.08 * (impact + exploitability)
    score = math.ceil(min(raw, 10.0) * 10) / 10
    return CvssScore(vector=v, base_score=round(score, 1), severity=_severity_band(score))
