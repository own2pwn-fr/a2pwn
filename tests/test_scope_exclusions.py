"""Scope carve-outs: an exclusion always wins over the allow-list, on both executor paths.

Real scopes are stated as "*.example.com EXCEPT these", and a2pwn now DISCOVERS hosts on its own
(subdomain enumeration seeded at bootstrap), so an allow-list-only model would happily queue a host
the client explicitly carved out. These tests pin that exclusions are enforced at the tool layer,
not merely documented.
"""

from __future__ import annotations

import pytest

from a2pwn.config import EngagementSpec
from a2pwn.scope import ScopeGuard, is_excluded, path_of
from a2pwn.tools import burpwn_tools


def _engagement(targets, exclude=None) -> EngagementSpec:
    return EngagementSpec(
        name="t",
        targets=list(targets),
        in_scope=list(targets),
        exclude=list(exclude or []),
        session="t",
    )


# --------------------------------------------------------------------------- path parsing
@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("https://app.example.com/admin/billing", "/admin/billing"),
        ("https://app.example.com", "/"),
        ("app.example.com/admin", "/admin"),
        ("/admin/billing", "/admin/billing"),
        ("https://app.example.com/a?b=c", "/a"),
        ("--url=https://app.example.com/x", "/x"),
        ("curl", "/"),  # a non-host token has no path
        ("1' OR '1'='1", "/"),  # a payload must not parse as a path
    ],
)
def test_path_of(token, expected):
    assert path_of(token) == expected


# --------------------------------------------------------------------------- exclusion matching
def test_host_exclusion_covers_subdomains():
    assert is_excluded("legacy.example.com", "/", ["legacy.example.com"])
    assert is_excluded("api.legacy.example.com", "/", ["legacy.example.com"])
    assert not is_excluded("app.example.com", "/", ["legacy.example.com"])


def test_host_glob_exclusion():
    assert is_excluded("db.internal.example.com", "/", ["*.internal.example.com"])
    assert not is_excluded("app.example.com", "/", ["*.internal.example.com"])


def test_path_exclusion_respects_segment_boundary():
    # /admin must exclude /admin and /admin/billing but NOT /administration — a prefix match
    # without a boundary check would silently carve out an unrelated, in-scope area.
    assert is_excluded("app.example.com", "/admin", ["/admin"])
    assert is_excluded("app.example.com", "/admin/billing", ["/admin"])
    assert not is_excluded("app.example.com", "/administration", ["/admin"])


def test_url_exclusion_scopes_path_to_its_own_host():
    exclude = ["https://app.example.com/admin"]
    assert is_excluded("app.example.com", "/admin/x", exclude)
    assert not is_excluded("other.example.com", "/admin/x", exclude)
    assert not is_excluded("app.example.com", "/public", exclude)


def test_empty_exclusion_list_excludes_nothing():
    assert not is_excluded("app.example.com", "/anything", [])
    assert not is_excluded("app.example.com", "/anything", None)


# --------------------------------------------------------------------------- ScopeGuard
def test_guard_exclusion_beats_allow_list():
    guard = ScopeGuard(targets=["example.com"], exclude=["legacy.example.com"])
    assert guard.allows("app.example.com")
    assert not guard.allows("legacy.example.com")


def test_guard_without_allow_list_does_not_enforce():
    # No engagement/allow-list => no client-side refusal (burpwn's own containment still applies).
    guard = ScopeGuard()
    assert guard.allows("anything.example.org")
    assert guard.off_scope(["anything.example.org"]) == []


def test_guard_labels_off_scope_host_without_its_path():
    # A host that is entirely out of scope is reported bare: naming a path would imply some other
    # path on that host is reachable.
    guard = ScopeGuard(targets=["example.com"])
    assert guard.off_scope_tokens(["https://evil.org/x"]) == ["evil.org"]


def test_guard_labels_excluded_path_with_its_path():
    guard = ScopeGuard(targets=["example.com"], exclude=["/admin"])
    assert guard.off_scope_tokens(["https://app.example.com/admin/billing"]) == [
        "app.example.com/admin/billing"
    ]


def test_guard_from_engagement_reads_exclude():
    guard = ScopeGuard.from_engagement(_engagement(["example.com"], ["legacy.example.com"]))
    assert not guard.allows("legacy.example.com")


def test_guard_from_none_engagement_is_permissive():
    assert ScopeGuard.from_engagement(None).allows("whatever.example.org")


# --------------------------------------------------------------------------- tool layer
async def test_exec_refuses_excluded_host(fake_client):
    eng = _engagement(["https://example.com/"], ["legacy.example.com"])
    tools = {t.name: t for t in burpwn_tools(fake_client, eng)}
    res = await tools["burpwn_exec"].ainvoke({"argv": ["curl", "https://legacy.example.com/x"]})
    assert res["refused"] is True
    assert res["off_scope_hosts"] == ["legacy.example.com"]
    assert fake_client.execs == []  # nothing ran


async def test_exec_refuses_excluded_path_on_an_allowed_host(fake_client):
    eng = _engagement(["https://app.example.com/"], ["/admin/billing"])
    tools = {t.name: t for t in burpwn_tools(fake_client, eng)}
    res = await tools["burpwn_exec"].ainvoke(
        {"argv": ["curl", "https://app.example.com/admin/billing/export"]}
    )
    assert res["refused"] is True
    assert fake_client.execs == []


async def test_exec_allows_a_sibling_path_on_the_same_host(fake_client):
    eng = _engagement(["https://app.example.com/"], ["/admin/billing"])
    tools = {t.name: t for t in burpwn_tools(fake_client, eng)}
    await tools["burpwn_exec"].ainvoke({"argv": ["curl", "https://app.example.com/public"]})
    assert len(fake_client.execs) == 1


async def test_refusal_message_names_the_exclusions(fake_client):
    eng = _engagement(["https://example.com/"], ["legacy.example.com"])
    tools = {t.name: t for t in burpwn_tools(fake_client, eng)}
    res = await tools["burpwn_exec"].ainvoke({"argv": ["curl", "https://legacy.example.com/"]})
    assert "EXCLUDING" in res["message"]
    assert "legacy.example.com" in res["message"]
