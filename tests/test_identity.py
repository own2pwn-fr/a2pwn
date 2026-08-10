"""Named identities — the thing that makes the two_identity oracle reachable at all.

Before identities existed there was no way to hand a2pwn a credential, so every access-control
class (IDOR/BOLA, cross-tenant CRUD, privilege escalation, CSRF) was unreachable unless the
executor happened to self-register accounts. These tests pin the credential lifecycle: resolution,
caching, login extraction, expiry-driven re-auth, and the header-merge precedence rules.
"""

from __future__ import annotations

import asyncio

import pytest

from a2pwn.config import EngagementSpec, IdentitySpec, LoginRecipe
from a2pwn.identity import (
    IdentityError,
    IdentityStore,
    ResolvedIdentity,
    apply_identity_to_argv,
    merge_identity_headers,
)
from a2pwn.tools import burpwn_tools

ALICE = IdentitySpec(name="alice", headers={"Authorization": "Bearer alice-token"})
BOB = IdentitySpec(name="bob", cookies={"session": "bob-session"})
ANON = IdentitySpec(name="anon", anonymous=True)


def _engagement(identities=None) -> EngagementSpec:
    return EngagementSpec(
        name="t",
        targets=["https://app.example.com/"],
        in_scope=["app.example.com"],
        identities=list(identities or []),
        session="t",
    )


# --------------------------------------------------------------------------- static credentials
async def test_static_headers_resolve(fake_client):
    store = IdentityStore(fake_client, [ALICE])
    resolved = await store.resolve("alice")
    assert resolved.all_headers()["Authorization"] == "Bearer alice-token"


async def test_cookies_become_a_cookie_header(fake_client):
    store = IdentityStore(fake_client, [BOB])
    resolved = await store.resolve("bob")
    assert resolved.all_headers()["Cookie"] == "session=bob-session"


async def test_anonymous_identity_carries_no_credentials(fake_client):
    # The negative control must stay genuinely credential-free: attaching a stray header would
    # destroy the very thing it proves (that an unauthenticated caller is DENIED).
    store = IdentityStore(fake_client, [IdentitySpec(name="anon", anonymous=True, headers={"X": "y"})])
    resolved = await store.resolve("anon")
    assert resolved.all_headers() == {}
    assert resolved.anonymous is True


async def test_unknown_identity_raises_with_the_known_names(fake_client):
    store = IdentityStore(fake_client, [ALICE])
    with pytest.raises(IdentityError, match="alice"):
        await store.resolve("mallory")


async def test_identity_with_no_credentials_at_all_is_an_error(fake_client):
    store = IdentityStore(fake_client, [IdentitySpec(name="empty")])
    with pytest.raises(IdentityError, match="no credentials"):
        await store.resolve("empty")


# --------------------------------------------------------------------------- forbidden headers
async def test_host_header_cannot_be_set_by_an_identity(fake_client):
    # An identity that could set Host would silently re-target a request at another host, which is
    # exactly what the scope guard inspects — so it must never be expressible here.
    spec = IdentitySpec(name="x", headers={"Host": "evil.example.org", "Authorization": "Bearer t"})
    resolved = await IdentityStore(fake_client, [spec]).resolve("x")
    assert "Host" not in resolved.all_headers()
    assert "Authorization" in resolved.all_headers()


# --------------------------------------------------------------------------- replay login
async def test_replay_login_extracts_a_token_from_the_captured_flow(fake_client):
    fake_client.exec_return = {"exit_code": 0, "captured_request_ids": [7], "exec_id": "e1"}
    fake_client.all_flows = [
        {"id": 7, "response": {"status": 200, "headers": "", "body": '{"token":"abc123"}'}}
    ]
    spec = IdentitySpec(
        name="api",
        login=LoginRecipe(
            url="https://app.example.com/login",
            body='{"u":"a","p":"b"}',
            extract={"token": r'"token":"([^"]+)"'},
            inject={"Authorization": "Bearer {token}"},
        ),
    )
    resolved = await IdentityStore(fake_client, [spec]).resolve("api")
    assert resolved.all_headers()["Authorization"] == "Bearer abc123"


async def test_replay_login_harvests_set_cookie(fake_client):
    fake_client.exec_return = {"exit_code": 0, "captured_request_ids": [8], "exec_id": "e1"}
    fake_client.all_flows = [
        {
            "id": 8,
            "response": {
                "status": 200,
                "headers": "Set-Cookie: sid=deadbeef; Path=/; HttpOnly\r\nContent-Type: text/html",
                "body": "ok",
            },
        }
    ]
    spec = IdentitySpec(name="web", login=LoginRecipe(url="https://app.example.com/login"))
    resolved = await IdentityStore(fake_client, [spec]).resolve("web")
    assert resolved.cookies == {"sid": "deadbeef"}


async def test_replay_login_failed_extraction_is_a_loud_error(fake_client):
    # Silently resolving to no credentials would turn every later access-control probe into a
    # false "access control held" negative that no oracle could distinguish from real enforcement.
    fake_client.exec_return = {"exit_code": 0, "captured_request_ids": [9], "exec_id": "e1"}
    fake_client.all_flows = [{"id": 9, "response": {"status": 401, "headers": "", "body": "denied"}}]
    spec = IdentitySpec(
        name="api",
        login=LoginRecipe(
            url="https://app.example.com/login",
            extract={"token": r'"token":"([^"]+)"'},
            inject={"Authorization": "Bearer {token}"},
        ),
    )
    with pytest.raises(IdentityError, match="did not match"):
        await IdentityStore(fake_client, [spec]).resolve("api")


async def test_inject_template_referencing_an_unextracted_placeholder_errors(fake_client):
    fake_client.exec_return = {"exit_code": 0, "captured_request_ids": [10], "exec_id": "e1"}
    fake_client.all_flows = [{"id": 10, "response": {"status": 200, "headers": "", "body": "{}"}}]
    spec = IdentitySpec(
        name="api",
        login=LoginRecipe(url="https://app.example.com/login", inject={"Authorization": "Bearer {nope}"}),
    )
    with pytest.raises(IdentityError, match="never extracted"):
        await IdentityStore(fake_client, [spec]).resolve("api")


# --------------------------------------------------------------------------- caching / re-auth
async def test_login_runs_once_and_is_cached(fake_client):
    fake_client.exec_return = {"exit_code": 0, "captured_request_ids": [11], "exec_id": "e1"}
    fake_client.all_flows = [
        {"id": 11, "response": {"status": 200, "headers": "Set-Cookie: s=1", "body": "ok"}}
    ]
    store = IdentityStore(
        fake_client, [IdentitySpec(name="w", login=LoginRecipe(url="https://app.example.com/l"))]
    )
    await store.resolve("w")
    await store.resolve("w")
    assert len(fake_client.execs) == 1


async def test_concurrent_resolution_shares_one_login(fake_client):
    # A parallel dispatch fan-out must not fire N simultaneous logins at the target.
    fake_client.exec_return = {"exit_code": 0, "captured_request_ids": [12], "exec_id": "e1"}
    fake_client.all_flows = [
        {"id": 12, "response": {"status": 200, "headers": "Set-Cookie: s=1", "body": "ok"}}
    ]
    store = IdentityStore(
        fake_client, [IdentitySpec(name="w", login=LoginRecipe(url="https://app.example.com/l"))]
    )
    await asyncio.gather(*(store.resolve("w") for _ in range(5)))
    assert len(fake_client.execs) == 1


async def test_invalidate_forces_a_fresh_login(fake_client):
    fake_client.exec_return = {"exit_code": 0, "captured_request_ids": [13], "exec_id": "e1"}
    fake_client.all_flows = [
        {"id": 13, "response": {"status": 200, "headers": "Set-Cookie: s=1", "body": "ok"}}
    ]
    store = IdentityStore(
        fake_client, [IdentitySpec(name="w", login=LoginRecipe(url="https://app.example.com/l"))]
    )
    await store.resolve("w")
    store.invalidate("w")
    await store.resolve("w")
    assert len(fake_client.execs) == 2


async def test_a_401_reply_invalidates_the_identity(fake_client):
    # Session expiry mid-engagement must self-heal, otherwise every later probe reads as
    # "access control held".
    fake_client.replay_return = {"status": 401, "response": ""}
    store = IdentityStore(fake_client, [ALICE])
    await store.resolve("alice")
    tools = {t.name: t for t in burpwn_tools(fake_client, _engagement([ALICE]), identities=store)}
    await tools["burpwn_req_replay"].ainvoke({"id": 1, "as_identity": "alice"})
    assert store.describe()[0]["resolved"] is False


# --------------------------------------------------------------------------- header/argv merge
def test_merge_keeps_an_explicit_header_over_the_identity():
    # The model deliberately overriding Authorization (e.g. testing a forged JWT as identity A)
    # must not be silently reverted to the identity's real token.
    resolved = ResolvedIdentity(name="a", headers={"Authorization": "Bearer real"})
    merged = merge_identity_headers([{"name": "Authorization", "value": "Bearer forged"}], resolved)
    assert merged == [{"name": "Authorization", "value": "Bearer forged"}]


def test_merge_appends_identity_headers_that_were_not_supplied():
    resolved = ResolvedIdentity(name="a", headers={"Authorization": "Bearer real"})
    merged = merge_identity_headers([{"name": "X-Test", "value": "1"}], resolved)
    assert {"name": "Authorization", "value": "Bearer real"} in merged


def test_apply_to_curl_argv_inserts_headers():
    resolved = ResolvedIdentity(name="a", headers={"Authorization": "Bearer t"})
    argv, warning = apply_identity_to_argv(["curl", "-s", "https://app.example.com/"], resolved)
    assert warning is None
    assert argv[1:3] == ["-H", "Authorization: Bearer t"]


def test_apply_to_non_curl_argv_warns_instead_of_silently_dropping():
    # Silently issuing an UNAUTHENTICATED request would look like "access control held" — a false
    # negative on exactly the class identities exist to test.
    resolved = ResolvedIdentity(name="a", headers={"Authorization": "Bearer t"})
    argv, warning = apply_identity_to_argv(["httpx", "-u", "https://app.example.com/"], resolved)
    assert argv == ["httpx", "-u", "https://app.example.com/"]
    assert "NOT applied" in warning


def test_apply_anonymous_identity_is_a_no_op_without_warning():
    argv, warning = apply_identity_to_argv(["httpx"], ResolvedIdentity(name="anon", anonymous=True))
    assert argv == ["httpx"]
    assert warning is None


# --------------------------------------------------------------------------- tool surface
async def test_identity_tools_appear_only_when_identities_are_declared(fake_client):
    without = {t.name for t in burpwn_tools(fake_client, _engagement())}
    assert "identity_list" not in without
    store = IdentityStore(fake_client, [ALICE, BOB, ANON])
    with_ids = {t.name for t in burpwn_tools(fake_client, _engagement([ALICE]), identities=store)}
    assert {"identity_list", "identity_request"} <= with_ids


async def test_identity_request_attaches_credentials_and_stays_in_scope(fake_client):
    store = IdentityStore(fake_client, [ALICE])
    tools = {t.name: t for t in burpwn_tools(fake_client, _engagement([ALICE]), identities=store)}
    await tools["identity_request"].ainvoke(
        {"url": "https://app.example.com/orders/1", "as_identity": "alice"}
    )
    argv = fake_client.execs[0]["argv"]
    assert "Authorization: Bearer alice-token" in argv


async def test_identity_request_refuses_an_out_of_scope_url(fake_client):
    store = IdentityStore(fake_client, [ALICE])
    tools = {t.name: t for t in burpwn_tools(fake_client, _engagement([ALICE]), identities=store)}
    res = await tools["identity_request"].ainvoke(
        {"url": "https://evil.example.org/", "as_identity": "alice"}
    )
    assert res["refused"] is True
    assert fake_client.execs == []


async def test_as_identity_without_declared_identities_is_refused(fake_client):
    tools = {t.name: t for t in burpwn_tools(fake_client, _engagement())}
    res = await tools["burpwn_exec"].ainvoke(
        {"argv": ["curl", "https://app.example.com/"], "as_identity": "ghost"}
    )
    assert res["refused"] is True
    assert fake_client.execs == []


# --------------------------------------------------------------------------- real exec shape
async def test_a_login_that_captured_no_flow_says_so(fake_client):
    # burpwn exec returns NO stdout, so a login with no captured flow has produced nothing
    # readable. This used to fall through to an empty string and surface as the misleading
    # "extraction did not match the response".
    fake_client.exec_return = {"exit_code": 0, "captured_request_ids": [], "exec_id": "e1"}
    spec = IdentitySpec(
        name="api",
        login=LoginRecipe(
            url="https://app.example.com/login",
            extract={"token": r'"token":"([^"]+)"'},
            inject={"Authorization": "Bearer {token}"},
        ),
    )
    with pytest.raises(IdentityError, match="captured no flow"):
        await IdentityStore(fake_client, [spec]).resolve("api")


def test_exec_stdout_tolerates_the_real_stdout_less_result():
    from a2pwn.identity import _exec_stdout

    assert _exec_stdout({"exit_code": 0, "captured_request_ids": [], "exec_id": "e1"}) == ""
