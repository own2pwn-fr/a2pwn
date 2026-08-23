"""External intelligence: the one deliberate hole in the burpwn-only-egress invariant, and the
static analysis that makes it worth having.

`a2pwn.research` is the single module that reaches the network without the sandbox, so almost
every test here is about the *bounds* of that exception rather than about lookups working: a fixed
allow-list that no engagement file can widen, a hard refusal for hosts that are the engagement's
own targets (a redirected or hallucinated URL turning an intel lookup into uncaptured target
traffic is the exact failure this module could introduce), and a degradation contract — an OSV
outage returns a dict, never an exception that would abort a dispatch mid-exploit.

`a2pwn.jsaudit` is the reason a bundle can be audited at all: the bytes stay in the artifact store
and the model gets a digest. Its tests pin the two properties that make the digest safe to ship
around — every credential-shaped hit is REDACTED before it lands in a log, a report or a
screen-shared TUI, and nothing it emits claims to be confirmed.

**No test in this file makes a real network call**: `httpx.AsyncClient` is replaced wholesale, and
the refusal tests additionally assert that no request object was ever constructed.
"""

from __future__ import annotations

import json

import pytest

from a2pwn import jsaudit, research
from a2pwn.artifacts import ArtifactStore
from a2pwn.research import ALLOWED_HOSTS, ResearchClient, _summarise_osv, normalise_ecosystem
from a2pwn.tools.research_tools import research_tools, run_js_analyze

_TARGET_HOST = "app.example.com"


# --------------------------------------------------------------------------- fake transport
class _FakeResponse:
    def __init__(self, text: str, status: int) -> None:
        self.text = text
        self.status_code = status


def _fake_http(monkeypatch, *, body: str = "{}", status: int = 200, boom: Exception | None = None) -> list[dict]:
    """Replace ``httpx.AsyncClient`` and hand back the list every request is recorded into.

    ``research`` imports httpx inside the request function, so patching the attribute on the module
    object is what the code under test will actually resolve.
    """
    import httpx

    calls: list[dict] = []

    class _Client:
        def __init__(self, **kw):
            self._kw = kw

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def request(self, method, url, json=None, headers=None):  # noqa: A002 - httpx's own name
            calls.append({"method": method, "url": url, "json": json, "headers": headers, "client": self._kw})
            if boom is not None:
                raise boom
            return _FakeResponse(body, status)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    return calls


def _client(**kw) -> ResearchClient:
    return ResearchClient(in_scope_hosts=[_TARGET_HOST], **kw)


# --------------------------------------------------------------------------- refusals
async def test_an_engagement_target_is_refused_even_though_lookups_are_the_point(monkeypatch):
    """The tool exists to fetch things, and this is the one host it must not fetch.

    A model that has just read `https://app.example.com/.well-known/security.txt` off a bundle will
    reasonably try to `research_fetch` it. Serving that would put target traffic on a socket burpwn
    never saw: uncaptured, unproven, invisible to the oracle kernel, and outside the scope guard
    and the throttle. The refusal has to be in the client, not in the prompt.
    """
    calls = _fake_http(monkeypatch)

    out = await _client().fetch(f"https://{_TARGET_HOST}/.well-known/security.txt")

    assert out["refused"] is True
    assert _TARGET_HOST in out["error"]
    assert "burpwn" in out["error"]  # the refusal tells the model where to go instead
    assert calls == []  # nothing was even attempted


async def test_a_target_that_is_also_allow_listed_is_still_refused(monkeypatch):
    # Scope membership wins over the allow-list, not the other way round: an engagement whose
    # target happens to be one of these hosts must not get an off-sandbox back door to it.
    calls = _fake_http(monkeypatch)
    client = ResearchClient(in_scope_hosts=["api.github.com"])

    out = await client.fetch("https://api.github.com/advisories")

    assert out["refused"] is True
    assert calls == []


async def test_a_host_off_the_allow_list_is_refused_and_says_what_is_allowed(monkeypatch):
    # The generic-fetch failure mode: the exception this module opens is for public vulnerability
    # databases, so anything else has to be a refusal rather than a request.
    calls = _fake_http(monkeypatch)

    out = await _client().fetch("https://attacker.example.net/collect?data=1")

    assert out["refused"] is True
    assert "not a permitted intelligence source" in out["error"]
    assert "api.osv.dev" in out["error"]  # the model is told what it CAN use
    assert calls == []


async def test_a_url_with_no_host_is_refused(monkeypatch):
    # `urlsplit("not a url").hostname` is None; a blank host must fail closed, not fall through.
    calls = _fake_http(monkeypatch)

    out = await _client().fetch("not-a-url")

    assert out["refused"] is True
    assert calls == []


async def test_no_research_disables_the_channel_entirely(monkeypatch):
    """`--no-research` is an operator decision about data leaving the client's estate.

    Package names and version strings discovered on an engagement are themselves intelligence, and
    the operator is shown that before the authorization gate. When they decline, no allow-listed
    host is a permitted exception either.
    """
    calls = _fake_http(monkeypatch)
    client = _client(enabled=False)

    fetched = await client.fetch("https://api.osv.dev/v1/query")
    queried = await client.osv_query("npm", "lodash", "4.17.15")

    for out in (fetched, queried):
        assert out["refused"] is True
        assert "--no-research" in out["error"]
    assert calls == []


async def test_the_intel_channel_does_not_follow_redirects(monkeypatch):
    # A 302 off the allow-list would defeat the host check entirely: the request that leaves the
    # process must be the one that was checked.
    calls = _fake_http(monkeypatch, body='{"vulns": []}')

    await _client().fetch("https://api.osv.dev/v1/vulns/GHSA-1234")

    assert calls[0]["client"]["follow_redirects"] is False


# --------------------------------------------------------------------------- the allow-list
def test_the_allow_list_cannot_be_widened_at_runtime():
    """Immutability is the control, not a style choice.

    A mutable allow-list is one `runconfig` key or one helpful `.add()` away from being
    engagement-supplied, and an engagement-supplied intel host is just an off-sandbox egress with
    extra steps. `frozenset` makes widening it a code change that has to be reviewed.
    """
    assert isinstance(ALLOWED_HOSTS, frozenset)
    with pytest.raises(AttributeError):
        ALLOWED_HOSTS.add("attacker.example.net")  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        ALLOWED_HOSTS.update({"attacker.example.net"})  # type: ignore[attr-defined]

    assert research.host_allowed("attacker.example.net") is False
    assert research.host_allowed("api.osv.dev") is True
    assert research.host_allowed("  API.OSV.DEV ") is True  # models paste hosts with odd casing
    assert research.host_allowed("") is False


def test_the_allow_list_holds_only_public_vulnerability_sources():
    # A regression guard on the *contents*: this set is the whole trust argument for the module.
    assert "api.osv.dev" in ALLOWED_HOSTS
    assert ALLOWED_HOSTS <= {
        "api.osv.dev",
        "osv.dev",
        "api.deps.dev",
        "deps.dev",
        "api.github.com",
        "services.nvd.nist.gov",
        "cve.circl.lu",
        "endoflife.date",
    }


# --------------------------------------------------------------------------- ecosystem names
def test_ecosystem_names_are_normalised_to_what_osv_actually_indexes():
    """OSV ecosystem names are case-sensitive and are not the words a model reaches for.

    A model that read `lodash@4.17.15` out of a bundle says "node" or "js", and OSV answers an
    unknown ecosystem with an empty result set — which reads exactly like "no known
    vulnerabilities". A silent empty answer on a vulnerable dependency is the worst outcome this
    tool can produce, so the mapping is done before the query, not hoped for.
    """
    assert normalise_ecosystem("node") == "npm"
    assert normalise_ecosystem("js") == "npm"
    assert normalise_ecosystem("JavaScript") == "npm"
    assert normalise_ecosystem("python") == "PyPI"
    assert normalise_ecosystem("pip") == "PyPI"
    assert normalise_ecosystem("golang") == "Go"
    assert normalise_ecosystem("cargo") == "crates.io"
    assert normalise_ecosystem("rust") == "crates.io"
    assert normalise_ecosystem(" Composer ") == "Packagist"


def test_an_unknown_ecosystem_is_passed_through_rather_than_guessed():
    # OSV indexes more ecosystems than the table names; rewriting an unrecognised one to `npm`
    # would turn "I don't know this ecosystem" into a confident wrong query.
    assert normalise_ecosystem("Hex") == "Hex"
    assert normalise_ecosystem("") == "npm"  # …but an absent one defaults to the common case


# --------------------------------------------------------------------------- OSV summarisation
def _osv_payload() -> dict:
    return {
        "vulns": [
            {
                "id": "GHSA-jf85-cpcp-j695",
                "aliases": ["CVE-2019-10744", "SNYK-JS-LODASH-450202"],
                "summary": "Prototype pollution in lodash " + "x" * 500,
                "details": "y" * 20_000,
                "published": "2019-07-19T16:13:07Z",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                "affected": [{"ranges": [{"events": [{"introduced": "0"}]}]} for _ in range(50)],
            }
        ]
    }


def test_an_osv_record_is_compressed_to_the_fields_that_drive_a_decision():
    """A raw OSV record is tens of kilobytes of affected-range tables per vulnerability.

    Handing that to the model evicts the engagement context — the transcript is the only working
    memory a stateless sub-agent has — to say what id/severity/summary already say. Everything
    dropped here is recoverable with a `research_fetch` if the agent actually needs it.
    """
    (vuln,) = _summarise_osv(_osv_payload())

    assert set(vuln) == {"id", "aliases", "summary", "severity", "published"}
    assert vuln["id"] == "GHSA-jf85-cpcp-j695"
    assert vuln["severity"].startswith("CVSS:3.1/")
    assert vuln["published"] == "2019-07-19T16:13:07Z"
    assert len(vuln["summary"]) == 300  # capped, not the 500-char blurb


def test_alias_lists_are_capped():
    # Some records carry dozens of vendor aliases; the CVE and the GHSA are what an operator greps.
    payload = {"vulns": [{"id": "GHSA-x", "aliases": [f"CVE-2020-{i}" for i in range(40)]}]}

    (vuln,) = _summarise_osv(payload)

    assert len(vuln["aliases"]) == 6


def test_summarising_tolerates_junk_without_raising():
    """The digest is built from a third party's JSON, so shape-defensiveness is the contract.

    An OSV schema change or an error body must degrade to fewer entries, never to an exception
    inside a tool call the agent then has to interpret.
    """
    payload = {
        "vulns": [
            "not a dict",
            None,
            {"id": "GHSA-ok"},  # every optional field missing
            {"id": "GHSA-junk", "aliases": ["CVE-1", 42, None], "severity": [None, {"type": "x"}, "str"]},
        ]
    }

    out = _summarise_osv(payload)

    assert [v["id"] for v in out] == ["GHSA-ok", "GHSA-junk"]
    assert out[0] == {"id": "GHSA-ok", "aliases": [], "summary": "", "severity": "", "published": None}
    assert out[1]["aliases"] == ["CVE-1"]  # non-string aliases dropped, not stringified
    assert out[1]["severity"] == ""  # no scored entry


def test_a_response_with_no_vulns_key_is_an_empty_list_not_an_error():
    # OSV answers "nothing known" with `{}`; that is a result, and must not read as a failure.
    assert _summarise_osv({}) == []
    assert _summarise_osv({"vulns": None}) == []
    assert _summarise_osv("not json at all") == []
    assert _summarise_osv(None) == []


# --------------------------------------------------------------------------- degradation
async def test_a_clean_osv_query_returns_the_summary_keyed_to_the_package(monkeypatch):
    calls = _fake_http(monkeypatch, body=json.dumps(_osv_payload()))

    out = await _client().osv_query("node", "lodash", "4.17.15")

    assert calls[0]["method"] == "POST"
    assert calls[0]["url"] == "https://api.osv.dev/v1/query"
    assert calls[0]["json"] == {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.15"}
    assert out["package"] == "lodash"
    assert out["version"] == "4.17.15"
    assert [v["id"] for v in out["vulns"]] == ["GHSA-jf85-cpcp-j695"]


async def test_a_versionless_query_omits_the_version_field(monkeypatch):
    # OSV rejects `{"version": ""}`; asking about a package with an unknown version is legitimate.
    calls = _fake_http(monkeypatch, body='{"vulns": []}')

    await _client().osv_query("npm", "lodash")

    assert "version" not in calls[0]["json"]


async def test_an_intel_outage_degrades_to_an_error_dict_and_never_raises(monkeypatch):
    """OSV being down must cost the engagement a lookup, not the dispatch.

    This is called mid-exploit from a tool wrapper; an exception here propagates into the sub-agent
    as a dispatch failure and throws away a transcript that may already hold a proven finding.
    """
    _fake_http(monkeypatch, boom=OSError("connection reset by peer"))

    out = await _client().osv_query("npm", "lodash", "4.17.15")

    assert "vulns" not in out
    assert "research request failed" in out["error"]
    assert "connection reset" in out["error"]
    assert out.get("refused") is None  # a refusal and an outage are different things to the model


async def test_a_non_json_body_degrades_to_text_with_its_status(monkeypatch):
    # A WAF interstitial, an HTML 502 page, a rate-limit notice: the status plus the body is what
    # lets the model decide whether to retry or move on, and neither is a parse error.
    _fake_http(monkeypatch, body="<html>502 Bad Gateway</html>", status=502)

    out = await _client().fetch("https://api.deps.dev/v3/systems/npm/packages/lodash")

    assert out == {"status": 502, "text": "<html>502 Bad Gateway</html>"}


async def test_an_osv_query_that_did_not_return_json_is_passed_through_unwrapped(monkeypatch):
    # `osv_query` only summarises when there IS json; otherwise the raw degradation must survive
    # rather than being reported as a package with zero vulnerabilities.
    _fake_http(monkeypatch, body="Service Unavailable", status=503)

    out = await _client().osv_query("npm", "lodash", "4.17.15")

    assert out == {"status": 503, "text": "Service Unavailable"}
    assert "vulns" not in out


# --------------------------------------------------------------------------- jsaudit: endpoints
def test_a_bundle_names_the_endpoints_no_crawl_will_ever_reach():
    """This is the reason to read a bundle at all.

    A front-end names every route it calls, including the admin and internal ones nothing links to
    — the endpoints a spider structurally cannot discover.
    """
    src = """
      const BASE = "https://api.internal.example.com/v2";
      fetch("/api/admin/users"); fetch("/internal/debug/config");
      import x from "/_next/static/chunk.js";
      el.src = "/img/logo.png";
    """

    out = jsaudit.extract_endpoints(src)

    assert out["urls"] == ["https://api.internal.example.com/v2"]
    assert "/api/admin/users" in out["paths"]
    assert "/internal/debug/config" in out["paths"]
    assert "/_next/static/chunk.js" in out["paths"]


def test_the_loose_path_pattern_only_engages_when_the_targeted_one_found_little():
    """On a real bundle the loose pattern matches thousands of asset paths.

    Sorting an admin route out of 4 000 sprite and locale paths is a worse job than the targeted
    pattern already did, so the fallback is a rescue for small/obfuscated bundles only.
    """
    rich = ";".join(f'fetch("/api/v1/resource{i}")' for i in range(12)) + ';img.src="/static/logo.png";'
    sparse = 'fetch("/api/me"); img.src="/static/logo.png";'

    assert "/static/logo.png" not in jsaudit.extract_endpoints(rich)["paths"]
    assert "/static/logo.png" in jsaudit.extract_endpoints(sparse)["paths"]


def test_sourcemap_urls_are_extracted():
    # The single highest-value artefact in a bundle: a .map reconstructs the original sources,
    # comments and internal paths that minification was supposed to remove.
    src = "!function(){}();\n//# sourceMappingURL=main.4f2a.js.map\n//@ sourceMappingURL=vendor.js.map"

    assert jsaudit.extract_sourcemaps(src) == ["main.4f2a.js.map", "vendor.js.map"]


# --------------------------------------------------------------------------- jsaudit: dependencies
def test_library_versions_are_read_from_both_a_banner_and_an_assignment():
    """Both forms exist because minifiers keep the licence banner and inline the version constant.

    These pairs are what makes `cve_lookup` possible at all: a minified bundle has no manifest, so
    without them a front-end's dependency tree is unauditable.
    """
    banner = jsaudit.extract_dependencies("/*! jQuery v3.4.1 | (c) JS Foundation */")
    assign = jsaudit.extract_dependencies('var lodash="4.17.15";')

    assert banner == [{"name": "jquery", "version": "3.4.1", "source": "banner"}]
    assert assign == [{"name": "lodash", "version": "4.17.15", "source": "assignment"}]


def test_generic_identifier_names_are_not_reported_as_libraries():
    """`version = "1.2.3"` names no library, and a bogus pair poisons the OSV query.

    A lookup for a package literally called `version` returns nothing, and "no known
    vulnerabilities" against a name that was never a package is indistinguishable, to the agent,
    from a clean dependency.
    """
    src = 'var version="9.9.9"; var name="1.0.0"; var type="2.0.0"; var moment="2.29.1";'

    names = {d["name"] for d in jsaudit.extract_dependencies(src)}

    assert names == {"moment"}


# --------------------------------------------------------------------------- jsaudit: secrets
_TOKENS = {
    "aws-access-key": "AKIAIOSFODNN7EXAMPLE",
    # Deliberately shaped to match our extractor but NOT a real-token detector: GitHub push
    # protection rejects a plausible xoxb- literal even inside a test corpus, and a fixture is not
    # worth a secret-scanning allow-list entry.
    "slack-token": "xoxb-EXAMPLE-NOT-A-REAL-TOKEN-000000",
    "github-token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "stripe-key": "sk_live_abcdefghijklmnop1234",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghijkl",
}
# Google keys are `AIza` + exactly 35 characters; the pattern is anchored on that length.
_GOOGLE_KEY = "AIzaSyD1234567890abcdefghijklmnopqrstuv"


def test_every_vendor_token_shape_is_recognised():
    """Prefixed vendor tokens are matched exactly because they are unambiguous.

    A bundle is where secrets that were never meant to be public actually end up, and each of these
    prefixes identifies the issuer — which is what tells an operator whether the leak is a billing
    key, a repo token or a cloud credential.
    """
    for kind, value in _TOKENS.items():
        (hit,) = jsaudit.extract_secrets(f'var v = "{value}";')
        assert hit["kind"] == kind, value

    (google,) = jsaudit.extract_secrets(f'var v = "{_GOOGLE_KEY}";')
    assert google["kind"] == "google-api-key"

    (pk,) = jsaudit.extract_secrets("const K = `-----BEGIN RSA PRIVATE KEY-----\\nMIIE...`;")
    assert pk["kind"] == "private-key-block"

    (fb,) = jsaudit.extract_secrets(f'firebaseConfig = {{ apiKey: "{_GOOGLE_KEY}" }}')
    assert fb["kind"] in {"google-api-key", "firebase-config"}


def test_a_secret_is_never_reported_in_full():
    """The digest is what gets logged, pasted into a report and shown in a shared TUI.

    The full string is still in the artifact store and in the captured flow, where it belongs; the
    redaction keeps enough to recognise the value and re-find it without a2pwn's own output
    becoming a second copy of the leak.
    """
    src = "\n".join(f'var v{i} = "{value}";' for i, value in enumerate(_TOKENS.values()))
    src += f'\nvar myApiKey = "{_GOOGLE_KEY}";'

    out = jsaudit.extract_secrets(src)
    serialised = json.dumps(out)

    assert out, "the fixture must actually produce hits, or this proves nothing"
    for value in (*_TOKENS.values(), _GOOGLE_KEY):
        assert value not in serialised
    for hit in out:
        assert "…" in hit["value"]  # every value went through the redactor


def test_the_full_digest_also_carries_only_redacted_secrets():
    # `analyse` is the shape the tool actually returns; the redaction has to hold there too.
    digest = jsaudit.analyse(f'var t = "{_TOKENS["github-token"]}";')

    assert _TOKENS["github-token"] not in json.dumps(digest)
    assert "confirmed" not in json.dumps(digest)  # a hit is a LEAD; nothing here claims proof


def test_a_high_entropy_assignment_is_a_lead_and_a_low_entropy_one_is_not():
    """The entropy gate is what stops a bundle's own identifiers drowning the real hits.

    Every minified bundle assigns hundreds of credential-*named* things — feature flags, cache
    keys, i18n ids. Reporting them all trains the operator (and the model) to ignore the section
    that occasionally holds a live key.
    """
    high = 'var x_secret = "Zk3Qp7Lm2Xr9Tv4Bn8Cd1Fg6Hj0Kl5W";'
    low = 'var x_secret = "aaaaaaaaaaaaaaaaaaaa";'

    (hit,) = jsaudit.extract_secrets(high)
    assert hit["kind"] == "high-entropy-assignment"
    assert hit["name"] == "x_secret"
    assert jsaudit.shannon_entropy("Zk3Qp7Lm2Xr9Tv4Bn8Cd1Fg6Hj0Kl5W") >= jsaudit._MIN_ENTROPY

    assert jsaudit.extract_secrets(low) == []


def test_placeholder_and_env_indirection_values_are_not_reported_as_secrets():
    """`apiKey: process.env.API_KEY` is the CORRECT pattern; flagging it is a false positive.

    Reporting build-time indirection and `xxxxxxxx` placeholders as credential leads is how a
    supply-chain section becomes noise nobody reads — and each one costs a dispatch that tries to
    replay a string that was never a credential.
    """
    for src in (
        "var x_secret = process.env.API_KEY;",
        'var x_secret = "process.env.API_KEY";',
        'var x_secret = "xxxxxxxxxxxxxxxxxxxx";',
        'var x_secret = "<YOUR_API_KEY_HERE>";',
        "var x_secret = undefined;",
    ):
        assert jsaudit.extract_secrets(src) == [], src


def test_the_same_secret_is_reported_once_however_many_times_it_appears():
    # A bundle inlines the same key into every chunk that uses it; one lead is one lead.
    src = "; ".join(f'var v{i} = "{_TOKENS["aws-access-key"]}"' for i in range(5))

    assert len(jsaudit.extract_secrets(src)) == 1


# --------------------------------------------------------------------------- jsaudit: sinks / jwt
def test_dom_sinks_are_counted_not_listed():
    """Counts, not occurrences: the number is a triage signal, the code is in the artifact store.

    A bundle with 200 `innerHTML` writes is a different manual-review proposition from one with
    two, and that ranking is the whole value — dumping every call site would put the bundle back
    into the transcript by another route.
    """
    src = "a.innerHTML=x; b.innerHTML=y; c.innerHTML=z; eval(q); document.cookie; location.href"

    out = {s["sink"]: s["count"] for s in jsaudit.extract_sinks(src)}

    assert out["innerHTML"] == 3
    assert out["eval"] == 1
    assert out["document.cookie"] == 1
    assert out["location.href"] == 1
    assert jsaudit.extract_sinks("nothing interesting here") == []


def test_jwt_claims_are_decoded_without_validating_anything():
    """An unsigned peek: alg/kid/iss/exp and any role claim decide how the token is attacked.

    Validation is deliberately not attempted — the point is to read a token the engagement does not
    hold the key for, and a "verified" flag here would be a claim the oracle kernel has not made.
    """
    import base64

    payload = base64.urlsafe_b64encode(b'{"sub":"1","role":"admin"}').decode().rstrip("=")
    token = f"eyJhbGciOiJIUzI1NiJ9.{payload}.not-a-real-signature"

    assert jsaudit.decode_jwt_claims(token) == {"sub": "1", "role": "admin"}


def test_a_malformed_token_is_a_non_result_not_an_error():
    # Called on whatever the model thought looked like a JWT; a wrong guess must cost nothing.
    for garbage in ("", "not-a-token", "a.b.c", "eyJhbGciOiJIUzI1NiJ9", "x." + "!" * 20 + ".y"):
        assert jsaudit.decode_jwt_claims(garbage) == {}


# --------------------------------------------------------------------------- the js_analyze tool
_JS = """
  /*! axios v0.21.1 */
  fetch("/api/admin/impersonate");
  const token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
  el.innerHTML = untrusted;
  //# sourceMappingURL=app.js.map
"""


async def test_a_stored_bundle_yields_a_digest_instead_of_its_bytes():
    """The inversion this tool exists for: the blob stays in the store, the model gets structure.

    Handing a three-megabyte minified bundle to a model fails twice — it evicts the engagement
    context, and a model skimming minified code is a worse grep than a regex.
    """
    store = ArtifactStore()
    artifact = store.put(_JS, kind="http-body", origin="https://app.example.com/app.js")

    out = await run_js_analyze(store, artifact.id)

    assert out["artifact"] == artifact.id
    assert out["size"] == len(_JS)
    assert "/api/admin/impersonate" in out["endpoints"]["paths"]
    assert out["sourcemaps"] == ["app.js.map"]
    assert {"name": "axios", "version": "0.21.1", "source": "banner"} in out["dependencies"]
    assert [s["kind"] for s in out["secrets"]] == ["github-token"]
    assert {"sink": "innerHTML", "count": 1} in out["dom_sinks"]
    # …and the digest is a digest: no bundle text, and the leaked token still redacted.
    assert "el.innerHTML = untrusted" not in json.dumps(out)
    assert _TOKENS["github-token"] not in json.dumps(out)


async def test_an_unknown_artifact_id_names_the_reason():
    # The model invents ids; an empty digest would read as "that bundle is clean".
    store = ArtifactStore()

    out = await run_js_analyze(store, "art-9999")

    assert out == {"error": "no such artifact art-9999"}


async def test_a_dropped_artifact_is_not_silently_re_read():
    """`artifact_drop` is the agent's ability to forget, and forgetting has to stick.

    The tombstone carries the *conclusion* that the blob was not relevant. Answering a later
    `js_analyze` with an empty digest would hide that a decision was already made — and a retry
    round replaying the same reasoning would re-fetch and re-read the bundle it just discarded.
    """
    store = ArtifactStore()
    artifact = store.put(_JS, kind="http-body", origin="https://app.example.com/app.js")
    store.drop(artifact.id, "vendor bundle, no app code")

    out = await run_js_analyze(store, artifact.id)

    assert "error" in out
    assert artifact.id in out["error"]
    assert "vendor bundle, no app code" in out["error"]
    assert "endpoints" not in out


async def test_an_empty_artifact_is_an_error_not_an_empty_digest():
    store = ArtifactStore()
    artifact = store.put("", kind="http-body", origin="https://app.example.com/empty.js")

    out = await run_js_analyze(store, artifact.id)

    assert out == {"error": f"{artifact.id} has no readable content"}


# --------------------------------------------------------------------------- the tool surface
async def test_the_research_tools_are_the_four_documented_names_and_route_to_the_client(monkeypatch):
    """Both executor paths get these four and nothing else.

    `research_fetch` in particular has to carry the refusal all the way out to the model rather
    than raising, since a refused lookup is a normal event the agent has to reason about.
    """
    store = ArtifactStore()
    tools = research_tools(store, _client())

    assert [t.name for t in tools] == ["js_analyze", "cve_lookup", "research_fetch", "jwt_decode"]
    by_name = {t.name: t for t in tools}

    calls = _fake_http(monkeypatch, body=json.dumps(_osv_payload()))
    cve = await by_name["cve_lookup"].ainvoke({"package": "lodash", "ecosystem": "node", "version": "4.17.15"})
    assert calls[0]["json"]["package"]["ecosystem"] == "npm"
    assert [v["id"] for v in cve["vulns"]] == ["GHSA-jf85-cpcp-j695"]

    refused = await by_name["research_fetch"].ainvoke({"url": f"https://{_TARGET_HOST}/app.js"})
    assert refused["refused"] is True

    artifact = store.put(_JS, kind="http-body", origin="https://app.example.com/app.js")
    assert (await by_name["js_analyze"].ainvoke({"artifact_id": artifact.id}))["artifact"] == artifact.id

    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
    assert await by_name["jwt_decode"].ainvoke({"token": token}) == {"claims": {"sub": "1"}}


def test_every_research_tool_description_tells_the_model_the_egress_rule():
    # The tool descriptions are the only place the model learns that this channel is not the
    # target's; a description that reads like a generic fetch invites exactly the misuse the
    # client then has to refuse.
    from a2pwn.tools import research_tools as rt

    assert "burpwn" in rt.CVE_LOOKUP_DESC
    assert "burpwn" in rt.RESEARCH_FETCH_DESC
    assert "LEAD" in rt.JS_ANALYZE_DESC and "LEAD" in rt.CVE_LOOKUP_DESC
    for host in ALLOWED_HOSTS:
        assert host in rt.RESEARCH_FETCH_DESC


# --------------------------------------------------------------------------- #
# regressions: the secret matcher used to miss the commonest names             #
# --------------------------------------------------------------------------- #
def test_a_bare_credential_name_is_matched_without_a_prefix():
    """`apiKey = "..."` must be found, not just `myApiKey = "..."`.

    The name group required a leading `[A-Za-z_]` before the keyword, so the keyword could never
    start at offset 0 of the identifier — and `apiKey`, `api_key`, `secret`, `token` and
    `password`, by far the commonest spellings in a real bundle, matched nothing at all. The
    extractor looked like it worked because decorated names still hit.
    """
    value = "Zk3Qp7Lm2Xr9Tv4Bn8Cd1Fg6Hj0Kl5W"  # entropy well above the gate
    for name in ("apiKey", "api_key", "API_KEY", "secret", "token", "password", "myApiKey"):
        hits = jsaudit.extract_secrets(f'var {name} = "{value}";')
        assert hits, f"{name} was not matched"
        assert hits[0]["kind"] == "high-entropy-assignment"


def test_build_time_indirections_are_denied_but_dotted_secrets_are_not():
    """`apiKey: "process.env.API_KEY"` is a reference to a secret, not a secret.

    The deny list only became load-bearing once `.` was admitted into the value class (real secrets
    contain dots). A generic "dotted identifier chain" rule was tried and rejected here: base64
    segments are valid identifiers, so it silently ate genuine dotted secrets to catch a class the
    explicit code roots already cover.
    """
    for denied in ("process.env.API_KEY", "import.meta.env.VITE_KEY", "window.__CONFIG.token"):
        assert jsaudit.extract_secrets(f'var apiKey = "{denied}";') == []
    for kept in ("aK9x.Lm2Qp7Tv4Bn8Cd1Fg6Hj0Kl5Wz3", "Zk3Qp7Lm2Xr9Tv4Bn8Cd1Fg6Hj0Kl5W"):
        assert jsaudit.extract_secrets(f'var apiKey = "{kept}";'), kept
