"""Declarative engagement files, and the CLI-wins-over-file merge rule.

Two properties matter here. First, an unknown key is an ERROR, not a warning: a typo'd ``exlude:``
silently widening the tested scope is the exact failure this file exists to prevent. Second, a flag
left at its default must NOT clobber a file setting — typer cannot distinguish an omitted flag from
one passed at its default, so without that rule every file value would be overwritten by a default
the operator never typed.
"""

from __future__ import annotations

import pytest

from a2pwn.runconfig import ConfigError, load_engagement_file, merge


def _write(tmp_path, text: str):
    path = tmp_path / "engagement.yaml"
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- parsing
def test_loads_scope_and_exclusions(tmp_path):
    path = _write(
        tmp_path,
        """
        name: acme-q3
        objective: audit the shop
        targets:
          - https://app.example.com
        in_scope: [example.com]
        exclude:
          - legacy.example.com
          - /admin/billing
        """,
    )
    cfg = load_engagement_file(path)
    assert cfg["targets"] == ["https://app.example.com"]
    assert cfg["exclude"] == ["legacy.example.com", "/admin/billing"]


def test_a_scalar_is_accepted_where_a_list_is_expected(tmp_path):
    cfg = load_engagement_file(_write(tmp_path, "targets: https://app.example.com\n"))
    assert cfg["targets"] == ["https://app.example.com"]


def test_unknown_key_is_rejected(tmp_path):
    # A typo here would silently change the tested scope.
    with pytest.raises(ConfigError, match="unknown key"):
        load_engagement_file(_write(tmp_path, "exlude: [legacy.example.com]\n"))


def test_malformed_yaml_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_engagement_file(_write(tmp_path, "targets: [unclosed\n"))


def test_non_mapping_top_level_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="mapping"):
        load_engagement_file(_write(tmp_path, "- just\n- a\n- list\n"))


def test_empty_file_is_an_empty_config(tmp_path):
    assert load_engagement_file(_write(tmp_path, "")) == {}


def test_missing_file_is_reported_cleanly(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_engagement_file(tmp_path / "nope.yaml")


def test_wrong_list_element_type_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="list of strings"):
        load_engagement_file(_write(tmp_path, "targets: [{a: 1}]\n"))


# --------------------------------------------------------------------------- identities
def test_identities_are_validated_at_load_time(tmp_path):
    path = _write(
        tmp_path,
        """
        targets: [https://app.example.com]
        identities:
          - name: alice
            headers: {Authorization: "Bearer t"}
          - name: anon
            anonymous: true
        """,
    )
    cfg = load_engagement_file(path)
    assert [i.name for i in cfg["identities"]] == ["alice", "anon"]
    assert cfg["identities"][1].anonymous is True


def test_a_malformed_identity_fails_before_any_model_spend(tmp_path):
    path = _write(
        tmp_path,
        """
        targets: [https://app.example.com]
        identities:
          - name: bad
            login: {method: POST}
        """,
    )
    with pytest.raises(ConfigError, match="identities\\[0\\]"):
        load_engagement_file(path)


def test_duplicate_identity_names_are_rejected(tmp_path):
    # The name IS the key the model addresses; two identities sharing one is unresolvable.
    path = _write(
        tmp_path,
        """
        targets: [https://app.example.com]
        identities:
          - {name: alice, headers: {A: "1"}}
          - {name: alice, headers: {A: "2"}}
        """,
    )
    with pytest.raises(ConfigError, match="duplicate identity"):
        load_engagement_file(path)


def test_a_login_recipe_round_trips(tmp_path):
    path = _write(
        tmp_path,
        """
        targets: [https://app.example.com]
        identities:
          - name: api
            login:
              url: https://app.example.com/login
              method: POST
              body: '{"u":"a"}'
              extract: {token: '"token":"([^"]+)"'}
              inject: {Authorization: "Bearer {token}"}
        """,
    )
    identity = load_engagement_file(path)["identities"][0]
    assert identity.login.url == "https://app.example.com/login"
    assert identity.login.inject == {"Authorization": "Bearer {token}"}


# --------------------------------------------------------------------------- merge
def test_explicit_cli_value_wins_over_the_file():
    merged = merge({"max_phases": 20}, {"max_phases": 3}, {"max_phases": 12})
    assert merged["max_phases"] == 3


def test_a_flag_left_at_its_default_does_not_clobber_the_file():
    merged = merge({"max_phases": 20}, {"max_phases": 12}, {"max_phases": 12})
    assert merged["max_phases"] == 20


def test_none_cli_values_are_ignored():
    merged = merge({"max_usd": 5.0}, {"max_usd": None}, {})
    assert merged["max_usd"] == 5.0


def test_cli_only_values_pass_through():
    merged = merge({}, {"targets": ["https://a.example.com"]}, {"targets": []})
    assert merged["targets"] == ["https://a.example.com"]


def test_empty_cli_list_at_default_keeps_the_file_scope():
    # The bug this guards: `a2pwn run --config f.yaml` with no --target must not end up scopeless.
    merged = merge({"targets": ["https://app.example.com"]}, {"targets": []}, {"targets": []})
    assert merged["targets"] == ["https://app.example.com"]
