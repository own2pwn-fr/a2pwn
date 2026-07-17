"""Config validation ergonomics + advisory/step-through fields (RUNTIME audit regressions)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from a2pwn.config import A2pwnConfig, BackendConfig, EngagementSpec, RoleModels


def _eng(**kw) -> EngagementSpec:
    return EngagementSpec(name="e", targets=["https://x"], session="e", **kw)


def test_verifier_must_differ_from_executor_actionable_message():
    with pytest.raises(ValidationError) as ei:
        RoleModels(
            executor=BackendConfig(provider="claude-code", model="opus"),
            verifier=BackendConfig(provider="claude-code", model="opus"),
        )
    msg = str(ei.value)
    assert "adversarial independence" in msg
    assert "--verifier-model" in msg  # tells the operator how to fix it


def test_default_rolemodels_are_distinct_and_subscription_coherent():
    rm = RoleModels()
    assert rm.verifier.model == "opus"
    assert rm.verifier.provider == "claude-code"  # runs with no API key out of the box
    assert (rm.verifier.provider, rm.verifier.model) != (rm.executor.provider, rm.executor.model)


def test_step_through_defaults_false():
    assert A2pwnConfig(engagement=_eng()).step_through is False


def test_dos_allowed_is_a_settable_advisory_field():
    assert _eng(dos_allowed=True).dos_allowed is True
