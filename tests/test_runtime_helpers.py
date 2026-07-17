"""Regression tests for RUNTIME helpers: burpwn preflight, scope hosts, per-dispatch approval
semantics, telemetry-chunk unpacking, dynamic-interrupt detection, and dead-code removal.

The heavy async ``run_engagement``/astream integration test is owned by the TESTS agent; these are
the small unit-level guards for the RUNTIME audit fixes.
"""

from __future__ import annotations

import pytest

from a2pwn import runtime
from a2pwn.runtime import (
    BurpwnMissingError,
    _approve_interrupt,
    _has_dynamic_interrupt,
    _unpack,
)


class _Eng:
    targets = ["https://app.example.com"]


class _Cfg:
    """Duck-typed A2pwnConfig for _approve_interrupt (only needs step_through + engagement)."""

    def __init__(self, step_through: bool) -> None:
        self.step_through = step_through
        self.engagement = _Eng()


# --- burpwn preflight ------------------------------------------------------- #
def test_ensure_burpwn_missing_raises(monkeypatch):
    monkeypatch.setattr(runtime.shutil, "which", lambda _name: None)
    with pytest.raises(BurpwnMissingError):
        runtime.ensure_burpwn_available()


def test_ensure_burpwn_present_ok(monkeypatch):
    monkeypatch.setattr(runtime.shutil, "which", lambda _name: "/usr/bin/burpwn")
    runtime.ensure_burpwn_available()  # must not raise


# --- per-dispatch approval semantics ---------------------------------------- #
def test_approve_interrupt_upfront_only_auto_approves():
    # Default (no step-through): approval is upfront-only, so we resume without prompting.
    assert _approve_interrupt(_Cfg(step_through=False), snap=None) is True


def test_approve_interrupt_step_through_prompts_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    assert _approve_interrupt(_Cfg(step_through=True), snap=None) is True


def test_approve_interrupt_step_through_declines(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    assert _approve_interrupt(_Cfg(step_through=True), snap=None) is False


def test_approve_interrupt_step_through_eof_declines(monkeypatch):
    def _raise(*_):
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise)
    assert _approve_interrupt(_Cfg(step_through=True), snap=None) is False


# --- telemetry chunk unpacking ---------------------------------------------- #
def test_unpack_all_shapes():
    assert _unpack({"a": 1}) == ((), None, {"a": 1})  # bare data (not a tuple)
    assert _unpack((("ns",), "updates", {"n": 1})) == (("ns",), "updates", {"n": 1})  # 3-tuple
    assert _unpack((("ns",), ("messages", "x"))) == (("ns",), "messages", "x")  # (ns,(mode,data))
    assert _unpack(("updates", {"n": 1})) == ((), "updates", {"n": 1})  # (mode,data)


# --- dynamic-interrupt detection -------------------------------------------- #
class _Task:
    def __init__(self, interrupts):
        self.interrupts = interrupts


class _Snap:
    def __init__(self, tasks=(), values=None):
        self.tasks = tasks
        self.values = values


def test_has_dynamic_interrupt_via_task():
    assert _has_dynamic_interrupt(_Snap(tasks=(_Task(interrupts=["x"]),))) is True


def test_has_dynamic_interrupt_via_values():
    assert _has_dynamic_interrupt(_Snap(values={"__interrupt__": 1})) is True


def test_has_dynamic_interrupt_false():
    assert _has_dynamic_interrupt(_Snap(tasks=(_Task(interrupts=None),), values={})) is False


# --- dead code removed ------------------------------------------------------ #
def test_bootstrap_node_removed():
    # graph.py owns the sole entry seeder (_make_bootstrap); the duplicate is gone.
    assert not hasattr(runtime, "bootstrap_node")


# --- scope host extraction (needs BURPWN's scope.py; skipped pre-integration) #
def test_scope_hosts_dedup_and_parse():
    pytest.importorskip("a2pwn.scope")

    class _ScopeEng:
        in_scope = [
            "https://app.example.com/login",
            "app.example.com",
            "https://api.example.com",
        ]
        targets: list[str] = []

    class _ScopeCfg:
        engagement = _ScopeEng()

    hosts = runtime._scope_hosts(_ScopeCfg())
    assert set(hosts) == {"app.example.com", "api.example.com"}
    assert len(hosts) == 2  # deduplicated


def test_scope_hosts_falls_back_to_targets():
    pytest.importorskip("a2pwn.scope")

    class _ScopeEng:
        in_scope: list[str] = []
        targets = ["https://only-target.example.com"]

    class _ScopeCfg:
        engagement = _ScopeEng()

    assert runtime._scope_hosts(_ScopeCfg()) == ["only-target.example.com"]
