"""Tests for a2pwn.backends — routing + the Claude Code subscription wrapper.

No network and no real SDK: the ``claude_agent_sdk`` module is faked in ``sys.modules``
and the anyio sync bridge / ``init_chat_model`` are monkeypatched.
"""

from __future__ import annotations

import os
import sys
import types

import anyio
import pytest
from langchain_core.messages import HumanMessage
from langchain_core.outputs import ChatResult
from langchain_core.tools import tool

from a2pwn import backends
from a2pwn.backends import ChatAntigravity, ChatClaudeCode, ChatCodex, make_model
from a2pwn.config import BackendConfig

# --------------------------------------------------------------------------- #
# fake claude_agent_sdk
# --------------------------------------------------------------------------- #


class _TextBlock:
    def __init__(self, text: str):
        self.text = text


class _ToolUseBlock:
    def __init__(self, id: str, name: str, input: dict):
        self.id = id
        self.name = name
        self.input = input


class _AssistantMessage:
    def __init__(self, content: list):
        self.content = content


class _Options:
    def __init__(self, **kw):
        self.kw = kw


def _install_fake_sdk(monkeypatch, blocks: list) -> dict:
    seen: dict = {}

    async def query(*, prompt, options, transport=None):
        seen["prompt"] = prompt
        seen["options"] = options
        yield _AssistantMessage(content=blocks)

    fake = types.ModuleType("claude_agent_sdk")
    fake.query = query
    fake.ClaudeAgentOptions = _Options
    fake.TextBlock = _TextBlock
    fake.ToolUseBlock = _ToolUseBlock
    fake.AssistantMessage = _AssistantMessage
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", fake)
    return seen


# --------------------------------------------------------------------------- #
# routing
# --------------------------------------------------------------------------- #


def test_make_model_claude_code_default():
    m = make_model(BackendConfig(provider="claude-code"))
    assert isinstance(m, ChatClaudeCode)
    assert m.model == "sonnet"
    assert m._llm_type == "claude-code"


def test_make_model_claude_code_custom_model_and_options():
    m = make_model(BackendConfig(provider="claude-code", model="opus", options={"max_turns": 1}))
    assert isinstance(m, ChatClaudeCode)
    assert m.model == "opus"
    assert m.options == {"max_turns": 1}


def test_make_model_codex_and_antigravity():
    assert isinstance(make_model(BackendConfig(provider="codex")), ChatCodex)
    assert make_model(BackendConfig(provider="codex")).model == "gpt-5-codex"
    assert isinstance(make_model(BackendConfig(provider="antigravity")), ChatAntigravity)
    assert make_model(BackendConfig(provider="antigravity")).model == "gemini-3-pro"


def test_make_model_litellm(monkeypatch):
    captured = {}

    class ChatLiteLLM:
        def __init__(self, model=None, **kw):
            captured["model"] = model
            captured["kw"] = kw

    fake = types.ModuleType("langchain_litellm")
    fake.ChatLiteLLM = ChatLiteLLM
    monkeypatch.setitem(sys.modules, "langchain_litellm", fake)

    m = make_model(BackendConfig(provider="litellm", model="gpt-4o", kwargs={"api_base": "x"}))
    assert isinstance(m, ChatLiteLLM)
    assert captured["model"] == "gpt-4o"
    assert captured["kw"] == {"api_base": "x"}


def test_make_model_api_provider_routes_init_chat_model(monkeypatch):
    import langchain.chat_models as lcm

    def fake_icm(model, model_provider=None, **kw):
        return ("ICM", model, model_provider, kw)

    monkeypatch.setattr(lcm, "init_chat_model", fake_icm)
    out = make_model(BackendConfig(provider="anthropic", model="claude-opus-4-5"))
    assert out == ("ICM", "claude-opus-4-5", "anthropic", {})


# --------------------------------------------------------------------------- #
# ChatClaudeCode: env scrub + block collection
# --------------------------------------------------------------------------- #


async def test_agenerate_scrubs_api_key_and_collects_blocks(monkeypatch):
    seen = _install_fake_sdk(
        monkeypatch,
        [_TextBlock("hello "), _ToolUseBlock("t1", "sqlmap", {"url": "http://x"})],
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-should-be-removed")

    model = ChatClaudeCode(model="opus", options={"permission_mode": "plan"})
    result = await model._agenerate([HumanMessage("go")])

    # Critical gotcha: the key must be scrubbed so the subscription is billed.
    assert "ANTHROPIC_API_KEY" not in os.environ
    # allowed_tools must be disabled so the graph owns tool execution.
    assert seen["options"].kw["allowed_tools"] == []
    assert seen["options"].kw["model"] == "opus"
    assert seen["options"].kw["permission_mode"] == "plan"

    msg = result.generations[0].message
    assert msg.content == "hello "
    assert len(msg.tool_calls) == 1
    assert msg.tool_calls[0]["name"] == "sqlmap"
    assert msg.tool_calls[0]["args"] == {"url": "http://x"}
    assert msg.tool_calls[0]["id"] == "t1"


async def test_astream_yields_text_and_tool_chunks(monkeypatch):
    _install_fake_sdk(
        monkeypatch,
        [_TextBlock("part-a"), _ToolUseBlock("t2", "ffuf", {"w": "list"})],
    )
    model = ChatClaudeCode()
    chunks = [c async for c in model._astream([HumanMessage("go")])]
    texts = "".join(c.message.content for c in chunks)
    assert "part-a" in texts
    tool_chunks = [tc for c in chunks for tc in (c.message.tool_call_chunks or [])]
    assert any(tc["name"] == "ffuf" for tc in tool_chunks)


# --------------------------------------------------------------------------- #
# anyio sync bridge
# --------------------------------------------------------------------------- #


def test_generate_uses_anyio_from_thread_bridge(monkeypatch):
    called = {}

    def fake_run(func, *args):
        called["func"] = func
        called["args"] = args
        return ChatResult(generations=[])

    monkeypatch.setattr(anyio.from_thread, "run", fake_run)

    model = ChatClaudeCode()
    msgs = [HumanMessage("go")]
    out = model._generate(msgs, stop=None, run_manager=None)

    assert isinstance(out, ChatResult)
    # the sync path must bridge into the async _agenerate via anyio.from_thread.run
    assert called["func"] == model._agenerate
    assert called["args"][0] is msgs


def test_stream_uses_anyio_from_thread_bridge(monkeypatch):
    recorded = {}

    def fake_run(func, *args):
        recorded["func"] = func
        return []

    monkeypatch.setattr(anyio.from_thread, "run", fake_run)
    model = ChatClaudeCode()
    list(model._stream([HumanMessage("go")]))
    assert recorded["func"] == model._collect_stream


# --------------------------------------------------------------------------- #
# bind_tools
# --------------------------------------------------------------------------- #


def test_bind_tools_injects_json_schema():
    @tool
    def run_sqlmap(url: str) -> str:
        """Run sqlmap against a URL."""
        return url

    model = ChatClaudeCode()
    bound = model.bind_tools([run_sqlmap])
    assert isinstance(bound, ChatClaudeCode)
    assert bound.tool_schemas
    fn = bound.tool_schemas[0]["function"]
    assert fn["name"] == "run_sqlmap"
    assert "url" in fn["parameters"]["properties"]
    # original is untouched (bind returns a copy)
    assert model.tool_schemas == []


def test_bound_prompt_carries_tool_schema(monkeypatch):
    @tool
    def run_ffuf(wordlist: str) -> str:
        """Fuzz with ffuf."""
        return wordlist

    seen = _install_fake_sdk(monkeypatch, [_TextBlock("ok")])
    model = ChatClaudeCode().bind_tools([run_ffuf])
    await_result = anyio.run(model._agenerate, [HumanMessage("go")])
    assert isinstance(await_result, ChatResult)
    assert "run_ffuf" in seen["prompt"]


# --------------------------------------------------------------------------- #
# best-effort codex/antigravity fallback
# --------------------------------------------------------------------------- #


def test_codex_prefers_openai_key_delegate(monkeypatch):
    import langchain.chat_models as lcm

    sentinel = types.SimpleNamespace(name="openai-delegate")
    monkeypatch.setattr(lcm, "init_chat_model", lambda *a, **k: sentinel)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    model = ChatCodex(model="gpt-5-codex")
    assert model._resolve() is sentinel


def test_codex_cli_fallback_errors_without_binary(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(backends.shutil, "which", lambda _: None)
    model = ChatCodex()
    assert model._resolve() is None
    with pytest.raises(RuntimeError):
        model._cli_generate("hi")


def test_antigravity_requires_key(monkeypatch):
    for var in ("GOOGLE_API_KEY", "GEMINI_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT"):
        monkeypatch.delenv(var, raising=False)
    model = ChatAntigravity()
    assert model._resolve() is None
    with pytest.raises(RuntimeError):
        model._cli_generate("hi")
