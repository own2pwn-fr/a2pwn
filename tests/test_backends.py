"""Tests for a2pwn.backends — routing + the Claude Code subscription wrapper.

No network and no real SDK: the ``claude_agent_sdk`` module is faked in ``sys.modules``
and the anyio sync bridge / ``init_chat_model`` are monkeypatched.
"""

from __future__ import annotations

import os
import sys
import threading
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

    # Critical gotcha: the key must be scrubbed from the SDK CHILD env so the subscription
    # is billed — but NOT from our own process env (other roles may be provider=anthropic).
    assert os.environ.get("ANTHROPIC_API_KEY") == "sk-should-be-removed"
    assert "ANTHROPIC_API_KEY" not in seen["options"].kw["env"]
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


def test_generate_bridges_to_agenerate(monkeypatch):
    """The sync path must drive the async _agenerate to completion even in a plain thread
    (no running loop, no anyio portal) — the environment LangGraph runs sync nodes in."""
    called = {}

    async def fake_agen(self, messages, stop=None, run_manager=None, **kw):
        called["messages"] = messages
        return ChatResult(generations=[])

    monkeypatch.setattr(ChatClaudeCode, "_agenerate", fake_agen)
    model = ChatClaudeCode()
    msgs = [HumanMessage("go")]

    out = {}
    t = threading.Thread(target=lambda: out.update(r=model._generate(msgs, stop=None, run_manager=None)))
    t.start()
    t.join()

    assert isinstance(out["r"], ChatResult)
    assert called["messages"] is msgs


def test_stream_bridges_to_astream(monkeypatch):
    async def fake_astream(self, messages, stop=None, run_manager=None, **kw):
        from langchain_core.messages import AIMessageChunk
        from langchain_core.outputs import ChatGenerationChunk

        yield ChatGenerationChunk(message=AIMessageChunk(content="hi"))

    monkeypatch.setattr(ChatClaudeCode, "_astream", fake_astream)
    model = ChatClaudeCode()
    chunks = list(model._stream([HumanMessage("go")]))
    assert chunks and chunks[0].message.content == "hi"


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


# --------------------------------------------------------------------------- #
# prompted function-calling (the subscription backend is text-only)
# --------------------------------------------------------------------------- #
from pydantic import BaseModel  # noqa: E402

from a2pwn.backends import (  # noqa: E402
    _first_json_object,
    _parse_prompted_tool_calls,
    _render_messages,
)


def test_first_json_object_fence_and_balanced():
    assert _first_json_object("sure:\n```json\n{\"a\": {\"b\": 1}}\n```") == {"a": {"b": 1}}
    assert _first_json_object('prefix {"x": "}"} suffix') == {"x": "}"}
    assert _first_json_object("no json here") is None


def test_parse_prompted_tool_calls_variants():
    calls = _parse_prompted_tool_calls('{"tool_calls":[{"name":"burpwn_exec","arguments":{"argv":["curl"]}}]}')
    assert calls and calls[0]["name"] == "burpwn_exec" and calls[0]["args"] == {"argv": ["curl"]}
    assert calls[0]["id"]  # a synthetic id is always assigned
    # bare single object
    single = _parse_prompted_tool_calls('{"name":"nmap","arguments":{"t":"x"}}')
    assert single and single[0]["name"] == "nmap"
    # a plain-text final answer is NOT a tool call
    assert _parse_prompted_tool_calls("The finding is confirmed because ...") is None


def test_render_messages_injects_protocol_and_prior_calls():
    from langchain_core.messages import AIMessage, HumanMessage

    schema = {"function": {"name": "nmap", "description": "scan", "parameters": {"type": "object"}}}
    prior = AIMessage(content="", tool_calls=[{"id": "1", "name": "nmap", "args": {"t": "x"}, "type": "tool_call"}])
    rendered = _render_messages([HumanMessage(content="hi"), prior], [schema])
    assert "tool_calls" in rendered and "nmap" in rendered  # protocol + prior call are visible


def test_with_structured_output_parses_json(monkeypatch):
    class Out(BaseModel):
        tasks: list[str] = []

    async def fake_agen(self, messages, *a, **k):
        from langchain_core.messages import AIMessage
        from langchain_core.outputs import ChatGeneration, ChatResult

        return ChatResult(generations=[ChatGeneration(message=AIMessage(content='```json\n{"tasks":["a","b"]}\n```'))])

    monkeypatch.setattr(ChatClaudeCode, "_agenerate", fake_agen)
    m = ChatClaudeCode(model="sonnet")
    out = anyio.run(m.with_structured_output(Out).ainvoke, [HumanMessage(content="plan")])
    assert isinstance(out, Out) and out.tasks == ["a", "b"]


# --------------------------------------------------------------------------- #
# regression: _first_json_object rescans past stray/malformed leading braces
# --------------------------------------------------------------------------- #


def test_first_json_object_skips_leading_non_json_brace():
    # A prose brace before the real tool JSON must NOT drop the object.
    text = 'note {step 1} then {"tool_calls":[{"name":"nmap"}]}'
    assert _first_json_object(text) == {"tool_calls": [{"name": "nmap"}]}


def test_first_json_object_scans_past_malformed_first_object():
    # First balanced object fails to parse; the second (valid) one is returned.
    text = '{not: valid} {"ok": true}'
    assert _first_json_object(text) == {"ok": True}


def test_first_json_object_multiple_objects_returns_first_valid():
    text = 'garbage {"a":1} trailing {"b":2}'
    assert _first_json_object(text) == {"a": 1}


def test_first_json_object_all_garbage_is_none():
    assert _first_json_object("prose {oops not json} more prose") is None


def test_parse_prompted_tool_calls_survives_prose_prefix():
    text = 'Reasoning about {the target}.\n{"tool_calls":[{"name":"sqlmap","arguments":{"u":"x"}}]}'
    calls = _parse_prompted_tool_calls(text)
    assert calls and calls[0]["name"] == "sqlmap" and calls[0]["args"] == {"u": "x"}


# --------------------------------------------------------------------------- #
# regression: bare {name,arguments} only counts as a tool call for a bound tool
# --------------------------------------------------------------------------- #


def test_bare_object_gated_by_known_tools():
    body = '{"name":"admin","arguments":{"role":"root"}}'  # looks like an API response body
    # Without a bound-tool allowlist the bare heuristic still fires (direct callers).
    assert _parse_prompted_tool_calls(body) is not None
    # But when tools are bound and the name is not one of them, it is NOT a tool call.
    assert _parse_prompted_tool_calls(body, known_tools={"nmap", "sqlmap"}) is None
    # A bound name is accepted.
    assert _parse_prompted_tool_calls(body, known_tools={"admin"}) is not None


def test_sdk_blocks_ignores_bare_json_answer(monkeypatch):
    # A final answer that happens to contain {"name":...,"args":...} must stay prose.
    _install_fake_sdk(monkeypatch, [_TextBlock('{"name":"admin","args":{"id":1}}')])

    @tool
    def run_nmap(url: str) -> str:
        """Scan."""
        return url

    model = ChatClaudeCode().bind_tools([run_nmap])
    result = anyio.run(model._agenerate, [HumanMessage("go")])
    msg = result.generations[0].message
    assert not msg.tool_calls
    assert msg.content == '{"name":"admin","args":{"id":1}}'


# --------------------------------------------------------------------------- #
# regression: string-encoded non-object tool args are not silently dropped
# --------------------------------------------------------------------------- #


def test_string_array_args_are_wrapped_not_dropped():
    calls = _parse_prompted_tool_calls('{"tool_calls":[{"name":"burpwn_exec","arguments":"[\\"curl\\",\\"-s\\"]"}]}')
    assert calls and calls[0]["args"] == {"input": ["curl", "-s"]}


def test_string_object_args_are_decoded():
    calls = _parse_prompted_tool_calls('{"tool_calls":[{"name":"x","arguments":"{\\"a\\":1}"}]}')
    assert calls and calls[0]["args"] == {"a": 1}


# --------------------------------------------------------------------------- #
# regression: env scrub is scoped to the SDK child (never mutates our process env)
# --------------------------------------------------------------------------- #


async def test_env_scrub_restored_on_legacy_sdk_without_env_option(monkeypatch):
    class _NoEnvOptions:
        def __init__(self, **kw):
            if "env" in kw:  # emulate an older SDK that rejects `env`
                raise TypeError("unexpected keyword argument 'env'")
            self.kw = kw

    captured = {}

    async def query(*, prompt, options, transport=None):
        captured["key_during"] = os.environ.get("ANTHROPIC_API_KEY", "<absent>")
        yield _AssistantMessage(content=[_TextBlock("ok")])

    fake = types.ModuleType("claude_agent_sdk")
    fake.query = query
    fake.ClaudeAgentOptions = _NoEnvOptions
    fake.TextBlock = _TextBlock
    fake.ToolUseBlock = _ToolUseBlock
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", fake)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-restore-me")

    await ChatClaudeCode(model="sonnet")._agenerate([HumanMessage("go")])

    # scrubbed for the duration of the call, restored afterwards
    assert captured["key_during"] == "<absent>"
    assert os.environ.get("ANTHROPIC_API_KEY") == "sk-restore-me"


# --------------------------------------------------------------------------- #
# regression: with_structured_output repair retry + clear error on final failure
# --------------------------------------------------------------------------- #


def test_with_structured_output_repairs_on_second_try(monkeypatch):
    class Out(BaseModel):
        tasks: list[str] = []

    calls = {"n": 0}

    async def flaky_agen(self, messages, *a, **k):
        from langchain_core.messages import AIMessage
        from langchain_core.outputs import ChatGeneration, ChatResult

        calls["n"] += 1
        content = "sorry, here are the tasks" if calls["n"] == 1 else '{"tasks":["a"]}'
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=content))])

    monkeypatch.setattr(ChatClaudeCode, "_agenerate", flaky_agen)
    m = ChatClaudeCode(model="sonnet")
    out = anyio.run(m.with_structured_output(Out).ainvoke, [HumanMessage(content="plan")])
    assert calls["n"] == 2  # first miss triggered exactly one repair retry
    assert isinstance(out, Out) and out.tasks == ["a"]


def test_with_structured_output_raises_clear_error_after_retry(monkeypatch):
    from a2pwn.backends import StructuredOutputError

    class Out(BaseModel):
        tasks: list[str] = []

    async def prose_agen(self, messages, *a, **k):
        from langchain_core.messages import AIMessage
        from langchain_core.outputs import ChatGeneration, ChatResult

        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="no json whatsoever"))])

    monkeypatch.setattr(ChatClaudeCode, "_agenerate", prose_agen)
    m = ChatClaudeCode(model="sonnet")
    with pytest.raises(StructuredOutputError) as ei:
        anyio.run(m.with_structured_output(Out).ainvoke, [HumanMessage(content="plan")])
    assert "no json whatsoever" in ei.value.raw


def test_with_structured_output_include_raw_envelope(monkeypatch):
    class Out(BaseModel):
        tasks: list[str] = []

    async def prose_agen(self, messages, *a, **k):
        from langchain_core.messages import AIMessage
        from langchain_core.outputs import ChatGeneration, ChatResult

        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="nope"))])

    monkeypatch.setattr(ChatClaudeCode, "_agenerate", prose_agen)
    m = ChatClaudeCode(model="sonnet")
    env = anyio.run(m.with_structured_output(Out, include_raw=True).ainvoke, [HumanMessage(content="p")])
    assert env["parsed"] is None
    assert env["parsing_error"] is not None
    assert env["raw"].content == "nope"


def test_with_structured_output_sync_path(monkeypatch):
    class Out(BaseModel):
        tasks: list[str] = []

    async def fake_agen(self, messages, *a, **k):
        from langchain_core.messages import AIMessage
        from langchain_core.outputs import ChatGeneration, ChatResult

        return ChatResult(generations=[ChatGeneration(message=AIMessage(content='{"tasks":["z"]}'))])

    monkeypatch.setattr(ChatClaudeCode, "_agenerate", fake_agen)
    m = ChatClaudeCode(model="sonnet")
    # drive the RunnableLambda's sync func= path (no running loop) in a plain thread
    out_box = {}
    t = threading.Thread(
        target=lambda: out_box.update(r=m.with_structured_output(Out).invoke([HumanMessage(content="p")]))
    )
    t.start()
    t.join()
    assert isinstance(out_box["r"], Out) and out_box["r"].tasks == ["z"]


def test_with_structured_output_rejects_unknown_kwargs():
    class Out(BaseModel):
        tasks: list[str] = []

    with pytest.raises(NotImplementedError):
        ChatClaudeCode(model="sonnet").with_structured_output(Out, method="function_calling")


# --------------------------------------------------------------------------- #
# regression: make_model input validation + friendly extras errors
# --------------------------------------------------------------------------- #


def test_make_model_claude_code_rejects_kwargs():
    with pytest.raises(ValueError):
        make_model(BackendConfig(provider="claude-code", kwargs={"temperature": 0}))


def test_make_model_litellm_missing_extra_is_friendly(monkeypatch):
    # Simulate the extra not being installed.
    monkeypatch.setitem(sys.modules, "langchain_litellm", None)
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "langchain_litellm":
            raise ImportError("No module named 'langchain_litellm'")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(ImportError) as ei:
        make_model(BackendConfig(provider="litellm", model="gpt-4o"))
    assert "langchain-litellm" in str(ei.value)


# --------------------------------------------------------------------------- #
# regression: Codex/Antigravity CLI fallback keeps bound tools + timeout/stdin
# --------------------------------------------------------------------------- #


def test_codex_cli_fallback_keeps_bound_tools(monkeypatch):
    @tool
    def run_nmap(url: str) -> str:
        """Scan."""
        return url

    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    model = ChatCodex()
    bound = model.bind_tools([run_nmap])
    assert isinstance(bound, ChatCodex)
    assert bound.tool_schemas  # tools are NOT silently dropped in the CLI tier

    # a tool-call reply from the CLI is parsed back into tool_calls
    monkeypatch.setattr(
        ChatCodex,
        "_cli_generate",
        lambda self, prompt: '{"tool_calls":[{"name":"run_nmap","arguments":{"url":"http://x"}}]}',
    )
    result = bound._generate([HumanMessage("go")])
    msg = result.generations[0].message
    assert msg.tool_calls and msg.tool_calls[0]["name"] == "run_nmap"


def test_codex_cli_uses_stdin_and_timeout(monkeypatch):
    captured = {}

    class _Proc:
        returncode = 0
        stdout = "done"
        stderr = ""

    def fake_run(argv, **kw):
        captured["argv"] = argv
        captured["kw"] = kw
        return _Proc()

    monkeypatch.setattr(backends.shutil, "which", lambda _: "/usr/bin/codex")
    monkeypatch.setattr(backends.subprocess, "run", fake_run)
    out = ChatCodex()._cli_generate("a very long prompt")
    assert out == "done"
    assert captured["argv"][-1] == "-"  # prompt fed via stdin, not argv
    assert captured["kw"]["input"] == "a very long prompt"
    assert captured["kw"]["timeout"]  # a wall-clock cap is enforced


def test_codex_cli_timeout_raises(monkeypatch):
    def fake_run(argv, **kw):
        raise backends.subprocess.TimeoutExpired(argv, kw.get("timeout"))

    monkeypatch.setattr(backends.shutil, "which", lambda _: "/usr/bin/codex")
    monkeypatch.setattr(backends.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="timed out"):
        ChatCodex()._cli_generate("hi")


# --------------------------------------------------------------------------- #
# resilience: salvage streamed content on a terminal SDK error
# --------------------------------------------------------------------------- #
def _install_raising_sdk(monkeypatch, blocks, exc):
    """Fake SDK whose query streams `blocks` then raises `exc` (models the CLI's terminal
    'returned an error result: success' after the assistant content already streamed)."""

    async def query(*, prompt, options, transport=None):
        yield _AssistantMessage(content=blocks)
        raise exc

    fake = types.ModuleType("claude_agent_sdk")
    fake.query = query
    fake.ClaudeAgentOptions = _Options
    fake.TextBlock = _TextBlock
    fake.ToolUseBlock = _ToolUseBlock
    fake.AssistantMessage = _AssistantMessage
    monkeypatch.setitem(sys.modules, "claude_agent_sdk", fake)


async def test_sdk_error_after_content_is_salvaged(monkeypatch):
    _install_raising_sdk(
        monkeypatch, [_TextBlock("partial answer")], Exception("returned an error result: success")
    )
    model = ChatClaudeCode()
    result = await model._agenerate([HumanMessage("go")])
    assert result.generations[0].message.content == "partial answer"


async def test_sdk_error_with_no_content_propagates(monkeypatch):
    _install_raising_sdk(monkeypatch, [], RuntimeError("auth failed"))
    model = ChatClaudeCode()
    with pytest.raises(RuntimeError):
        await model._agenerate([HumanMessage("go")])


# --------------------------------------------------------------------------- #
# arg coercion: the model often stringifies list/None/bool argument VALUES
# --------------------------------------------------------------------------- #
from a2pwn.backends import _coerce_args, _coerce_value  # noqa: E402


def test_coerce_value_destringifies():
    assert _coerce_value('["curl", "-s"]') == ["curl", "-s"]
    assert _coerce_value('{"a": 1}') == {"a": 1}
    assert _coerce_value("null") is None
    assert _coerce_value("true") is True
    assert _coerce_value("plain") == "plain"
    assert _coerce_value(42) == 42


def test_coerce_args_per_value():
    # exactly the malformed shape observed live: argv + signals as JSON strings, workspace_id "null"
    out = _coerce_args({"argv": '["curl", "-si", "http://x/"]', "workspace_id": "null", "n": "3"})
    assert out["argv"] == ["curl", "-si", "http://x/"]
    assert out["workspace_id"] is None
    assert out["n"] == "3"  # numeric strings left for pydantic to coerce


def test_coerce_args_whole_string_dict():
    out = _coerce_args('{"signals": "[\\"root:x:0:0\\"]"}')
    assert out["signals"] == ["root:x:0:0"]
