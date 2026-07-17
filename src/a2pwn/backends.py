"""Model backend factory + subscription/agent chat wrappers.

Two internal families:

* API providers (anthropic/openai/bedrock_converse/google_vertexai/litellm) → thin
  wrappers over ``init_chat_model`` / ``ChatLiteLLM``.
* Subscription / agent backends (Claude Code default, Codex, Antigravity) → custom
  ``BaseChatModel`` subclasses. Claude Code is driven through ``claude-agent-sdk``
  (imports as ``claude_agent_sdk``) so it inherits the user's own Claude Code login;
  ``ANTHROPIC_API_KEY`` is scrubbed from the environment first so the subscription is
  billed instead of the API.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import uuid
from collections.abc import AsyncIterator, Iterator
from typing import Any

import anyio
from langchain_core.callbacks import AsyncCallbackManagerForLLMRun, CallbackManagerForLLMRun
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, BaseMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult
from langchain_core.runnables import Runnable, RunnableLambda
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from a2pwn.config import BackendConfig


def make_model(cfg: BackendConfig) -> BaseChatModel:
    """Route a :class:`BackendConfig` to a concrete ``BaseChatModel``."""
    p = cfg.provider
    if p == "claude-code":
        return ChatClaudeCode(model=cfg.model or "sonnet", options=cfg.options)
    if p == "litellm":
        from langchain_litellm import ChatLiteLLM

        return ChatLiteLLM(model=cfg.model, **cfg.kwargs)
    if p == "codex":
        return ChatCodex(model=cfg.model or "gpt-5-codex", **cfg.kwargs)
    if p == "antigravity":
        return ChatAntigravity(model=cfg.model or "gemini-3-pro", **cfg.kwargs)
    from langchain.chat_models import init_chat_model

    return init_chat_model(cfg.model, model_provider=p, **cfg.kwargs)


# --------------------------------------------------------------------------- #
# rendering helpers
# --------------------------------------------------------------------------- #

_ROLE_HEADERS = {
    "system": "System",
    "human": "User",
    "user": "User",
    "ai": "Assistant",
    "assistant": "Assistant",
    "tool": "Tool",
    "function": "Tool",
}


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                parts.append(str(block.get("text", block.get("content", ""))))
            else:  # pragma: no cover - defensive
                parts.append(str(block))
        return "\n".join(p for p in parts if p)
    return str(content)


_FENCE_RE = re.compile(r"^\s*```(?:json)?\s*|\s*```\s*$", re.IGNORECASE)


def _first_json_object(text: str) -> dict | None:
    """Extract the first balanced ``{...}`` JSON object from free text (fence-tolerant)."""
    if not text:
        return None
    stripped = _FENCE_RE.sub("", text.strip())
    start = stripped.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(stripped)):
        ch = stripped[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(stripped[start : i + 1])
                except json.JSONDecodeError:
                    return None
    return None


def _parse_prompted_tool_calls(text: str) -> list[dict] | None:
    """Parse the prompted ``{"tool_calls": [...]}`` protocol out of a text reply.

    Also tolerates a bare single ``{"name": ..., "arguments": ...}`` object. Returns a
    LangChain ``tool_calls`` list (with generated ids) or ``None`` when the reply is a
    plain-text final answer.
    """
    obj = _first_json_object(text)
    if not obj:
        return None
    raw = obj.get("tool_calls") or obj.get("tool_call")
    if raw is None and "name" in obj and ("arguments" in obj or "args" in obj):
        raw = [obj]
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list) or not raw:
        return None
    calls: list[dict] = []
    for c in raw:
        if not isinstance(c, dict) or not c.get("name"):
            continue
        args = c.get("arguments", c.get("args", {}))
        if isinstance(args, str):
            args = _first_json_object(args) or {}
        calls.append(
            {"id": c.get("id") or uuid.uuid4().hex[:24], "name": c["name"], "args": args, "type": "tool_call"}
        )
    return calls or None


def _sync(coro: Any) -> Any:
    """Drive a coroutine to completion from a synchronous caller, whether or not an event
    loop is already running (LangGraph runs sync nodes in plain worker threads with no loop
    and no anyio portal). Mirrors ``graph._run``."""
    import asyncio
    import concurrent.futures

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _coerce_messages(value: Any) -> list[BaseMessage]:
    """Normalise a Runnable input (message list / PromptValue / str) to ``list[BaseMessage]``."""
    if isinstance(value, BaseMessage):
        return [value]
    if isinstance(value, str):
        return [HumanMessage(content=value)]
    if hasattr(value, "to_messages"):
        return list(value.to_messages())
    if isinstance(value, list):
        return [m if isinstance(m, BaseMessage) else HumanMessage(content=str(m)) for m in value]
    return [HumanMessage(content=str(value))]


_TOOL_PROTOCOL = (
    "You have tools available (listed below). Work step by step.\n"
    "- To CALL one or more tools, reply with ONLY this JSON object and nothing else "
    '(no prose, no markdown fences): {"tool_calls": [{"name": "<tool>", "arguments": {<args>}}]}\n'
    "- To give your FINAL answer when no tool is needed, reply with plain text (never JSON).\n"
    "- Never mix prose and the tool-call JSON in one reply.\n\n"
    "Available tools:"
)


def _render_messages(messages: list[BaseMessage], tool_schemas: list[dict]) -> str:
    """Flatten a LangChain message list into a single prompt string (with the prompted
    tool-calling protocol when tools are bound, and prior tool calls/results rendered so a
    multi-turn ReAct loop stays coherent)."""
    blocks: list[str] = []
    if tool_schemas:
        lines = [_TOOL_PROTOCOL]
        for schema in tool_schemas:
            fn = schema.get("function", schema)
            lines.append(f"- {fn.get('name')}: {fn.get('description', '')}")
            params = fn.get("parameters")
            if params:
                lines.append(f"  arguments schema: {json.dumps(params, separators=(',', ':'))}")
        blocks.append("[System]\n" + "\n".join(lines))
    for msg in messages:
        header = _ROLE_HEADERS.get(getattr(msg, "type", "human"), "User")
        text = _content_to_text(msg.content)
        tcs = getattr(msg, "tool_calls", None)
        if tcs:  # render the assistant's own prior tool calls so it can follow the thread
            rendered = json.dumps(
                {"tool_calls": [{"name": tc["name"], "arguments": tc.get("args", {})} for tc in tcs]},
                separators=(",", ":"),
            )
            text = (text + "\n" + rendered).strip()
        name = getattr(msg, "name", None)
        label = f"{header} {name}" if (header == "Tool" and name) else header
        blocks.append(f"[{label}]\n{text}")
    return "\n\n".join(blocks)


# --------------------------------------------------------------------------- #
# Claude Code subscription backend
# --------------------------------------------------------------------------- #


class ChatClaudeCode(BaseChatModel):
    """LangChain chat model over the Claude Code subscription via ``claude-agent-sdk``.

    Runs single-turn with Claude Code's own agent tools disabled (``allowed_tools=[]``)
    so the model's tool-call proposal is returned to *our* LangGraph rather than being
    executed autonomously. ``TextBlock`` → ``content``; ``ToolUseBlock`` → ``tool_calls``.
    """

    model_config = ConfigDict(extra="allow")

    model: str = "sonnet"
    options: dict = Field(default_factory=dict)
    tool_schemas: list[dict] = Field(default_factory=list)

    @property
    def _llm_type(self) -> str:
        return "claude-code"

    @property
    def _identifying_params(self) -> dict[str, Any]:
        return {"model": self.model}

    def bind_tools(self, tools: list, **kwargs: Any) -> Runnable:
        schemas = [convert_to_openai_tool(t) for t in tools]
        return self.model_copy(update={"tool_schemas": schemas})

    # ---- core async generation ---- #

    async def _sdk_blocks(self, prompt: str) -> tuple[str, list[dict]]:
        """Drive ``claude_agent_sdk.query`` once; return (text, tool_calls)."""
        # Force subscription billing: never let the child see an API key.
        os.environ.pop("ANTHROPIC_API_KEY", None)

        import claude_agent_sdk as sdk

        try:  # block classes are optional across SDK versions
            from claude_agent_sdk import TextBlock, ToolUseBlock
        except Exception:  # pragma: no cover - version guard
            TextBlock = ToolUseBlock = None  # type: ignore[assignment]

        opts_kwargs = {"model": self.model, "allowed_tools": []}
        opts_kwargs.update(self.options)
        options = sdk.ClaudeAgentOptions(**opts_kwargs)

        text_parts: list[str] = []
        tool_calls: list[dict] = []
        async for message in sdk.query(prompt=prompt, options=options):
            for block in getattr(message, "content", None) or []:
                is_tool = (ToolUseBlock is not None and isinstance(block, ToolUseBlock)) or (
                    hasattr(block, "name") and hasattr(block, "input")
                )
                is_text = (TextBlock is not None and isinstance(block, TextBlock)) or hasattr(
                    block, "text"
                )
                if is_tool:
                    tool_calls.append(
                        {
                            "id": getattr(block, "id", None) or uuid.uuid4().hex[:24],
                            "name": getattr(block, "name", ""),
                            "args": getattr(block, "input", {}) or {},
                            "type": "tool_call",
                        }
                    )
                elif is_text:
                    text_parts.append(getattr(block, "text", ""))
        text = "".join(text_parts)
        # Subscription runs with allowed_tools=[] (text only), so native ToolUseBlocks never
        # arrive — recover tool calls from the prompted JSON protocol instead.
        if not tool_calls and self.tool_schemas:
            parsed = _parse_prompted_tool_calls(text)
            if parsed:
                return "", parsed
        return text, tool_calls

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: AsyncCallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        prompt = _render_messages(messages, self.tool_schemas)
        text, tool_calls = await self._sdk_blocks(prompt)
        message = AIMessage(content=text, tool_calls=tool_calls)
        return ChatResult(generations=[ChatGeneration(message=message)])

    async def _astream(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: AsyncCallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> AsyncIterator[ChatGenerationChunk]:
        # The subscription SDK is single-shot and tool calls must be parsed from the whole
        # reply, so we generate once and emit a single chunk (tool calls carried intact).
        result = await self._agenerate(messages, stop, run_manager, **kwargs)
        msg = result.generations[0].message
        chunk_msg = AIMessageChunk(
            content=msg.content,
            tool_call_chunks=[
                {
                    "name": tc["name"],
                    "args": _dumps(tc.get("args", {})),
                    "id": tc.get("id"),
                    "index": i,
                    "type": "tool_call_chunk",
                }
                for i, tc in enumerate(getattr(msg, "tool_calls", []) or [])
            ],
        )
        chunk = ChatGenerationChunk(message=chunk_msg)
        if run_manager is not None:
            await run_manager.on_llm_new_token(msg.content or "", chunk=chunk)
        yield chunk

    # ---- structured output (JSON mode; the subscription backend can't tool-call natively) ---- #

    def with_structured_output(self, schema: Any, **kwargs: Any) -> Runnable:
        """Return a runnable that yields an instance of ``schema`` (a pydantic model).

        Implemented as JSON-mode prompting + parsing, because the subscription backend is
        text-only: we ask for a single JSON object matching the schema and validate it.
        """
        is_model = isinstance(schema, type) and issubclass(schema, BaseModel)
        json_schema = schema.model_json_schema() if is_model else schema
        instruction = (
            "Respond with ONLY a single JSON object that conforms to this JSON schema — no prose, "
            "no markdown fences:\n" + json.dumps(json_schema, separators=(",", ":"))
        )
        model = self

        async def _ainvoke(messages_input: Any) -> Any:
            msgs = _coerce_messages(messages_input)
            msgs = [*msgs, HumanMessage(content=instruction)]
            result = await model._agenerate(msgs)
            text = result.generations[0].message.content
            obj = _first_json_object(text) or {}
            return schema.model_validate(obj) if is_model else obj

        return RunnableLambda(afunc=_ainvoke, func=lambda x: _sync(_ainvoke(x)))

    # ---- sync bridge (anyio; safe inside LangGraph's threaded sync harness) ---- #

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        return _sync(self._agenerate(messages, stop, run_manager))

    def _stream(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> Iterator[ChatGenerationChunk]:
        yield from _sync(self._collect_stream(messages, stop, run_manager))

    async def _collect_stream(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None,
        run_manager: Any,
    ) -> list[ChatGenerationChunk]:
        return [c async for c in self._astream(messages, stop, None)]


def _dumps(obj: Any) -> str:
    import json

    if isinstance(obj, str):
        return obj
    try:
        return json.dumps(obj)
    except Exception:  # pragma: no cover - defensive
        return str(obj)


# --------------------------------------------------------------------------- #
# Best-effort subscription backends (Codex / Antigravity)
# --------------------------------------------------------------------------- #


class _DelegatingChat(BaseChatModel):
    """Shared machinery for best-effort backends that fall back to a key-based tier."""

    model_config = ConfigDict(extra="allow")

    model: str = ""
    _delegate: BaseChatModel | None = PrivateAttr(default=None)

    def _extra_kwargs(self) -> dict[str, Any]:
        return dict(self.model_extra or {})

    def _resolve(self) -> BaseChatModel | None:
        """Return (and cache) a key-based delegate model, or ``None`` if unavailable."""
        if self._delegate is None:
            self._delegate = self._build_delegate()
        return self._delegate

    def _build_delegate(self) -> BaseChatModel | None:  # pragma: no cover - overridden
        raise NotImplementedError

    def bind_tools(self, tools: list, **kwargs: Any) -> Runnable:
        delegate = self._resolve()
        if delegate is not None:
            return delegate.bind_tools(tools, **kwargs)
        return self

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        delegate = self._resolve()
        if delegate is not None:
            return delegate._generate(messages, stop, run_manager, **kwargs)
        text = self._cli_generate(_render_messages(messages, []))
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: AsyncCallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        delegate = self._resolve()
        if delegate is not None:
            return await delegate._agenerate(messages, stop, run_manager, **kwargs)
        text = await anyio.to_thread.run_sync(self._cli_generate, _render_messages(messages, []))
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=text))])

    def _cli_generate(self, prompt: str) -> str:  # pragma: no cover - overridden
        raise RuntimeError(f"{type(self).__name__}: no key-based tier and no CLI fallback available")


class ChatCodex(_DelegatingChat):
    """Best-effort ChatGPT-subscription Codex backend.

    Prefers the sanctioned key-based path (``OPENAI_API_KEY`` → ``ChatOpenAI``); otherwise
    shells out to the ``codex exec`` CLI (subscription OAuth from ``~/.codex/auth.json``).
    """

    model: str = "gpt-5-codex"

    @property
    def _llm_type(self) -> str:
        return "codex"

    def _build_delegate(self) -> BaseChatModel | None:
        if os.environ.get("OPENAI_API_KEY"):
            from langchain.chat_models import init_chat_model

            return init_chat_model(self.model, model_provider="openai", **self._extra_kwargs())
        return None

    def _cli_generate(self, prompt: str) -> str:
        binary = shutil.which("codex")
        if not binary:
            raise RuntimeError(
                "ChatCodex: set OPENAI_API_KEY or install the `codex` CLI (best-effort subscription)"
            )
        proc = subprocess.run(
            [binary, "exec", "--model", self.model, prompt],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"codex exec failed ({proc.returncode}): {proc.stderr.strip()}")
        return proc.stdout.strip()


class ChatAntigravity(_DelegatingChat):
    """Best-effort Google-subscription Antigravity backend.

    Steers to the supported key-based tiers: ``GOOGLE_API_KEY`` / ``GEMINI_API_KEY`` →
    ``google_genai``; Vertex creds → ``google_vertexai``. The unofficial OAuth
    subscription path is not shipped; absent a key we raise an informative error.
    """

    model: str = "gemini-3-pro"

    @property
    def _llm_type(self) -> str:
        return "antigravity"

    def _build_delegate(self) -> BaseChatModel | None:
        from langchain.chat_models import init_chat_model

        if os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY"):
            return init_chat_model(self.model, model_provider="google_genai", **self._extra_kwargs())
        if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS") or os.environ.get(
            "GOOGLE_CLOUD_PROJECT"
        ):
            return init_chat_model(
                self.model, model_provider="google_vertexai", **self._extra_kwargs()
            )
        return None

    def _cli_generate(self, prompt: str) -> str:
        raise RuntimeError(
            "ChatAntigravity: unofficial subscription OAuth is not shipped; set GOOGLE_API_KEY / "
            "GEMINI_API_KEY (google_genai) or Vertex creds (google_vertexai)"
        )
