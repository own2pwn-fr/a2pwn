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

import os
import shutil
import subprocess
from collections.abc import AsyncIterator, Iterator
from typing import Any

import anyio
from langchain_core.callbacks import AsyncCallbackManagerForLLMRun, CallbackManagerForLLMRun
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, AIMessageChunk, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult
from langchain_core.runnables import Runnable
from langchain_core.utils.function_calling import convert_to_openai_tool
from pydantic import ConfigDict, Field, PrivateAttr

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


def _render_messages(messages: list[BaseMessage], tool_schemas: list[dict]) -> str:
    """Flatten a LangChain message list into a single prompt string."""
    blocks: list[str] = []
    if tool_schemas:
        import json

        lines = ["You may call one of the following tools by emitting a tool call.", ""]
        for schema in tool_schemas:
            fn = schema.get("function", schema)
            lines.append(f"- {fn.get('name')}: {fn.get('description', '')}")
            params = fn.get("parameters")
            if params:
                lines.append(f"  schema: {json.dumps(params, separators=(',', ':'))}")
        blocks.append("[System]\n" + "\n".join(lines))
    for msg in messages:
        header = _ROLE_HEADERS.get(getattr(msg, "type", "human"), "User")
        blocks.append(f"[{header}]\n{_content_to_text(msg.content)}")
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
                            "id": getattr(block, "id", None) or "",
                            "name": getattr(block, "name", ""),
                            "args": getattr(block, "input", {}) or {},
                            "type": "tool_call",
                        }
                    )
                elif is_text:
                    text_parts.append(getattr(block, "text", ""))
        return "".join(text_parts), tool_calls

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
        os.environ.pop("ANTHROPIC_API_KEY", None)
        import claude_agent_sdk as sdk

        try:
            from claude_agent_sdk import ToolUseBlock
        except Exception:  # pragma: no cover - version guard
            ToolUseBlock = None  # type: ignore[assignment]

        opts_kwargs = {"model": self.model, "allowed_tools": []}
        opts_kwargs.update(self.options)
        options = sdk.ClaudeAgentOptions(**opts_kwargs)

        prompt = _render_messages(messages, self.tool_schemas)
        idx = 0
        async for message in sdk.query(prompt=prompt, options=options):
            for block in getattr(message, "content", None) or []:
                is_tool = (ToolUseBlock is not None and isinstance(block, ToolUseBlock)) or (
                    hasattr(block, "name") and hasattr(block, "input")
                )
                if is_tool:
                    chunk = ChatGenerationChunk(
                        message=AIMessageChunk(
                            content="",
                            tool_call_chunks=[
                                {
                                    "name": getattr(block, "name", ""),
                                    "args": _dumps(getattr(block, "input", {}) or {}),
                                    "id": getattr(block, "id", None) or "",
                                    "index": idx,
                                    "type": "tool_call_chunk",
                                }
                            ],
                        )
                    )
                    idx += 1
                else:
                    text = getattr(block, "text", "")
                    if not text:
                        continue
                    chunk = ChatGenerationChunk(message=AIMessageChunk(content=text))
                if run_manager is not None:
                    await run_manager.on_llm_new_token(
                        chunk.message.content or "", chunk=chunk
                    )
                yield chunk

    # ---- sync bridge (anyio; safe inside LangGraph's threaded sync harness) ---- #

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        return anyio.from_thread.run(self._agenerate, messages, stop, run_manager)

    def _stream(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> Iterator[ChatGenerationChunk]:
        chunks = anyio.from_thread.run(self._collect_stream, messages, stop, run_manager)
        yield from chunks

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
