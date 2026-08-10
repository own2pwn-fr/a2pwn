"""LangChain ``BaseTool`` adapters over the shared tool definitions.

This is now a *thin* adapter: the behaviour, descriptions and scope/identity/throttle enforcement
all live in :mod:`a2pwn.toolcore`, which the native-SDK path in :mod:`a2pwn.sdk_agent` adapts too.
Keeping one definition is what stops the two executor paths from drifting apart (they previously
did, and real findings were lost to it — see the module docstring in ``toolcore``).
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import BaseTool, StructuredTool

from a2pwn.burpwn import BurpwnClient
from a2pwn.identity import IdentityStore
from a2pwn.scope import ScopeGuard
from a2pwn.throttle import Throttle
from a2pwn.toolcore import build_tool_specs


def burpwn_tools(
    client: BurpwnClient,
    engagement: Any = None,
    *,
    identities: IdentityStore | None = None,
    throttle: Throttle | None = None,
    fuzz_cap: int = 0,
) -> list[BaseTool]:
    """Tools over a bound client.

    When ``engagement`` is given, every target-facing tool deterministically REFUSES out-of-scope or
    explicitly excluded destinations (parsed from argv / replay Host overrides / fuzz payloads)
    before anything runs — a prompt-injected ``fetch http://attacker/`` or a stray
    ``169.254.169.254`` cannot drive real traffic off-scope. ``identities`` adds the identity tools
    and the ``as_identity`` parameter; ``throttle``/``fuzz_cap`` apply the engagement's traffic
    policy.
    """
    specs = build_tool_specs(
        client,
        guard=ScopeGuard.from_engagement(engagement),
        identities=identities,
        throttle=throttle,
        fuzz_cap=fuzz_cap,
    )
    return [
        StructuredTool.from_function(coroutine=spec.fn, name=spec.name, description=spec.description)
        for spec in specs
    ]
