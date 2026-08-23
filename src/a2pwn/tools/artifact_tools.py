"""Artifact tools — reading, and deliberately forgetting, bulky tool output.

Shared definition for both executor paths (see `a2pwn.toolcore` for the same pattern on the burpwn
hot loop). `artifact_drop` is the one that matters most: it lets an agent convert "I read three
megabytes and it was a vendor bundle" into a single line of durable knowledge, so neither this turn
nor a later retry round pays for that discovery twice.
"""

from __future__ import annotations

from langchain_core.tools import BaseTool, StructuredTool

from a2pwn.artifacts import ArtifactStore

ARTIFACT_TOOL_SPECS: list[tuple[str, str, dict]] = [
    (
        "artifact_grep",
        "Regex-search a stored artifact (a tool result too large to inline) and get windows of "
        "context around each match. This is the cheap way into a big JS bundle, HAR or wordlist "
        "result: search for what you need instead of reading the whole thing.",
        {"id": str, "pattern": str, "max_matches": int},
    ),
    (
        "artifact_slice",
        "Read a window of a stored artifact by character offset. Use after artifact_grep has told "
        "you roughly where to look.",
        {"id": str, "offset": int, "limit": int},
    ),
    (
        "artifact_list",
        "List stored artifacts with their size, origin and whether they were dropped.",
        {},
    ),
    (
        "artifact_drop",
        "Forget a stored artifact's content, keeping only a one-line reason. Call this the moment "
        "you conclude a blob is a dead end (a minified vendor bundle, an unrelated dump): the "
        "reason is what carries forward, and it stops you or a later dispatch re-reading it.",
        {"id": str, "reason": str},
    ),
]


def artifact_tools(store: ArtifactStore) -> list[BaseTool]:
    async def artifact_grep(id: str, pattern: str, max_matches: int = 40) -> str:
        return store.grep(id, pattern, max_matches)

    async def artifact_slice(id: str, offset: int = 0, limit: int = 8000) -> str:
        return store.slice(id, offset, limit)

    async def artifact_list() -> str:
        return store.listing()

    async def artifact_drop(id: str, reason: str) -> str:
        return store.drop(id, reason)

    fns = {
        "artifact_grep": artifact_grep,
        "artifact_slice": artifact_slice,
        "artifact_list": artifact_list,
        "artifact_drop": artifact_drop,
    }
    out: list[BaseTool] = []
    for name, description, _schema in ARTIFACT_TOOL_SPECS:
        fn = fns[name]
        fn.__doc__ = description
        out.append(StructuredTool.from_function(coroutine=fn, name=name))
    return out
