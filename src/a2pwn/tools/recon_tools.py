"""The recon-follow-up-proposal tool for the ReAct executor.

Lets a recon-intent dispatch (subdomain enumeration, tech fingerprinting, ...) hand concrete
follow-up targets straight to the master's dispatch queue instead of only describing them in
prose. ``propose_targets``' return artifact (a list of ``TaskSpec``) is harvested by
``graph._distill`` into ``CleanResult.next_hops`` exactly like a cross-chain follow-up, so the
planner sees ready-to-run tasks next phase instead of having to rediscover them itself.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import BaseTool, StructuredTool

from a2pwn.models import TaskSpec
from a2pwn.scope import host_of, in_scope


def recon_tools(engagement: Any = None) -> list[BaseTool]:
    """``propose_targets``. When ``engagement`` is given, a proposed host outside its
    targets/in_scope allow-list is silently dropped — defense in depth, not the primary control:
    the same host would be refused at the traffic layer anyway the moment a follow-up dispatch
    actually tried to touch it, so this just keeps a hallucinated/off-scope host out of the
    planner's queue in the first place.
    """
    targets = list(getattr(engagement, "targets", None) or [])
    allow = list(getattr(engagement, "in_scope", None) or [])
    enforce = bool(engagement is not None and (targets or allow))

    async def propose_targets(hosts: list[dict]) -> tuple[str, list[TaskSpec]]:
        """Propose concrete follow-up tasks for hosts discovered during recon (e.g. via subfinder +
        httpx). Call this once per genuinely live, distinct host worth testing — skip parked/dead/
        CDN-only/duplicate entries. Each entry: ``{"host": "<hostname or URL>", "note": "<why this
        host matters / what you saw, e.g. status/tech>"}``.
        """
        proposed: list[TaskSpec] = []
        for entry in hosts or []:
            raw = str(entry.get("host") or "").strip()
            if not raw:
                continue
            host = host_of(raw) or raw
            if enforce and not in_scope(host, targets, allow):
                continue
            note = str(entry.get("note") or "").strip()
            url = raw if "://" in raw else f"https://{host}"
            task_text = f"Recon and (if warranted) exploit {host}."
            if note:
                task_text += f" Context from discovery: {note}"
            proposed.append(TaskSpec(task=task_text, target=url, hints=[note] if note else []))
        summary = f"proposed {len(proposed)} follow-up target(s)" if proposed else "no new targets proposed"
        return summary, proposed

    return [
        StructuredTool.from_function(
            coroutine=propose_targets, name="propose_targets", response_format="content_and_artifact"
        )
    ]
