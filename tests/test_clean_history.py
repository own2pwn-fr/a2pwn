"""Clean-history-by-construction guards (structural, not behavioural).

(1) MasterState physically has no chatty channel a transcript could leak into.
(2) The child subgraph is reached ONLY through the plain ``run_subagent`` wrapper —
    never ``add_node(compiled_subgraph)`` — so its ``messages`` never share a channel.
"""

import ast
from pathlib import Path

from a2pwn.graph import MasterState, SubAgentState

_SOURCE = Path(__file__).resolve().parent.parent / "src" / "a2pwn" / "graph.py"


def test_master_state_has_no_transcript_channel():
    keys = set(MasterState.__annotations__)
    assert "messages" not in keys
    assert "scratch" not in keys
    assert "clarifications" not in keys


def test_child_state_owns_the_transcript_channels():
    # The isolation only works if the chatter lives in the CHILD schema.
    child = set(SubAgentState.__annotations__)
    assert "messages" in child
    assert "clarifications" in child


def _tree() -> ast.Module:
    return ast.parse(_SOURCE.read_text())


def test_no_add_node_wires_the_compiled_subgraph():
    tree = _tree()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "add_node"
        ):
            assert len(node.args) >= 2, "add_node must name a node function"
            target = node.args[1]
            assert not (
                isinstance(target, ast.Name) and target.id in {"subgraph", "SUBAGENT_GRAPH"}
            ), "the compiled subgraph must never be added as a node"


def test_subgraph_is_read_only_inside_run_subagent():
    tree = _tree()
    readers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for sub in ast.walk(node):
                if (
                    isinstance(sub, ast.Name)
                    and sub.id == "SUBAGENT_GRAPH"
                    and isinstance(sub.ctx, ast.Load)
                ):
                    readers.add(node.name)
    assert readers <= {"run_subagent"}
