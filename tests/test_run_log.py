"""The durable JSONL run log — the observability gap that hid three real bugs.

Adjudication reject reasons, tool failures and model refusals used to exist only on the TUI's
in-memory event bus, so a finished run could only be diagnosed by re-reading raw model transcripts
by hand. That is precisely how the "well-evidenced findings silently dropped from the report" class
stayed hidden until a live engagement surfaced it. ``run.jsonl`` makes a finished run answerable.
"""

from __future__ import annotations

import asyncio
import json

from a2pwn import progress


def _read(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_events_are_written_as_jsonl(tmp_path):
    path = tmp_path / "run.jsonl"
    progress.set_file_sink(path)
    try:
        progress.emit("dispatch_start", id="0-task-0", intent="task")
        progress.emit("finding", status="rejected", reason="oracle did not re-derive")
    finally:
        progress.close_file_sink()
    events = _read(path)
    assert [e["kind"] for e in events] == ["dispatch_start", "finding"]
    assert events[1]["reason"] == "oracle did not re-derive"


def test_every_event_is_timestamped_and_attributed(tmp_path):
    path = tmp_path / "run.jsonl"
    progress.set_file_sink(path)
    try:
        progress.emit("activity", stage="exploit", text="burpwn_exec")
    finally:
        progress.close_file_sink()
    event = _read(path)[0]
    assert "ts" in event
    assert event["dispatch"] == "master"


def test_dispatch_attribution_follows_the_contextvar(tmp_path):
    path = tmp_path / "run.jsonl"
    progress.set_file_sink(path)
    token = progress.set_dispatch("1-verify-2")
    try:
        progress.emit("activity", stage="verify")
    finally:
        progress.reset_dispatch(token)
        progress.close_file_sink()
    assert _read(path)[0]["dispatch"] == "1-verify-2"


def test_the_file_sink_works_without_a_tui_queue(tmp_path):
    # A --plain run has no queue but must still produce the log; that is the whole point.
    path = tmp_path / "run.jsonl"
    progress.clear_sink()
    progress.set_file_sink(path)
    try:
        progress.emit("phase", phase="plan", round=0)
    finally:
        progress.close_file_sink()
    assert len(_read(path)) == 1


def test_both_sinks_receive_the_same_event(tmp_path):
    path = tmp_path / "run.jsonl"
    queue = asyncio.Queue()
    progress.set_sink(queue)
    progress.set_file_sink(path)
    try:
        progress.emit("done", n_verified=3)
    finally:
        progress.clear_sink()
        progress.close_file_sink()
    assert queue.get_nowait()["kind"] == "done"
    assert _read(path)[0]["kind"] == "done"


def test_emitting_without_any_sink_is_a_no_op():
    progress.clear_sink()
    progress.close_file_sink()
    progress.emit("activity", text="nothing installed")  # must not raise


def test_an_unwritable_path_degrades_instead_of_aborting_the_run(tmp_path):
    # A read-only or full run directory must never take down a live engagement.
    progress.set_file_sink(tmp_path / "no-such-dir" / "run.jsonl")
    progress.emit("activity", text="still fine")
    progress.close_file_sink()


def test_non_serialisable_fields_do_not_break_the_log(tmp_path):
    path = tmp_path / "run.jsonl"
    progress.set_file_sink(path)
    try:
        progress.emit("finding", target=object())
    finally:
        progress.close_file_sink()
    assert len(_read(path)) == 1


def test_a_new_sink_replaces_the_previous_one(tmp_path):
    first, second = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    progress.set_file_sink(first)
    progress.emit("activity", text="one")
    progress.set_file_sink(second)
    progress.emit("activity", text="two")
    progress.close_file_sink()
    assert len(_read(first)) == 1
    assert _read(second)[0]["text"] == "two"
