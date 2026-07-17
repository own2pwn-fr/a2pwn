"""Guard: NUL bytes are stripped from evidence before persistence.

A NUL byte in finding evidence (e.g. a binary body pulled from ``.svn/wc.db``)
once aborted a whole ingestion. Every note written during ``seal`` must be
NUL-free, and the returned ref must carry the sanitised note.
"""

from a2pwn.burpwn import FlowBatchManager


def test_strip_nul_removes_all_null_bytes():
    assert FlowBatchManager.strip_nul("a\x00b\x00c") == "abc"
    assert FlowBatchManager.strip_nul("clean") == "clean"
    assert FlowBatchManager.strip_nul("\x00") == ""


async def test_seal_strips_nul_in_note_and_ref(fake_client):
    fbm = FlowBatchManager(fake_client)
    ref = await fbm.open_batch("sqli-poc")
    sealed = await fbm.seal(
        ref,
        captured_request_ids=[10, 11],
        tag="sqli",
        color="red",
        note_body="union select\x00 1,2,3 -- extracted admin\x00 hash",
        key_flow=10,
    )
    assert "\x00" not in sealed.note
    assert sealed.note == "union select 1,2,3 -- extracted admin hash"
    assert sealed.flow_ids == [10, 11]
    assert sealed.key_flow == 10
    assert sealed.tag == "sqli"
    assert sealed.color == "red"
    # every persisted note is NUL-free, on the key flow
    assert fake_client.notes == [
        {"flow_id": 10, "body": "union select 1,2,3 -- extracted admin hash"}
    ]
    # both captured flows were tagged with the highlight colour
    assert fake_client.tags == [
        {"flow_id": 10, "name": "sqli", "color": "red"},
        {"flow_id": 11, "name": "sqli", "color": "red"},
    ]


async def test_seal_without_captured_ids_skips_note(fake_client):
    fbm = FlowBatchManager(fake_client)
    ref = await fbm.open_batch("empty")
    sealed = await fbm.seal(ref, [], tag="x", color="red", note_body="nope", key_flow=None)
    assert sealed.flow_ids == []
    assert sealed.key_flow is None
    assert fake_client.notes == []
