"""Per-user history and progress tests.

Two properties matter:

  * **Isolation.** One user must never be able to read another's history or
    progress — every accessor is keyed by the caller's own id.
  * **Bounded growth.** History and progress must not grow without limit, and
    the store must survive a corrupt file without losing the bot's ability to
    answer commands.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.users import (  # noqa: E402
    MAX_HISTORY,
    UserStore,
)

ALICE = 111111
BOB = 222222


@pytest.fixture
def store(tmp_path):
    return UserStore(tmp_path / "users.json")


# --- identity ---------------------------------------------------------------

class TestTouch:
    def test_first_contact_creates_a_record(self, store):
        rec = store.touch(ALICE)
        assert rec.user_id == str(ALICE)
        assert rec.first_seen > 0

    def test_repeat_contact_preserves_first_seen(self, store):
        first = store.touch(ALICE).first_seen
        again = store.touch(ALICE).first_seen
        assert again == first

    def test_int_and_str_ids_are_the_same_user(self, store):
        store.record(ALICE, command="inspect", address="0xabc")
        store.record(str(ALICE), command="inspect", address="0xdef")
        assert len(store.history(ALICE)) == 2


# --- history ----------------------------------------------------------------

class TestHistory:
    def test_empty_for_unknown_user(self, store):
        assert store.history(ALICE) == []

    def test_records_a_lookup(self, store):
        store.record(ALICE, command="inspect", address="0xabc")
        rows = store.history(ALICE)
        assert len(rows) == 1
        assert rows[0].command == "inspect"
        assert rows[0].address == "0xabc"

    def test_most_recent_first(self, store):
        store.record(ALICE, command="inspect", address="first")
        store.record(ALICE, command="inspect", address="second")
        assert store.history(ALICE)[0].address == "second"

    def test_leading_slash_is_normalised(self, store):
        store.record(ALICE, command="/inspect", address="0xabc")
        assert store.history(ALICE)[0].command == "inspect"

    def test_untracked_commands_are_not_stored(self, store):
        for cmd in ("start", "help", "status", "chains", "setname", "bogus"):
            store.record(ALICE, command=cmd)
        assert store.history(ALICE) == []

    def test_history_is_capped(self, store):
        for i in range(MAX_HISTORY + 25):
            store.record(ALICE, command="inspect", address=f"0x{i}")
        assert len(store.history(ALICE, limit=1000)) == MAX_HISTORY

    def test_cap_keeps_the_newest(self, store):
        for i in range(MAX_HISTORY + 10):
            store.record(ALICE, command="inspect", address=f"0x{i}")
        newest = store.history(ALICE, limit=1)[0].address
        assert newest == f"0x{MAX_HISTORY + 9}"

    def test_long_detail_is_truncated(self, store):
        store.record(ALICE, command="inspect", address="0xabc",
                     detail="x" * 5000)
        assert len(store.history(ALICE)[0].detail) <= 120

    def test_limit_is_honoured(self, store):
        for i in range(20):
            store.record(ALICE, command="inspect", address=f"0x{i}")
        assert len(store.history(ALICE, limit=5)) == 5


# --- isolation --------------------------------------------------------------

class TestIsolation:
    def test_history_is_per_user(self, store):
        store.record(ALICE, command="inspect", address="alice-addr")
        store.record(BOB, command="inspect", address="bob-addr")
        assert store.history(ALICE)[0].address == "alice-addr"
        assert store.history(BOB)[0].address == "bob-addr"

    def test_progress_is_per_user(self, store):
        store.set_progress(ALICE, sku="puzzle-a")
        store.set_progress(BOB, sku="puzzle-b")
        assert [p.sku for p in store.progress(ALICE)] == ["puzzle-a"]
        assert [p.sku for p in store.progress(BOB)] == ["puzzle-b"]

    def test_unknown_user_sees_nothing(self, store):
        store.record(ALICE, command="inspect", address="0xabc")
        assert store.history(BOB) == []
        assert store.progress(BOB) == []

    def test_stats_are_per_user(self, store):
        store.record(ALICE, command="inspect", address="0xabc")
        assert store.stats(BOB)["history"] == 0
        assert store.stats(ALICE)["history"] == 1


# --- progress ---------------------------------------------------------------

class TestProgress:
    def test_set_and_read(self, store):
        store.set_progress(ALICE, sku="puzzle-a", title="Puzzle A",
                           status="solved")
        rows = store.progress(ALICE)
        assert rows[0].sku == "puzzle-a"
        assert rows[0].status == "solved"

    def test_update_overwrites_the_same_sku(self, store):
        store.set_progress(ALICE, sku="puzzle-a", status="open")
        store.set_progress(ALICE, sku="puzzle-a", status="solved")
        rows = store.progress(ALICE)
        assert len(rows) == 1
        assert rows[0].status == "solved"

    def test_default_status(self, store):
        assert store.set_progress(ALICE, sku="puzzle-a").status == "open"

    def test_long_note_is_truncated(self, store):
        p = store.set_progress(ALICE, sku="puzzle-a", note="y" * 5000)
        assert len(p.note) <= 200

    def test_progress_is_capped(self, store):
        from app.users import MAX_PROGRESS
        for i in range(MAX_PROGRESS + 20):
            store.set_progress(ALICE, sku=f"p{i}")
        assert len(store.progress(ALICE)) <= MAX_PROGRESS


# --- persistence ------------------------------------------------------------

class TestPersistence:
    def test_survives_a_new_instance(self, tmp_path):
        p = tmp_path / "users.json"
        UserStore(p).record(ALICE, command="inspect", address="0xabc")
        assert UserStore(p).history(ALICE)[0].address == "0xabc"

    def test_progress_survives(self, tmp_path):
        p = tmp_path / "users.json"
        UserStore(p).set_progress(ALICE, sku="puzzle-a", status="solved")
        assert UserStore(p).progress(ALICE)[0].status == "solved"

    def test_file_is_owner_only(self, store):
        store.record(ALICE, command="inspect", address="0xabc")
        assert (store.path.stat().st_mode & 0o777) == 0o600

    def test_corrupt_file_does_not_crash(self, tmp_path):
        p = tmp_path / "users.json"
        p.write_text("{not valid json")
        s = UserStore(p)
        assert s.history(ALICE) == []
        assert s.progress(ALICE) == []

    def test_corrupt_file_is_recoverable_by_writing(self, tmp_path):
        p = tmp_path / "users.json"
        p.write_text("{not valid json")
        s = UserStore(p)
        s.record(ALICE, command="inspect", address="0xabc")
        assert UserStore(p).history(ALICE)[0].address == "0xabc"

    def test_malformed_entries_are_skipped(self, tmp_path):
        p = tmp_path / "users.json"
        p.write_text(json.dumps({"users": {
            str(ALICE): {
                "history": [{"at": "not-a-number", "command": "inspect"},
                            {"at": 1.0, "command": "inspect", "address": "ok"}],
                "progress": [{"sku": ""}, {"sku": "good"}],
            }
        }}))
        s = UserStore(p)
        # the malformed row must not take the whole record down
        assert isinstance(s.history(ALICE), list)
        assert any(e.sku == "good" for e in s.progress(ALICE))


# --- no secrets -------------------------------------------------------------

class TestNoSecretFields:
    def test_record_has_no_key_shaped_field(self, store):
        store.record(ALICE, command="inspect", address="0xabc")
        blob = json.dumps(store._load()[str(ALICE)].as_dict()).lower()
        for forbidden in ("private", "seed", "mnemonic", "wif", "secret",
                          "passphrase"):
            assert forbidden not in blob

    def test_stored_file_has_no_secret_fields(self, store):
        store.record(ALICE, command="inspect", address="0xabc")
        blob = store.path.read_text().lower()
        for forbidden in ("private", "seed", "mnemonic", "wif", "passphrase"):
            assert forbidden not in blob
