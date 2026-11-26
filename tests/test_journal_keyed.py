"""Keyed journal: HMAC-SHA256 chain bound to the store, head anchored outside the state directory.

Each test applies one edit an attacker who holds the state directory (but not the key nor the
anchor directory) can make, and checks that the journal is refused on read.
"""

import hashlib
import json
import secrets
import shutil

import pytest

from netops_copilot import changes, cli
from tests.test_changes import FIX, INVENTORY, approve


def entry(i: int) -> dict:
    return {"type": "apply", "change": f"{i:010x}", "operator": "alice",
            "request": f"change {i}", "devices": ["site-a"], "live": []}


@pytest.fixture
def vault(tmp_path):
    folder = tmp_path / "secrets"
    folder.mkdir()
    (folder / "journal.key").write_text(secrets.token_hex(32))
    return folder


@pytest.fixture
def keyed(tmp_path, vault):
    return changes.Store(tmp_path / "lab", key_file=vault / "journal.key",
                         anchor_dir=vault / "anchors")


def seeded(store: changes.Store, n: int = 3) -> changes.Store:
    for i in range(1, n + 1):
        store.append(entry(i))
    return store


def lines(store: changes.Store) -> list[dict]:
    return [json.loads(x) for x in store.journal_path.read_text().splitlines()]


def write(store: changes.Store, entries: list[dict]) -> None:
    store.journal_path.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))


def refused(store: changes.Store) -> bool:
    with pytest.raises(changes.JournalIntegrityError):
        store.journal()
    return not store.verify_journal()


# ---------- configuration ----------

def test_keyed_entries_verify_and_carry_alg_and_epoch(keyed):
    seeded(keyed)
    journal = keyed.journal()
    assert [e["seq"] for e in journal] == [1, 2, 3] and keyed.verify_journal()
    assert {e["alg"] for e in journal} == {"hmac-sha256"} and {e["epoch"] for e in journal} == {0}
    assert json.loads(keyed.anchor_path.read_text())["seq"] == 3


def test_key_and_anchor_must_live_outside_the_state_directory(tmp_path, vault):
    lab = tmp_path / "lab"
    with pytest.raises(changes.ChangeError, match="outside the state directory"):
        changes.Store(lab, key_file=lab / "journal.key", anchor_dir=vault)
    with pytest.raises(changes.ChangeError, match="outside the state directory"):
        changes.Store(lab, anchor_dir=lab / "anchors", key_file=vault / "journal.key")


def test_key_and_anchor_go_together(tmp_path, vault):
    with pytest.raises(changes.ChangeError, match="both"):
        changes.Store(tmp_path / "lab", key_file=vault / "journal.key")


def test_environment_variables_configure_the_keyed_journal(tmp_path, vault, monkeypatch):
    monkeypatch.setenv("NETOPS_JOURNAL_KEY_FILE", str(vault / "journal.key"))
    monkeypatch.setenv("NETOPS_JOURNAL_ANCHOR_DIR", str(vault / "anchors"))
    store = seeded(changes.Store(tmp_path / "lab"), 1)
    assert store.keyed and store.journal()[0]["alg"] == "hmac-sha256"


def test_short_key_is_refused(tmp_path, vault):
    (vault / "journal.key").write_text("short")
    store = changes.Store(tmp_path / "lab", key_file=vault / "journal.key",
                          anchor_dir=vault / "anchors")
    with pytest.raises(changes.ChangeError, match="too short"):
        store.append(entry(1))


def test_unkeyed_journal_is_unchanged(tmp_path):
    store = seeded(changes.Store(tmp_path / "lab"))
    assert not store.keyed and store.verify_journal()
    assert "alg" not in store.journal()[0]


# ---------- edits refused on read ----------

def test_edited_entry_is_refused(keyed):
    journal = lines(seeded(keyed))
    journal[1]["request"] += " [TAMPERED]"
    write(keyed, journal)
    assert refused(keyed)


def test_truncated_tail_is_refused(keyed):
    write(keyed, lines(seeded(keyed))[:-1])
    assert refused(keyed)


def test_deleted_and_reordered_entries_are_refused(keyed):
    journal = lines(seeded(keyed))
    write(keyed, [journal[0], journal[2]])
    assert refused(keyed)
    write(keyed, [journal[0], journal[2], journal[1]])
    assert refused(keyed)


def test_forged_entry_with_a_recomputed_unkeyed_digest_is_refused(keyed):
    journal = lines(seeded(keyed))
    forged = {**journal[-1], "seq": 4, "change": "f0f0f0f0f0", "request": "forged",
              "prev": journal[-1]["hash"]}
    forged.pop("hash")
    forged["hash"] = hashlib.sha256(json.dumps(forged, sort_keys=True).encode()).hexdigest()
    write(keyed, journal + [forged])
    assert refused(keyed)


def test_entry_copied_from_another_store_is_refused(tmp_path, vault, keyed):
    other = seeded(changes.Store(tmp_path / "other", key_file=vault / "journal.key",
                                 anchor_dir=vault / "anchors"))
    journal = lines(seeded(keyed))
    journal[1] = lines(other)[1]
    write(keyed, journal)
    assert refused(keyed)


def test_metadata_edit_is_refused(keyed):
    journal = lines(seeded(keyed))
    journal[0]["time"] = "2030-01-01T00:00:00+00:00"
    write(keyed, journal)
    assert refused(keyed)


def test_whole_store_rollback_is_refused(tmp_path, keyed):
    seeded(keyed, 2)
    shutil.copytree(keyed.root, tmp_path / "snapshot")
    keyed.append(entry(3))
    shutil.rmtree(keyed.root)
    shutil.copytree(tmp_path / "snapshot", keyed.root)
    assert refused(keyed)


def test_erased_journal_restored_from_a_copy_is_refused(tmp_path, keyed):
    seeded(keyed, 1)
    shutil.copytree(keyed.root, tmp_path / "snapshot")
    keyed.reset()
    assert keyed.journal() == [] and keyed.verify_journal()
    shutil.copytree(tmp_path / "snapshot", keyed.root, dirs_exist_ok=True)
    assert refused(keyed)


def test_journal_written_after_a_reset_verifies(keyed):
    seeded(keyed)
    keyed.reset()
    seeded(keyed, 2)
    assert keyed.verify_journal() and {e["epoch"] for e in keyed.journal()} == {1}


def test_edited_anchor_is_refused(keyed):
    seeded(keyed)
    anchor = json.loads(keyed.anchor_path.read_text())
    keyed.anchor_path.write_text(json.dumps({**anchor, "seq": 2}))
    assert refused(keyed)


def test_line_written_before_its_anchor_still_verifies(keyed):
    """A crash between the line and the anchor update must not lock the operator out."""
    seeded(keyed, 2)
    anchor = keyed.anchor_path.read_text()
    keyed.append(entry(3))
    keyed.anchor_path.write_text(anchor)
    assert len(keyed.journal()) == 3 and keyed.verify_journal()


# ---------- decisions are never taken from a refused journal ----------

def test_rollback_and_append_refuse_an_edited_journal(keyed):
    _, _, applied = approve(FIX, keyed)
    journal = lines(keyed)
    journal[0]["operator"] = "mallory"
    write(keyed, journal)
    with pytest.raises(changes.JournalIntegrityError):
        changes.rollback(applied["change"], INVENTORY, keyed)
    with pytest.raises(changes.JournalIntegrityError):
        keyed.append(entry(9))


def test_history_shows_entries_and_flags_a_broken_keyed_journal(keyed, capsys):
    write(keyed, lines(seeded(keyed))[:-1])
    assert cli.print_history(keyed) == 5
    out = capsys.readouterr().out
    assert "change 1" in out and "keyed hash chain, anchored head): BROKEN" in out
