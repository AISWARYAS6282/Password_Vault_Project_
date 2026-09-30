import pytest

from vault.exceptions import (
    AuthenticationError,
    DuplicateEntryError,
    EntryNotFoundError,
    ValidationError,
    VaultAlreadyInitializedError,
    VaultLockedError,
    VaultLockoutError,
    VaultNotInitializedError,
    WeakPasswordError,
)
from vault.vault_manager import VaultManager

MASTER = "Correct-Horse-Battery-9!"
N = 2**10


class FakeClock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture
def db_path(tmp_path):
    return tmp_path / "vault.db"


@pytest.fixture
def vault(db_path):
    v = VaultManager(db_path, kdf_n=N)
    v.initialize(MASTER)
    yield v
    v.close()


# ------------------------------------------------------------ master password
def test_new_vault_is_not_initialized(db_path):
    v = VaultManager(db_path, kdf_n=N)
    assert not v.is_initialized
    with pytest.raises(VaultNotInitializedError):
        v.unlock(MASTER)


def test_initialize_unlocks_and_cannot_repeat(vault):
    assert vault.is_initialized and vault.is_unlocked
    with pytest.raises(VaultAlreadyInitializedError):
        vault.initialize(MASTER)


@pytest.mark.parametrize("weak", ["short", "password1234", "aaaaaaaaaaaaaaaa", "12345678901234"])
def test_weak_master_rejected(db_path, weak):
    v = VaultManager(db_path, kdf_n=N)
    with pytest.raises(WeakPasswordError):
        v.initialize(weak)
    assert not v.is_initialized


def test_unlock_after_lock(vault):
    vault.lock()
    assert not vault.is_unlocked
    vault.unlock(MASTER)
    assert vault.is_unlocked


def test_wrong_master_password(vault):
    vault.lock()
    with pytest.raises(AuthenticationError):
        vault.unlock("Wrong-Password-123!")
    assert not vault.is_unlocked


def test_lockout_after_repeated_failures(db_path):
    clock = FakeClock()
    v = VaultManager(db_path, kdf_n=N, clock=clock)
    v.initialize(MASTER)
    v.lock()
    for _ in range(VaultManager.MAX_FAILED_ATTEMPTS):
        with pytest.raises(AuthenticationError):
            v.unlock("Wrong-Password-123!")
    with pytest.raises(VaultLockoutError) as info:
        v.unlock(MASTER)  # even the right password is refused during lockout
    assert 0 < info.value.seconds_remaining <= VaultManager.BASE_LOCKOUT_SECONDS

    clock.now += VaultManager.BASE_LOCKOUT_SECONDS + 1
    v.unlock(MASTER)
    assert v.is_unlocked
    v.close()


def test_lockout_persists_across_restarts(db_path):
    clock = FakeClock()
    v = VaultManager(db_path, kdf_n=N, clock=clock)
    v.initialize(MASTER)
    v.lock()
    for _ in range(VaultManager.MAX_FAILED_ATTEMPTS):
        with pytest.raises(AuthenticationError):
            v.unlock("nope-nope-nope-1A!")
    v.close()

    restarted = VaultManager(db_path, kdf_n=N, clock=clock)
    with pytest.raises(VaultLockoutError):
        restarted.unlock(MASTER)
    restarted.close()


# ------------------------------------------------------------------------ CRUD
def test_operations_require_unlock(vault):
    vault.lock()
    for call in (
        lambda: vault.add_entry("a", "b", "c"),
        lambda: vault.list_entries(),
        lambda: vault.get_entry(1),
        lambda: vault.search("a"),
        lambda: vault.delete_entry(1),
        lambda: vault.update_entry(1, notes="x"),
    ):
        with pytest.raises(VaultLockedError):
            call()


def test_add_and_get_entry(vault):
    entry_id = vault.add_entry("GitHub", "aiswarya", "s3cretPassw0rd!", "2FA enabled")
    e = vault.get_entry(entry_id)
    assert (e.service, e.username, e.password, e.notes) == ("GitHub", "aiswarya", "s3cretPassw0rd!", "2FA enabled")
    assert "s3cretPassw0rd!" not in repr(e)


def test_duplicate_entry_rejected_case_insensitive(vault):
    vault.add_entry("GitHub", "alice", "pw1")
    with pytest.raises(DuplicateEntryError):
        vault.add_entry("github", "ALICE", "pw2")


def test_validation(vault):
    with pytest.raises(ValidationError):
        vault.add_entry("  ", "user", "pw")
    with pytest.raises(ValidationError):
        vault.add_entry("svc", "user", "")


def test_list_and_search(vault):
    vault.add_entry("GitHub", "alice", "p1")
    vault.add_entry("Gmail", "alice@example.com", "p2")
    vault.add_entry("Netflix", "bob", "p3")
    assert [e.service for e in vault.list_entries()] == ["GitHub", "Gmail", "Netflix"]
    assert [e.service for e in vault.search("g")] == ["GitHub", "Gmail"]
    assert [e.service for e in vault.search("BOB")] == ["Netflix"]
    assert vault.search("zzz") == []


def test_search_treats_wildcards_literally(vault):
    vault.add_entry("Site", "user", "pw")
    assert vault.search("%") == []
    assert vault.search("_") == []


def test_update_entry(vault):
    entry_id = vault.add_entry("Svc", "user", "old")
    vault.update_entry(entry_id, password="new", notes="changed")
    e = vault.get_entry(entry_id)
    assert e.password == "new" and e.notes == "changed" and e.username == "user"


def test_update_to_duplicate_rejected(vault):
    vault.add_entry("A", "u", "p")
    second = vault.add_entry("B", "u", "p")
    with pytest.raises(DuplicateEntryError):
        vault.update_entry(second, service="A")


def test_update_and_delete_missing_entry(vault):
    with pytest.raises(EntryNotFoundError):
        vault.update_entry(999, notes="x")
    with pytest.raises(EntryNotFoundError):
        vault.delete_entry(999)
    with pytest.raises(EntryNotFoundError):
        vault.get_entry(999)


def test_delete_entry(vault):
    entry_id = vault.add_entry("Svc", "user", "pw")
    vault.delete_entry(entry_id)
    assert vault.list_entries() == []


# ------------------------------------------------------ persistence & security
def test_data_persists_across_sessions(db_path):
    v = VaultManager(db_path, kdf_n=N)
    v.initialize(MASTER)
    entry_id = v.add_entry("Svc", "user", "persisted-pw")
    v.close()

    again = VaultManager(db_path, kdf_n=N)
    again.unlock(MASTER)
    assert again.get_entry(entry_id).password == "persisted-pw"
    again.close()


def test_secrets_are_not_stored_in_plaintext(vault, db_path):
    vault.add_entry("Svc", "user", "UNIQUE-plaintext-canary-77", "NOTE-canary-88")
    raw = db_path.read_bytes()
    assert b"UNIQUE-plaintext-canary-77" not in raw
    assert b"NOTE-canary-88" not in raw
    assert MASTER.encode() not in raw


def test_master_password_is_not_logged(vault, tmp_path):
    vault.add_entry("Svc", "user", "log-canary-pw")
    log_text = (tmp_path / "logs" / "vault.log").read_text()
    assert "log-canary-pw" not in log_text and MASTER not in log_text
    assert "entry_added" in log_text


# ------------------------------------------------------------ change master
def test_change_master_password(db_path):
    v = VaultManager(db_path, kdf_n=N)
    v.initialize(MASTER)
    ids = [v.add_entry(f"S{i}", "u", f"pw-{i}", f"n-{i}") for i in range(3)]
    new_master = "Another-Strong-Master-42#"
    v.change_master_password(MASTER, new_master)
    v.close()

    again = VaultManager(db_path, kdf_n=N)
    with pytest.raises(AuthenticationError):
        again.unlock(MASTER)
    again.unlock(new_master)
    assert [again.get_entry(i).password for i in ids] == ["pw-0", "pw-1", "pw-2"]
    assert again.get_entry(ids[1]).notes == "n-1"
    again.close()


def test_change_master_requires_correct_current(vault):
    with pytest.raises(AuthenticationError):
        vault.change_master_password("Wrong-Current-123!", "Another-Strong-Master-42#")


def test_change_master_rejects_weak_or_same(vault):
    with pytest.raises(WeakPasswordError):
        vault.change_master_password(MASTER, "weak")
    with pytest.raises(ValidationError):
        vault.change_master_password(MASTER, MASTER)
    vault.add_entry("Svc", "u", "still-works")  # vault remains usable
