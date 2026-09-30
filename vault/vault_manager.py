"""High-level vault operations: master-password lifecycle and entry CRUD.

Security model
--------------
* The master password is never stored. We store a random salt, the scrypt parameters and
  an *encrypted verifier* (a known string encrypted with the derived key). A correct
  password decrypts the verifier; a wrong one fails the GCM tag check.
* Entry passwords and notes are encrypted with AES-256-GCM. service/username stay in
  plaintext so the vault can be listed/searched (documented trade-off).
* Repeated wrong master passwords trigger an exponential lockout (persisted in the DB).
  NOTE: this only slows *online* guessing; offline attacks are resisted by scrypt.
"""

from __future__ import annotations

import hmac
import json
import logging
import math
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from . import crypto
from .analyzer import analyze_password
from .database import Database
from .exceptions import (
    AuthenticationError,
    CryptoError,
    ValidationError,
    VaultAlreadyInitializedError,
    VaultLockedError,
    VaultLockoutError,
    VaultNotInitializedError,
    WeakPasswordError,
)
from .logger import log_event

_VERIFIER_TEXT = "password-vault:v1:verifier"
_AAD_VERIFIER = b"verifier"
_AAD_PASSWORD = b"password"
_AAD_NOTES = b"notes"


@dataclass(frozen=True)
class EntrySummary:
    """Non-secret view of an entry (safe to list)."""
    id: int
    service: str
    username: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class VaultEntry:
    """Fully decrypted entry. Secrets are excluded from repr() to avoid accidental leaks."""
    id: int
    service: str
    username: str
    password: str = field(repr=False)
    notes: str = field(repr=False)
    created_at: str = ""
    updated_at: str = ""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class VaultManager:
    MIN_MASTER_LENGTH = 12
    MIN_MASTER_SCORE = 60
    MAX_FAILED_ATTEMPTS = 5
    BASE_LOCKOUT_SECONDS = 30
    MAX_LOCKOUT_SECONDS = 3600

    def __init__(
        self,
        db_path: str | os.PathLike = "vault.db",
        *,
        kdf_n: int = crypto.DEFAULT_N,
        clock: Callable[[], float] = time.time,
    ):
        self._db = Database(db_path)
        self._default_n = kdf_n
        self._clock = clock
        self._key: bytes | None = None

    # ------------------------------------------------------------ properties
    @property
    def is_initialized(self) -> bool:
        return self._db.get_meta("salt") is not None

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None

    def close(self) -> None:
        self.lock()
        self._db.close()

    # -------------------------------------------------------------- policies
    def _check_master_policy(self, password: str) -> None:
        report = analyze_password(password)
        if (
            len(password) < self.MIN_MASTER_LENGTH
            or report.is_common
            or report.score < self.MIN_MASTER_SCORE
        ):
            feedback = report.feedback or []
            if len(password) < self.MIN_MASTER_LENGTH:
                feedback = [f"Master password must be at least {self.MIN_MASTER_LENGTH} characters."] + feedback
            raise WeakPasswordError("Master password is too weak.", feedback)

    def _kdf_params(self) -> dict:
        raw = self._db.get_meta("kdf")
        return json.loads(raw) if raw else {"n": self._default_n, "r": crypto.DEFAULT_R, "p": crypto.DEFAULT_P}

    # --------------------------------------------------- master-password flow
    def initialize(self, master_password: str) -> None:
        """First-time setup. Leaves the vault unlocked."""
        if self.is_initialized:
            raise VaultAlreadyInitializedError("Vault already exists.")
        self._check_master_policy(master_password)

        params = {"n": self._default_n, "r": crypto.DEFAULT_R, "p": crypto.DEFAULT_P}
        salt = crypto.generate_salt()
        key = crypto.derive_key(master_password, salt, **params)
        self._db.set_meta_many({
            "salt": salt,
            "kdf": json.dumps(params).encode(),
            "verifier": crypto.encrypt(key, _VERIFIER_TEXT, _AAD_VERIFIER),
            "failed_attempts": b"0",
            "lockout_until": b"0",
        })
        self._key = key
        log_event("vault_initialized")

    def _get_number(self, name: str) -> float:
        raw = self._db.get_meta(name)
        return float(raw.decode()) if raw else 0.0

    def _lockout_remaining(self) -> int:
        remaining = self._get_number("lockout_until") - self._clock()
        return max(0, math.ceil(remaining))

    def unlock(self, master_password: str) -> None:
        if not self.is_initialized:
            raise VaultNotInitializedError("No vault found. Initialize it first.")
        remaining = self._lockout_remaining()
        if remaining > 0:
            log_event("unlock_blocked_lockout", logging.WARNING, seconds=remaining)
            raise VaultLockoutError(remaining)

        salt = self._db.get_meta("salt")
        key = crypto.derive_key(master_password, salt, **self._kdf_params()) if master_password else None
        try:
            if key is None:
                raise CryptoError("empty password")
            crypto.decrypt(key, self._db.get_meta("verifier"), _AAD_VERIFIER)
        except CryptoError:
            self._register_failure()
            raise AuthenticationError("Incorrect master password.") from None

        self._db.set_meta_many({"failed_attempts": b"0", "lockout_until": b"0"})
        self._key = key
        log_event("vault_unlocked")

    def _register_failure(self) -> None:
        failures = int(self._get_number("failed_attempts")) + 1
        updates = {"failed_attempts": str(failures).encode()}
        if failures >= self.MAX_FAILED_ATTEMPTS:
            delay = min(
                self.BASE_LOCKOUT_SECONDS * 2 ** (failures - self.MAX_FAILED_ATTEMPTS),
                self.MAX_LOCKOUT_SECONDS,
            )
            updates["lockout_until"] = str(self._clock() + delay).encode()
        self._db.set_meta_many(updates)
        log_event("unlock_failed", logging.WARNING, consecutive_failures=failures)

    def lock(self) -> None:
        if self._key is not None:
            log_event("vault_locked")
        self._key = None  # drop reference (Python cannot securely wipe memory; see README)

    def change_master_password(self, current: str, new: str) -> None:
        """Re-encrypt the whole vault under a new master password (atomic)."""
        key = self._require_key()
        salt = self._db.get_meta("salt")
        if not hmac.compare_digest(crypto.derive_key(current, salt, **self._kdf_params()), key):
            log_event("master_change_failed", logging.WARNING)
            raise AuthenticationError("Current master password is incorrect.")
        if hmac.compare_digest(current.encode(), new.encode()):
            raise ValidationError("New master password must differ from the current one.")
        self._check_master_policy(new)

        params = {"n": self._default_n, "r": crypto.DEFAULT_R, "p": crypto.DEFAULT_P}
        new_salt = crypto.generate_salt()
        new_key = crypto.derive_key(new, new_salt, **params)

        blobs = []
        for row in self._db.list_entries():
            password = crypto.decrypt(key, row["password_enc"], _AAD_PASSWORD)
            notes = crypto.decrypt(key, row["notes_enc"], _AAD_NOTES)
            blobs.append((
                row["id"],
                crypto.encrypt(new_key, password, _AAD_PASSWORD),
                crypto.encrypt(new_key, notes, _AAD_NOTES),
            ))
        self._db.rekey(blobs, {
            "salt": new_salt,
            "kdf": json.dumps(params).encode(),
            "verifier": crypto.encrypt(new_key, _VERIFIER_TEXT, _AAD_VERIFIER),
        })
        self._key = new_key
        log_event("master_password_changed", entries_reencrypted=len(blobs))

    # ----------------------------------------------------------------- CRUD
    def _require_key(self) -> bytes:
        if self._key is None:
            raise VaultLockedError("Vault is locked.")
        return self._key

    @staticmethod
    def _clean(value: str, name: str) -> str:
        value = (value or "").strip()
        if not value:
            raise ValidationError(f"{name} must not be empty.")
        return value

    def add_entry(self, service: str, username: str, password: str, notes: str = "") -> int:
        key = self._require_key()
        service, username = self._clean(service, "Service"), self._clean(username, "Username")
        if not password:
            raise ValidationError("Password must not be empty.")
        entry_id = self._db.insert_entry(
            service, username,
            crypto.encrypt(key, password, _AAD_PASSWORD),
            crypto.encrypt(key, notes or "", _AAD_NOTES),
            _now(),
        )
        log_event("entry_added", entry_id=entry_id)
        return entry_id

    def get_entry(self, entry_id: int) -> VaultEntry:
        key = self._require_key()
        row = self._db.get_entry(entry_id)
        entry = VaultEntry(
            id=row["id"],
            service=row["service"],
            username=row["username"],
            password=crypto.decrypt(key, row["password_enc"], _AAD_PASSWORD),
            notes=crypto.decrypt(key, row["notes_enc"], _AAD_NOTES),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
        log_event("entry_viewed", entry_id=entry_id)
        return entry

    @staticmethod
    def _summaries(rows) -> list[EntrySummary]:
        return [
            EntrySummary(r["id"], r["service"], r["username"], r["created_at"], r["updated_at"])
            for r in rows
        ]

    def list_entries(self) -> list[EntrySummary]:
        self._require_key()
        return self._summaries(self._db.list_entries())

    def search(self, query: str) -> list[EntrySummary]:
        self._require_key()
        return self._summaries(self._db.list_entries(query.strip()))

    def update_entry(
        self,
        entry_id: int,
        *,
        service: str | None = None,
        username: str | None = None,
        password: str | None = None,
        notes: str | None = None,
    ) -> None:
        """Update only the fields that are not None."""
        key = self._require_key()
        self._db.get_entry(entry_id)  # raises EntryNotFoundError early
        fields: dict[str, object] = {}
        if service is not None:
            fields["service"] = self._clean(service, "Service")
        if username is not None:
            fields["username"] = self._clean(username, "Username")
        if password is not None:
            if not password:
                raise ValidationError("Password must not be empty.")
            fields["password_enc"] = crypto.encrypt(key, password, _AAD_PASSWORD)
        if notes is not None:
            fields["notes_enc"] = crypto.encrypt(key, notes, _AAD_NOTES)
        if not fields:
            return
        fields["updated_at"] = _now()
        self._db.update_entry(entry_id, **fields)
        log_event("entry_updated", entry_id=entry_id, fields=",".join(sorted(k.replace("_enc", "") for k in fields if k != "updated_at")))

    def delete_entry(self, entry_id: int) -> None:
        self._require_key()
        self._db.delete_entry(entry_id)
        log_event("entry_deleted", entry_id=entry_id)
