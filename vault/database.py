"""SQLite persistence layer.

This layer only stores and retrieves bytes/strings; it knows nothing about encryption.
All SQL is parameterised. Column names used in dynamic UPDATEs come from a whitelist.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from .exceptions import DatabaseError, DuplicateEntryError, EntryNotFoundError

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    service       TEXT NOT NULL,
    username      TEXT NOT NULL,
    password_enc  BLOB NOT NULL,
    notes_enc     BLOB NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (service COLLATE NOCASE, username COLLATE NOCASE)
);
"""

_UPDATABLE = {"service", "username", "password_enc", "notes_enc", "updated_at"}


def _escape_like(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class Database:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self.path.exists():  # create with owner-only permissions
                os.close(os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600))
            self._conn = sqlite3.connect(self.path)
            self._conn.row_factory = sqlite3.Row
            with self._conn:
                self._conn.executescript(SCHEMA)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        except (sqlite3.Error, OSError) as exc:
            raise DatabaseError(f"Cannot open database: {exc}") from exc

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------ meta
    def get_meta(self, key: str) -> bytes | None:
        row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return bytes(row["value"]) if row else None

    def set_meta_many(self, values: dict[str, bytes]) -> None:
        try:
            with self._conn:
                self._conn.executemany(
                    "INSERT INTO meta (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    list(values.items()),
                )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to write metadata: {exc}") from exc

    # --------------------------------------------------------------- entries
    def insert_entry(self, service, username, password_enc, notes_enc, timestamp) -> int:
        try:
            with self._conn:
                cur = self._conn.execute(
                    "INSERT INTO entries (service, username, password_enc, notes_enc, "
                    "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (service, username, password_enc, notes_enc, timestamp, timestamp),
                )
            return int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise DuplicateEntryError(
                f"An entry for '{service}' / '{username}' already exists."
            ) from exc
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to insert entry: {exc}") from exc

    def get_entry(self, entry_id: int) -> sqlite3.Row:
        row = self._conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        if row is None:
            raise EntryNotFoundError(f"No entry with id {entry_id}.")
        return row

    def list_entries(self, query: str | None = None) -> list[sqlite3.Row]:
        if query:
            like = f"%{_escape_like(query)}%"
            return self._conn.execute(
                "SELECT * FROM entries WHERE service LIKE ? ESCAPE '\\' "
                "OR username LIKE ? ESCAPE '\\' ORDER BY service COLLATE NOCASE, username",
                (like, like),
            ).fetchall()
        return self._conn.execute(
            "SELECT * FROM entries ORDER BY service COLLATE NOCASE, username"
        ).fetchall()

    def update_entry(self, entry_id: int, **fields) -> None:
        if not fields:
            return
        unknown = set(fields) - _UPDATABLE
        if unknown:
            raise DatabaseError(f"Illegal column(s): {sorted(unknown)}")
        assignments = ", ".join(f"{col} = ?" for col in fields)
        try:
            with self._conn:
                cur = self._conn.execute(
                    f"UPDATE entries SET {assignments} WHERE id = ?",  # noqa: S608 (whitelisted)
                    (*fields.values(), entry_id),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateEntryError("Another entry with that service/username exists.") from exc
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to update entry: {exc}") from exc
        if cur.rowcount == 0:
            raise EntryNotFoundError(f"No entry with id {entry_id}.")

    def delete_entry(self, entry_id: int) -> None:
        try:
            with self._conn:
                cur = self._conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        except sqlite3.Error as exc:
            raise DatabaseError(f"Failed to delete entry: {exc}") from exc
        if cur.rowcount == 0:
            raise EntryNotFoundError(f"No entry with id {entry_id}.")

    def rekey(self, blobs: list[tuple[int, bytes, bytes]], meta: dict[str, bytes]) -> None:
        """Atomically replace every encrypted blob and the key metadata (master change)."""
        try:
            with self._conn:  # single transaction: all-or-nothing
                self._conn.executemany(
                    "UPDATE entries SET password_enc = ?, notes_enc = ? WHERE id = ?",
                    [(pw, notes, eid) for eid, pw, notes in blobs],
                )
                self._conn.executemany(
                    "INSERT INTO meta (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    list(meta.items()),
                )
        except sqlite3.Error as exc:
            raise DatabaseError(f"Re-keying failed (nothing was changed): {exc}") from exc
