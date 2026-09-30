"""Custom exceptions for the password vault."""


class VaultError(Exception):
    """Base class for all vault errors."""


class CryptoError(VaultError):
    """Encryption, decryption or key-derivation failed (wrong key or tampered data)."""


class DatabaseError(VaultError):
    """Database layer failure."""


class VaultNotInitializedError(VaultError):
    """The vault has not been set up with a master password yet."""


class VaultAlreadyInitializedError(VaultError):
    """The vault already exists; cannot initialize again."""


class VaultLockedError(VaultError):
    """Operation requires an unlocked vault."""


class AuthenticationError(VaultError):
    """Incorrect master password."""


class VaultLockoutError(AuthenticationError):
    """Too many failed attempts; unlocking is temporarily disabled."""

    def __init__(self, seconds_remaining: int):
        self.seconds_remaining = seconds_remaining
        super().__init__(f"Too many failed attempts. Try again in {seconds_remaining} seconds.")


class WeakPasswordError(VaultError):
    """A password (usually the master password) does not meet the strength policy."""

    def __init__(self, message: str, feedback: list[str] | None = None):
        self.feedback = feedback or []
        super().__init__(message)


class DuplicateEntryError(VaultError):
    """An entry for this service/username already exists."""


class EntryNotFoundError(VaultError):
    """No entry with the given id exists."""


class ValidationError(VaultError):
    """Invalid user input."""
