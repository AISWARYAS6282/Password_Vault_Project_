"""Cryptographically secure password generation (uses the `secrets` module only)."""

from __future__ import annotations

import secrets
import string

from .exceptions import ValidationError

MIN_LENGTH = 8
MAX_LENGTH = 128
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = set("Il1O0o|`'\"")


def generate_password(
    length: int = 16,
    *,
    use_lower: bool = True,
    use_upper: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
) -> str:
    """Generate a random password guaranteed to contain every selected character class."""
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValidationError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")

    selected = []
    if use_lower:
        selected.append(string.ascii_lowercase)
    if use_upper:
        selected.append(string.ascii_uppercase)
    if use_digits:
        selected.append(string.digits)
    if use_symbols:
        selected.append(SYMBOLS)
    if not selected:
        raise ValidationError("Select at least one character type.")

    if exclude_ambiguous:
        selected = ["".join(c for c in chars if c not in AMBIGUOUS) for chars in selected]

    alphabet = "".join(selected)
    # One guaranteed character from each class, the rest from the full alphabet.
    chars = [secrets.choice(group) for group in selected]
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)  # CSPRNG shuffle so guaranteed chars aren't first
    return "".join(chars)
