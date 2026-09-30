"""Password strength analysis.

Score (0-100) is derived from an entropy estimate that is *penalised* for repeated
characters and keyboard/alphabet sequences, then capped by policy rules (very short,
single character class, common password). Feedback tells the user how to improve.
"""

from __future__ import annotations

import math
import string
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

DEFAULT_COMMON_PATH = Path(__file__).resolve().parent.parent / "data" / "common_passwords.txt"

_SYMBOLS = set(string.punctuation)
_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890")
_LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "l", "!": "i",
                       "0": "o", "$": "s", "5": "s", "7": "t"})
_TRAILING = string.digits + string.punctuation
_FULL_SCORE_ENTROPY = 75.0  # bits of *effective* entropy that earns a perfect score


@dataclass(frozen=True)
class StrengthReport:
    score: int                      # 0-100
    label: str                      # Very Weak / Weak / Fair / Strong / Very Strong
    entropy_bits: float
    is_common: bool
    feedback: list[str] = field(default_factory=list)


@lru_cache(maxsize=4)
def load_common_passwords(path: str | None = None) -> frozenset[str]:
    """Load the common-password list (lower-cased). Missing file -> empty set."""
    file = Path(path) if path else DEFAULT_COMMON_PATH
    try:
        lines = file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return frozenset()
    return frozenset(
        line.strip().lower() for line in lines if line.strip() and not line.startswith("#")
    )


def is_common_password(password: str, common: frozenset[str] | None = None) -> bool:
    """True if the password (or a trivial variation: case, leetspeak, trailing digits) is listed."""
    common = load_common_passwords() if common is None else common
    lowered = password.lower()
    leet = lowered.translate(_LEET)
    candidates = {lowered, leet, lowered.rstrip(_TRAILING), leet.rstrip(_TRAILING)}
    return any(c and c in common for c in candidates)


def _char_pool(password: str) -> tuple[int, int]:
    """Return (pool_size, number_of_character_classes_used)."""
    lower = any(c.islower() for c in password)
    upper = any(c.isupper() for c in password)
    digit = any(c.isdigit() for c in password)
    symbol = any(c in _SYMBOLS for c in password)
    other = any(not c.isascii() or c.isspace() for c in password)
    pool = 26 * lower + 26 * upper + 10 * digit + 33 * symbol + 32 * other
    return pool, sum((lower, upper, digit, symbol, other))


def _pattern_penalty(password: str) -> tuple[int, bool, bool]:
    """Count characters that add little entropy. Returns (penalty, has_repeats, has_sequence)."""
    s = password.lower()
    penalty, repeats, sequences = 0, False, False
    for i in range(1, len(s)):
        if s[i] == s[i - 1]:
            penalty += 1
            repeats = True
    for i in range(len(s) - 2):
        a, b, c = s[i:i + 3]
        step1, step2 = ord(b) - ord(a), ord(c) - ord(b)
        alnum_run = a.isalnum() and b.isalnum() and c.isalnum()
        if alnum_run and step1 == step2 and step1 in (1, -1):
            penalty += 1
            sequences = True
        elif any(s[i:i + 3] in row or s[i:i + 3][::-1] in row for row in _KEYBOARD_ROWS):
            penalty += 1
            sequences = True
    return penalty, repeats, sequences


def _label(score: int) -> str:
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Fair"
    if score < 80:
        return "Strong"
    return "Very Strong"


def analyze_password(password: str, common: frozenset[str] | None = None) -> StrengthReport:
    """Analyse *password* and return a :class:`StrengthReport`."""
    if not password:
        return StrengthReport(0, "Very Weak", 0.0, False, ["Password is empty."])

    pool, classes = _char_pool(password)
    penalty, repeats, sequences = _pattern_penalty(password)
    effective_len = max(0, len(password) - penalty)
    entropy = effective_len * math.log2(pool) if pool else 0.0
    score = round(min(entropy, _FULL_SCORE_ENTROPY) / _FULL_SCORE_ENTROPY * 100)

    common_hit = is_common_password(password, common)
    feedback: list[str] = []

    if common_hit:
        score = min(score, 5)
        feedback.append("This is a very common password (or a trivial variation of one).")
    if len(password) < 8:
        score = min(score, 25)
        feedback.append("Use at least 12 characters.")
    elif len(password) < 12:
        feedback.append("Longer is better: aim for 12+ characters.")
    if classes == 1 and len(password) < 16:
        score = min(score, 50)
    if classes < 3:
        feedback.append("Mix upper-case, lower-case, digits and symbols.")
    if repeats:
        feedback.append("Avoid repeated characters (e.g. 'aaa').")
    if sequences:
        feedback.append("Avoid sequences like 'abc', '123' or 'qwerty'.")

    return StrengthReport(score, _label(score), round(entropy, 1), common_hit, feedback)
