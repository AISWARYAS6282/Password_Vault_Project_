import string

import pytest

from vault.exceptions import ValidationError
from vault.generator import AMBIGUOUS, SYMBOLS, generate_password


def test_default_length():
    assert len(generate_password()) == 16


@pytest.mark.parametrize("length", [8, 20, 64, 128])
def test_requested_length(length):
    assert len(generate_password(length)) == length


def test_contains_every_selected_class():
    for _ in range(200):
        pw = generate_password(8)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in SYMBOLS for c in pw)


def test_digits_only():
    pw = generate_password(12, use_lower=False, use_upper=False, use_symbols=False)
    assert pw.isdigit()


def test_exclude_ambiguous():
    for _ in range(200):
        assert not (set(generate_password(32, exclude_ambiguous=True)) & AMBIGUOUS)


def test_passwords_are_unique():
    assert len({generate_password(20) for _ in range(500)}) == 500


@pytest.mark.parametrize("length", [0, 7, 129, -5])
def test_invalid_length(length):
    with pytest.raises(ValidationError):
        generate_password(length)


def test_no_character_class_selected():
    with pytest.raises(ValidationError):
        generate_password(12, use_lower=False, use_upper=False, use_digits=False, use_symbols=False)
