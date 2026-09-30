import pytest

from vault import crypto
from vault.exceptions import CryptoError

N = 2**10  # fast parameters for tests


@pytest.fixture
def key():
    return crypto.derive_key("correct horse", crypto.generate_salt(), n=N)


def test_roundtrip(key):
    assert crypto.decrypt(key, crypto.encrypt(key, "s3cret ✓")) == "s3cret ✓"


def test_key_derivation_is_deterministic_and_salted():
    salt = crypto.generate_salt()
    assert crypto.derive_key("pw", salt, n=N) == crypto.derive_key("pw", salt, n=N)
    assert crypto.derive_key("pw", salt, n=N) != crypto.derive_key("pw", crypto.generate_salt(), n=N)
    assert len(crypto.derive_key("pw", salt, n=N)) == crypto.KEY_SIZE


def test_wrong_key_fails(key):
    blob = crypto.encrypt(key, "data")
    other = crypto.derive_key("different", crypto.generate_salt(), n=N)
    with pytest.raises(CryptoError):
        crypto.decrypt(other, blob)


def test_tampering_detected(key):
    blob = bytearray(crypto.encrypt(key, "data"))
    blob[-1] ^= 0x01
    with pytest.raises(CryptoError):
        crypto.decrypt(key, bytes(blob))


def test_aad_mismatch_detected(key):
    blob = crypto.encrypt(key, "data", b"password")
    with pytest.raises(CryptoError):
        crypto.decrypt(key, blob, b"notes")


def test_nonce_is_random(key):
    assert crypto.encrypt(key, "same") != crypto.encrypt(key, "same")


def test_truncated_blob_rejected(key):
    with pytest.raises(CryptoError):
        crypto.decrypt(key, b"short")


def test_empty_password_rejected():
    with pytest.raises(CryptoError):
        crypto.derive_key("", crypto.generate_salt(), n=N)
