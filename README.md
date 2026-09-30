# Password Vault

A secure, offline, command-line password manager written in Python.

- **AES-256-GCM** authenticated encryption for every stored password and note
- **scrypt** memory-hard key derivation (per-vault random salt; key is never stored)
- **Secure generator** built on Python's `secrets` module
- **Strength analyzer**: entropy estimate, common-password/leetspeak detection, pattern penalties
- **Brute-force protection**: persistent exponential lockout after 5 failed unlocks
- **Audit log** that never contains secrets
- **58 unit tests** (pytest)

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py                  # or: python main.py --db /path/to/vault.db
```

First run creates the vault and asks for a master password (min. 12 characters, must score
"Strong"). **There is no recovery if you forget it** - that is what makes the encryption meaningful.

## Menu

| Option | Action |
|---|---|
| 1 | Add entry (optionally auto-generate the password) |
| 2 / 4 | List / search entries (by service or username) |
| 3 | View an entry (password shown, screen cleared afterwards) |
| 5 / 6 | Update / delete an entry |
| 7 | Generate a password |
| 8 | Check the strength of any password |
| 9 | Change master password (re-encrypts everything atomically) |
| 0 | Lock and exit |

The vault auto-locks after 120 s of inactivity.

## Project layout

```
main.py                CLI menus
vault/
  crypto.py            scrypt key derivation + AES-GCM encrypt/decrypt
  database.py          SQLite layer (parameterised SQL, 0600 file permissions)
  vault_manager.py     master-password logic, lockout, CRUD
  analyzer.py          strength scoring
  generator.py         secure password generation
  logger.py            rotating event log with secret redaction
  exceptions.py        custom errors
data/common_passwords.txt   blocklist (replace with SecLists 10k for production-grade coverage)
tests/                 pytest suite
docs/                  diagrams for the report
statement.md           problem statement and threat model
```

## How it works

1. **Setup:** random 16-byte salt -> `scrypt(master, salt)` -> 256-bit key. A known string is
   encrypted with the key and stored as a *verifier*. Salt, KDF parameters and verifier are
   saved; the master password and key are not.
2. **Unlock:** re-derive the key and try to decrypt the verifier. Success = correct password.
3. **Store:** each password/note is encrypted with a fresh random nonce; the field name is
   bound as associated data so blobs cannot be swapped between fields.
4. **Change master:** decrypt everything with the old key, re-encrypt with a new salt/key,
   and commit in a single SQLite transaction (all-or-nothing).

## Testing

```bash
python -m pytest -v
```

## Security notes and limitations

- Service names and usernames are stored **unencrypted** so listing/search works without
  decrypting everything. Passwords and notes are always encrypted.
- The lockout counter slows *online* guessing. Someone with the database file can reset it, so
  offline resistance comes from scrypt and a strong master password.
- Python cannot reliably wipe secrets from memory; the key reference is dropped on lock.
- Never commit `vault.db` or `logs/` (already in `.gitignore`). Back up `vault.db` privately.
- This is an educational project; audit it before trusting it with critical credentials.
