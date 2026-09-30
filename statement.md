# Problem Statement

## Title
Secure Command-Line Password Vault with Strength Analysis and Secure Generation

## Problem
People reuse weak passwords across services because remembering many strong, unique
passwords is hard. Storing them in plain text files or spreadsheets exposes every account
if the file is copied or the device is compromised.

## Objective
Build a local, offline, command-line password manager that:

1. Stores credentials **encrypted at rest**, unlocked only by a single master password.
2. **Generates** strong random passwords using a cryptographically secure source.
3. **Analyses** password strength (entropy, common-password check, patterns) and gives feedback.
4. Resists **brute-force attacks** (memory-hard key derivation) and **online guessing**
   (persistent, exponential lockout).
5. Keeps an **audit log** of events without ever recording secrets.

## Scope
In scope: CLI, SQLite storage, AES-256-GCM encryption, scrypt key derivation, CRUD, search,
master-password change with atomic re-encryption, unit tests.

Out of scope: cloud sync, browser integration, GUI, multi-user access, secure memory wiping
(not reliably possible in CPython), hardware-token support.

## Threat Model
| Threat | Mitigation |
|---|---|
| Attacker copies `vault.db` | AES-256-GCM encrypted secrets; scrypt-derived key; no key stored |
| Offline brute force of master password | Memory-hard scrypt (N=2^15), random 16-byte salt, master strength policy |
| Ciphertext tampering / field swapping | GCM authentication tag + per-field AAD |
| Online guessing via the CLI | 5 failures -> exponential lockout stored in DB |
| Secrets leaking via logs | Logger redacts sensitive fields; tests assert no secrets in logs |
| SQL injection | Parameterised queries; whitelisted column names |
| Shoulder surfing / idle terminal | Hidden password input, screen clear after reveal, 120 s idle auto-lock |

Known limitations: service names and usernames are stored in plaintext (enables search);
an attacker with file access can delete the lockout counters (scrypt is the real defence);
a compromised OS (keylogger, memory dump) defeats any local password manager.

## Expected Outcome
A tested, modular Python application demonstrating secure-coding practice: correct use of
cryptographic primitives, defence in depth, least privilege (0600 file permissions) and
separation of concerns.
