#!/usr/bin/env python3
"""Password Vault - command-line interface.

Usage:  python main.py [--db PATH]
"""

from __future__ import annotations

import argparse
import getpass
import sys
import time

from vault import VaultManager, analyze_password, generate_password
from vault.exceptions import (
    AuthenticationError,
    VaultError,
    VaultLockoutError,
    WeakPasswordError,
)

IDLE_TIMEOUT_SECONDS = 120
MAX_LOGIN_ATTEMPTS = 3

MENU = """
========== PASSWORD VAULT ==========
 1) Add entry            6) Delete entry
 2) List entries         7) Generate password
 3) View entry           8) Check password strength
 4) Search               9) Change master password
 5) Update entry         0) Lock & exit
====================================="""


# ---------------------------------------------------------------- helpers
def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def ask_int(prompt: str) -> int | None:
    raw = input(f"{prompt}: ").strip()
    if not raw.isdigit():
        print("  ! Please enter a valid number.")
        return None
    return int(raw)


def confirm(prompt: str) -> bool:
    return input(f"{prompt} [y/N]: ").strip().lower() in {"y", "yes"}


def show_report(password: str) -> None:
    r = analyze_password(password)
    print(f"  Strength: {r.label} ({r.score}/100, ~{r.entropy_bits} bits)")
    for tip in r.feedback:
        print(f"   - {tip}")


def print_table(entries) -> None:
    if not entries:
        print("  (no entries)")
        return
    print(f"  {'ID':<4} {'SERVICE':<24} {'USERNAME':<28} UPDATED")
    print("  " + "-" * 80)
    for e in entries:
        print(f"  {e.id:<4} {e.service[:23]:<24} {e.username[:27]:<28} {e.updated_at}")


def prompt_new_password() -> str | None:
    """Ask for a password or offer to generate one. Returns None if cancelled."""
    if confirm("  Generate a random password?"):
        raw = ask("  Length (8-128)", "16")
        try:
            pw = generate_password(int(raw))
        except (ValueError, VaultError) as exc:
            print(f"  ! {exc}")
            return None
        print(f"  Generated: {pw}")
        return pw
    pw = getpass.getpass("  Password (hidden): ")
    if not pw:
        return None
    show_report(pw)
    return pw


# ------------------------------------------------------------ authentication
def setup_vault(vault: VaultManager) -> bool:
    print("No vault found - let's create one.")
    print("Choose a strong master password (12+ chars). It cannot be recovered if lost!")
    for _ in range(MAX_LOGIN_ATTEMPTS):
        first = getpass.getpass("New master password: ")
        if first != getpass.getpass("Confirm master password: "):
            print("  ! Passwords do not match.")
            continue
        try:
            vault.initialize(first)
        except WeakPasswordError as exc:
            print(f"  ! {exc}")
            for tip in exc.feedback:
                print(f"   - {tip}")
            continue
        print("Vault created and unlocked.")
        return True
    return False


def authenticate(vault: VaultManager) -> bool:
    if not vault.is_initialized:
        return setup_vault(vault)
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        try:
            vault.unlock(getpass.getpass("Master password: "))
            print("Vault unlocked.")
            return True
        except VaultLockoutError as exc:
            print(f"  ! {exc}")
            return False
        except AuthenticationError:
            print(f"  ! Incorrect master password ({attempt}/{MAX_LOGIN_ATTEMPTS}).")
    return False


# ------------------------------------------------------------------- actions
def add_entry(vault: VaultManager) -> None:
    service = ask("Service (e.g. GitHub)")
    username = ask("Username / email")
    password = prompt_new_password()
    if password is None:
        print("  Cancelled.")
        return
    notes = ask("Notes (optional)")
    entry_id = vault.add_entry(service, username, password, notes)
    print(f"  Saved entry #{entry_id}.")


def list_entries(vault: VaultManager) -> None:
    print_table(vault.list_entries())


def view_entry(vault: VaultManager) -> None:
    entry_id = ask_int("Entry id")
    if entry_id is None:
        return
    e = vault.get_entry(entry_id)
    print(f"\n  Service  : {e.service}\n  Username : {e.username}")
    print(f"  Password : {e.password}\n  Notes    : {e.notes or '-'}")
    print(f"  Created  : {e.created_at}\n  Updated  : {e.updated_at}")
    input("\n  Press Enter to hide the password...")
    print("\033[2J\033[H", end="")  # clear terminal


def search_entries(vault: VaultManager) -> None:
    query = ask("Search term")
    print_table(vault.search(query))


def update_entry(vault: VaultManager) -> None:
    entry_id = ask_int("Entry id to update")
    if entry_id is None:
        return
    current = vault.get_entry(entry_id)
    print("  Leave a field empty to keep it unchanged.")
    service = ask("  Service", current.service)
    username = ask("  Username", current.username)
    new_password = None
    if confirm("  Change the password?"):
        new_password = prompt_new_password()
    notes = ask("  Notes", current.notes)
    vault.update_entry(
        entry_id, service=service, username=username, password=new_password, notes=notes
    )
    print("  Entry updated.")


def delete_entry(vault: VaultManager) -> None:
    entry_id = ask_int("Entry id to delete")
    if entry_id is None:
        return
    entry = vault.get_entry(entry_id)
    if confirm(f"  Delete '{entry.service}' ({entry.username})? This cannot be undone"):
        vault.delete_entry(entry_id)
        print("  Deleted.")


def generate(_: VaultManager) -> None:
    raw = ask("Length (8-128)", "16")
    if not raw.isdigit():
        print("  ! Invalid length.")
        return
    pw = generate_password(
        int(raw),
        use_symbols=confirm("Include symbols?"),
        exclude_ambiguous=confirm("Exclude look-alike characters (O/0, l/1)?"),
    )
    print(f"  {pw}")
    show_report(pw)


def check_strength(_: VaultManager) -> None:
    show_report(getpass.getpass("Password to check (hidden): "))


def change_master(vault: VaultManager) -> None:
    current = getpass.getpass("Current master password: ")
    new = getpass.getpass("New master password: ")
    if new != getpass.getpass("Confirm new master password: "):
        print("  ! Passwords do not match.")
        return
    try:
        vault.change_master_password(current, new)
    except WeakPasswordError as exc:
        print(f"  ! {exc}")
        for tip in exc.feedback:
            print(f"   - {tip}")
        return
    print("  Master password changed; all entries were re-encrypted.")


ACTIONS = {
    "1": add_entry, "2": list_entries, "3": view_entry, "4": search_entries,
    "5": update_entry, "6": delete_entry, "7": generate, "8": check_strength,
    "9": change_master,
}


# ----------------------------------------------------------------- main loop
def run_menu(vault: VaultManager) -> None:
    last_activity = time.monotonic()
    while True:
        print(MENU)
        choice = input("Select an option: ").strip()

        if time.monotonic() - last_activity > IDLE_TIMEOUT_SECONDS:
            vault.lock()
            print("\nSession timed out - vault locked.")
            if not authenticate(vault):
                return
        last_activity = time.monotonic()

        if choice == "0":
            return
        action = ACTIONS.get(choice)
        if action is None:
            print("  ! Invalid option.")
            continue
        try:
            action(vault)
        except VaultError as exc:
            print(f"  ! {exc}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Secure command-line password vault")
    parser.add_argument("--db", default="vault.db", help="path to vault database (default: vault.db)")
    args = parser.parse_args(argv)

    vault = VaultManager(args.db)
    try:
        if not authenticate(vault):
            print("Authentication failed. Exiting.")
            return 1
        run_menu(vault)
    except (KeyboardInterrupt, EOFError):
        print("\nInterrupted.")
    finally:
        vault.close()
        print("Vault locked. Goodbye.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
