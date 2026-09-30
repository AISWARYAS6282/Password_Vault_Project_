"""Secure command-line password vault."""

from .analyzer import StrengthReport, analyze_password
from .generator import generate_password
from .vault_manager import EntrySummary, VaultEntry, VaultManager

__version__ = "1.0.0"
__all__ = [
    "VaultManager", "VaultEntry", "EntrySummary",
    "analyze_password", "StrengthReport", "generate_password",
]
