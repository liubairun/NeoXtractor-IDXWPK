"""Compatibility shim for the old extractor code path."""
from core.archive.class_types import NPKEntry

def decrypt_entry(entry: NPKEntry, key: int | None = None) -> bytes:
    return entry.data
