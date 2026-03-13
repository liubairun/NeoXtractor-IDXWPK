"""Archive handling for IDX/WPK resources."""

from .class_types import NPKEntry, NPKIndex, NPKReadOptions
from .idxwpk_file import IDXWPKFile, NPKFile

ArchiveEntry = NPKEntry
ArchiveIndex = NPKIndex
ArchiveReadOptions = NPKReadOptions

__all__ = [
    "IDXWPKFile",
    "NPKFile",
    "NPKEntry",
    "NPKIndex",
    "NPKReadOptions",
    "ArchiveEntry",
    "ArchiveIndex",
    "ArchiveReadOptions",
]
