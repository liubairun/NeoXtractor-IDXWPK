"""Archive utility functions."""

from typing import cast

from PySide6 import QtCore

from core.archive.idxwpk_file import IDXWPKFile
from core.logger import get_logger

def get_archive_file() -> IDXWPKFile | None:
    """Get the current archive from the application instance."""
    return cast(QtCore.QCoreApplication, QtCore.QCoreApplication.instance()).property("archive_file")

def ransack_agent(data, search_string):
    """Check if the given search_string is present in the in-memory NPK entry data."""
    try:
        if isinstance(data, bytes):  # Convert binary data to string for searching
            data = data.decode('utf-8', errors='ignore')
        return search_string in data.lower()
    except (UnicodeDecodeError, AttributeError, TypeError) as e:
        get_logger().warning("Error scanning data: %s", e)
        return False


# Backward-compatible alias
get_npk_file = get_archive_file
