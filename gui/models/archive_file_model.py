"""A custom model for displaying archive entries in a QListView."""

from typing import Any, cast
from PySide6 import QtCore, QtGui, QtWidgets

from core.config import Config
from core.archive.class_types import NPKEntryDataFlags
from core.archive.idxwpk_file import IDXWPKFile
from core.utils import get_filename_in_config

class ArchiveFileModel(QtCore.QAbstractListModel):
    """
    Custom model for displaying archive entries in a QListView.
    """

    def __init__(self, archive_file: IDXWPKFile, parent: QtCore.QObject | None = None):
        super().__init__(parent)

        if isinstance(parent, QtWidgets.QWidget):
            self._loading_icon = parent.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_BrowserReload)
            self._encrypted_icon = parent.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_MessageBoxWarning)
            self._errored_icon = parent.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_MessageBoxCritical)
            self._file_icon = parent.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_FileIcon)

        self._archive_file = archive_file
        self._file_names_cache: dict[int, str] = {}
        app = cast(QtCore.QCoreApplication, QtWidgets.QApplication.instance())
        self._game_config: Config = app.property("game_config")

    def to_real_row(self, visible_row: int) -> int:
        return self._archive_file.get_visible_index(visible_row)

    def rowCount(self, parent: QtCore.QModelIndex | QtCore.QPersistentModelIndex = QtCore.QModelIndex()) -> int:
        return self._archive_file.valid_file_count

    def data(self, index: QtCore.QModelIndex | QtCore.QPersistentModelIndex,\
             role: int = QtCore.Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        if role == QtCore.Qt.ItemDataRole.DisplayRole:
            filename = self.get_filename(index)
            real_row = self.to_real_row(index.row())
            if not self._archive_file.is_entry_loaded(real_row):
                return filename

            # Entry is loaded at this point, get it from cache.
            entry = self._archive_file.read_entry(real_row)

            if entry.data_flags & NPKEntryDataFlags.ERROR:
                return f"{filename} (Error)"
            if entry.data_flags & NPKEntryDataFlags.ENCRYPTED:
                return f"{filename} (Encrypted)"

            return filename
        if role == QtCore.Qt.ItemDataRole.DecorationRole:
            real_row = self.to_real_row(index.row())
            if not self._archive_file.is_entry_loaded(real_row):
                return self._loading_icon

            # Entry is loaded at this point, get it from cache.
            entry = self._archive_file.read_entry(real_row)

            if entry.data_flags & NPKEntryDataFlags.ERROR:
                return self._errored_icon
            if entry.data_flags & NPKEntryDataFlags.ENCRYPTED:
                return self._encrypted_icon

            return self._file_icon
        if role == QtCore.Qt.ItemDataRole.ForegroundRole:
            real_row = self.to_real_row(index.row())
            idx_entry = self._archive_file.indices[real_row]
            if idx_entry.package_id > 15:
                return QtGui.QBrush(QtGui.QColor(0, 170, 0))
            if self._archive_file.is_entry_loaded(real_row):
                entry = self._archive_file.read_entry(real_row)
                if entry.data_flags & NPKEntryDataFlags.LOOSE_SOURCE:
                    return QtGui.QBrush(QtGui.QColor(0, 170, 0))
            return None
        if role == QtCore.Qt.ItemDataRole.UserRole:
            real_row = self.to_real_row(index.row())
            return self._archive_file.indices[real_row]
        return None

    def get_filename(self, index: QtCore.QModelIndex | QtCore.QPersistentModelIndex, invalidate_cache = False) -> str:
        """Get the filename for a given index."""
        if not index.isValid():
            return ""

        visible_row = index.row()
        real_row = self.to_real_row(visible_row)

        if visible_row in self._file_names_cache and not invalidate_cache:
            return self._file_names_cache[visible_row]

        filename = get_filename_in_config(self._game_config, real_row, self._archive_file)
        self._file_names_cache[visible_row] = filename
        return filename


# Backward-compatible alias
NPKFileModel = ArchiveFileModel
