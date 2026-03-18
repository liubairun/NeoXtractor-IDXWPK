"""A custom model for displaying NPK files in a QListView."""

from typing import Any, cast
from PySide6 import QtCore, QtGui, QtWidgets

from core.config import Config
from core.npk.class_types import NPKEntryDataFlags
from core.utils import get_filename_in_config

class NPKFileModel(QtCore.QAbstractListModel):
    """
    Custom model for displaying NPK files in a QListView.
    """

    _file_names_cache: dict[int, str] = {}

    def __init__(self, npk_file: Any, parent: QtCore.QObject | None = None):
        super().__init__(parent)

        if isinstance(parent, QtWidgets.QWidget):
            self._loading_icon = parent.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_BrowserReload)
            self._encrypted_icon = parent.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_MessageBoxWarning)
            self._errored_icon = parent.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_MessageBoxCritical)
            self._file_icon = parent.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_FileIcon)

        self._npk_file = npk_file
        app = cast(QtCore.QCoreApplication, QtWidgets.QApplication.instance())
        self._game_config: Config = app.property("game_config")

    def rowCount(self, parent: QtCore.QModelIndex | QtCore.QPersistentModelIndex = QtCore.QModelIndex()) -> int:
        return self._npk_file.file_count

    def data(self, index: QtCore.QModelIndex | QtCore.QPersistentModelIndex,\
             role: int = QtCore.Qt.ItemDataRole.DisplayRole) -> Any:
        if not index.isValid():
            return None
        if role == QtCore.Qt.ItemDataRole.DisplayRole:
            filename = self.get_filename(index)
            if not self._npk_file.is_entry_loaded(index.row()):
                return filename

            # Entry is loaded at this point, get it from cache.
            entry = self._npk_file.read_entry(index.row())

            if entry.data_flags & NPKEntryDataFlags.ERROR:
                return f"{filename} (Error)"
            if entry.data_flags & NPKEntryDataFlags.ENCRYPTED:
                return f"{filename} (Encrypted)"

            return filename
        if role == QtCore.Qt.ItemDataRole.DecorationRole:
            if not self._npk_file.is_entry_loaded(index.row()):
                return self._loading_icon

            # Entry is loaded at this point, get it from cache.
            entry = self._npk_file.read_entry(index.row())

            if entry.data_flags & NPKEntryDataFlags.ERROR:
                return self._errored_icon
            if entry.data_flags & NPKEntryDataFlags.ENCRYPTED:
                return self._encrypted_icon

            return self._file_icon
        if role == QtCore.Qt.ItemDataRole.ForegroundRole:
            if self._npk_file.is_entry_loaded(index.row()):
                entry = self._npk_file.read_entry(index.row())
                if getattr(entry, "is_slot_file", False):
                    return QtGui.QBrush(QtGui.QColor(0, 170, 0))
        if role == QtCore.Qt.ItemDataRole.UserRole:
            return self._npk_file.indices[index.row()]
        return None

    def get_filename(self, index: QtCore.QModelIndex | QtCore.QPersistentModelIndex, invalidate_cache = False) -> str:
        """Get the filename for a given index."""
        if not index.isValid():
            return ""

        if index.row() in self._file_names_cache and not invalidate_cache:
            return self._file_names_cache[index.row()]

        filename = get_filename_in_config(self._game_config, index.row(), self._npk_file)
        self._file_names_cache[index.row()] = filename
        return filename
