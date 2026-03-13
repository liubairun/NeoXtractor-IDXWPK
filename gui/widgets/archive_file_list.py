"""Custom QListView to display archives."""

import os
from typing import cast
from PySide6 import QtCore, QtWidgets

from core.config import Config
from core.archive.class_types import NPKEntry
from gui.models.archive_file_model import ArchiveFileModel
from gui.utils.config import save_config_manager_to_settings
from gui.utils.archive import get_archive_file
from gui.utils.viewer import ALL_VIEWERS, get_viewer_display_name

class ArchiveFileList(QtWidgets.QListView):
    """
    Custom QListView to display archives.
    """

    preview_entry = QtCore.Signal(int, NPKEntry)
    open_entry = QtCore.Signal(int, NPKEntry)
    open_entry_with = QtCore.Signal(int, NPKEntry, type)

    def __init__(self, parent: QtWidgets.QWidget | None = None):
        super().__init__(parent)

        self._disabled = False
        self._select_after_enabled: QtCore.QModelIndex | None = None

        self.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setDragEnabled(False)
        self.setAcceptDrops(False)
        self.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

        # Connect double-click signal to handler
        self.doubleClicked.connect(self.on_item_double_clicked)

    def setDisabled(self, disabled: bool):
        """
        Set the disabled state of the list view.

        :param disabled: True to disable, False to enable.
        """
        if disabled:
            self.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.NoSelection)
            self.setFocusPolicy(QtCore.Qt.FocusPolicy.NoFocus)
            self.setProperty("disabled", True)
        else:
            self.setSelectionMode(QtWidgets.QAbstractItemView.SelectionMode.ExtendedSelection)
            self.setFocusPolicy(QtCore.Qt.FocusPolicy.StrongFocus)
            self.setProperty("disabled", None)
        self.style().unpolish(self)
        self.style().polish(self)

        self._disabled = disabled

        if self._select_after_enabled:
            self.selectionModel().select(self._select_after_enabled,
                                         QtCore.QItemSelectionModel.SelectionFlag.ClearAndSelect)
            self.on_current_changed(self._select_after_enabled, QtCore.QModelIndex())
            self._select_after_enabled = None

    def disabled(self):
        """Get the disabled state of the list view."""
        return self._disabled

    def model(self) -> ArchiveFileModel:
        """
        Get the current model of the list view.

        :return: The current model, or None if not set.
        """
        return cast(ArchiveFileModel, super().model())

    def refresh_archive_file(self):
        """
        Set the archive to be displayed in the list.

        :param archive_file: The archive to display.
        """

        archive_file = get_archive_file()

        if archive_file is None:
            self.setModel(None)
        else:
            self.setModel(ArchiveFileModel(archive_file, self))
            self.selectionModel().currentChanged.connect(self.on_current_changed)

    def on_current_changed(self, current: QtCore.QModelIndex, previous: QtCore.QModelIndex):
        """
        Handle single-click on an item in the list.
        
        :param index: The model index that was clicked.
        """
        if self._disabled:
            self._select_after_enabled = current
            return

        archive_file = get_archive_file()

        if not self.model() or archive_file is None:
            return

        # Get the row index from the model index
        row_index = current.row()
        real_row = self.model().to_real_row(row_index)

        entry = archive_file.read_entry(real_row)

        self.preview_entry.emit(real_row, entry)

    def on_item_double_clicked(self, index: QtCore.QModelIndex):
        """
        Handle double-click on an item in the list.
        
        :param index: The model index that was double-clicked.
        """
        if self._disabled:
            return

        archive_file = get_archive_file()

        if not self.model() or archive_file is None:
            return

        # Get the row index from the model index
        row_index = index.row()
        real_row = self.model().to_real_row(row_index)

        entry = archive_file.read_entry(real_row)

        self.open_entry.emit(real_row, entry)

    def show_context_menu(self, position):
        """
        Show a context menu for selected items.
        
        :param position: Position where the context menu was requested.
        """
        archive_file = get_archive_file()

        if not self.model() or archive_file is None:
            return

        # Check if there are any selected items
        indexes = self.selectedIndexes()
        if not indexes:
            return

        menu = QtWidgets.QMenu(self)

        # Add extract option for any selection
        extract = menu.addAction("Extract")
        extract.triggered.connect(lambda: self.extract_entries(indexes))

        menu.addSeparator()
        for viewer in ALL_VIEWERS:
            viewer_action = menu.addAction("Open in " + get_viewer_display_name(viewer))
            viewer_action.triggered.connect(
                lambda _checked, v=viewer: self.open_entries_with(indexes, v)
            )

        if len(indexes) == 1:
            menu.addSeparator()
            rename = menu.addAction("Rename")
            rename.triggered.connect(lambda: self.show_rename_dialog(indexes[0]))

        # Show the context menu at the current position
        menu.exec(self.viewport().mapToGlobal(position))

    def open_entries_with(self, indexes: list[QtCore.QModelIndex], viewer: type):
        """
        Open the selected entry with the specified viewer.
        
        :param indexes: List of model indexes for the selected entries.
        :param viewer: The viewer class to use.
        """
        archive_file = get_archive_file()
        if archive_file is None:
            return
        for index in indexes:
            row = index.row()
            real_row = self.model().to_real_row(row)
            entry = archive_file.read_entry(real_row)
            self.open_entry_with.emit(real_row, entry, viewer)

    def extract_entries(self, indexes: list[QtCore.QModelIndex]):
        """
        Extract selected entries from the archive.
        
        :param indexes: List of model indexes for the selected entries.
        """
        archive_file = get_archive_file()
        if not self.model() or archive_file is None:
            return

        if len(indexes) == 1:
            # For single file, show file save dialog with filename pre-filled
            index = indexes[0]
            row_index = index.row()
            real_row = self.model().to_real_row(row_index)
            filename = self.model().get_filename(index)

            # Get the entry data
            entry = archive_file.read_entry(real_row)

            # Show save file dialog
            file_path, _ = QtWidgets.QFileDialog.getSaveFileName(
                self,
                "Extract File",
                filename,
                "All Files (*.*)"
            )

            if file_path:
                try:
                    with open(file_path, 'wb') as f:
                        f.write(entry.data)
                    QtWidgets.QMessageBox.information(
                        self,
                        "Success", 
                        f"File extracted to {file_path}"
                    )
                except Exception as e:
                    QtWidgets.QMessageBox.critical(
                        self,
                        "Error", 
                        f"Failed to extract file: {str(e)}"
                    )
        else:
            # For multiple files, show directory selection dialog
            dir_path = QtWidgets.QFileDialog.getExistingDirectory(
                self,
                "Select Directory to Extract Files",
                "",
                QtWidgets.QFileDialog.Option.ShowDirsOnly
            )

            if dir_path:
                try:
                    success_count = 0
                    fail_count = 0

                    for index in indexes:
                        row_index = index.row()
                        real_row = self.model().to_real_row(row_index)
                        filename = self.model().get_filename(index)

                        # Create safe filename
                        safe_filename = os.path.basename(filename)
                        if not safe_filename:
                            safe_filename = f"unknown_file_{real_row}"

                        file_path = os.path.join(dir_path, safe_filename)

                        # Get the entry data
                        entry = archive_file.read_entry(real_row)

                        try:
                            with open(file_path, 'wb') as f:
                                f.write(entry.data)
                            success_count += 1
                        except Exception:
                            fail_count += 1

                    message = f"Extracted {success_count} files to {dir_path}"
                    if fail_count > 0:
                        message += f"\n{fail_count} files failed to extract"

                    QtWidgets.QMessageBox.information(self, "Extraction Complete", message)
                except Exception as e:
                    QtWidgets.QMessageBox.critical(
                        self,
                        "Error",
                        f"Failed to extract files: {str(e)}"
                    )

    def show_rename_dialog(self, index: QtCore.QModelIndex):
        """
        Show a dialog to rename the selected file.
        
        :param index: The model index of the item to rename.
        """
        archive_file = get_archive_file()

        if not self.model() or archive_file is None:
            return

        real_row = self.model().to_real_row(index.row())
        entry_index = archive_file.indices[real_row]

        # Show input dialog to get new name
        new_name, ok = QtWidgets.QInputDialog.getText(
            self,
            "Rename File",
            f"Enter new name for {self.model().get_filename(index)}:",
            QtWidgets.QLineEdit.EchoMode.Normal,
            ""
        )

        if ok and new_name:
            app = cast(QtCore.QCoreApplication, QtWidgets.QApplication.instance())
            config: Config = app.property("game_config")
            config_manager = app.property("config_manager")
            settings_manager = app.property("settings_manager")
            config.entry_signature_name_map[hex(entry_index.file_signature)] = new_name
            save_config_manager_to_settings(config_manager, settings_manager)
            model = self.model()
            model.get_filename(index, invalidate_cache=True)
            self.update(model.index(index.row()))


# Backward-compatible alias
NPKFileList = ArchiveFileList


# Backward-compatible alias
NPKFileModel = ArchiveFileModel
