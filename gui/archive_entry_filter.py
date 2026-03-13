"""Provides a filter for NPK entries in the NPK file list."""

from core.archive.enums import NPKEntryFileCategories
from core.archive.class_types import NPKEntryDataFlags
from gui.utils.archive import get_archive_file, ransack_agent
from gui.widgets.archive_file_list import ArchiveFileList

class ArchiveEntryFilter:
    """
    This class is used to filter NPK entries based on given conditions.
    """

    def __init__(self, list_view: ArchiveFileList):
        self._list_view = list_view
        self.filter_string = ""
        self.filter_type: NPKEntryFileCategories | None = None
        self.include_text = True
        self.include_binary = True

        self.mesh_biped_head = False

    def apply_filter(self):
        """
        Filters the NPK entries based on the filter string.

        :param npk_entries: List of NPK entries to be filtered.
        :return: Filtered list of NPK entries.
        """
        if self._list_view.disabled():
            return

        model = self._list_view.model()
        archive_file = get_archive_file()
        if not model or not archive_file:
            return

        for row in range(model.rowCount()):
            real_row = model.to_real_row(row)
            npk_entry = archive_file.read_entry(real_row)
            filename_lower = model.get_filename(model.index(row)).lower()

            if self.include_text == self.include_binary == False:
                # If both are unchecked, hide all
                self._list_view.setRowHidden(row, True)
                continue

            if self.include_text != self.include_binary:
                # If only one is checked, hide the other
                if self.include_text and not npk_entry.data_flags & NPKEntryDataFlags.TEXT or \
                     (self.include_binary and npk_entry.data_flags & NPKEntryDataFlags.TEXT):
                    self._list_view.setRowHidden(row, True)
                    continue

            # Text filter - quick reject
            if self.filter_string and self.filter_string not in filename_lower:
                self._list_view.setRowHidden(row, True)
                continue

            # Category filtering
            if self.filter_type is None:
                # No filter type set, show all
                show_item = True
            elif self.filter_type == npk_entry.category:
                if self.filter_type == NPKEntryFileCategories.MESH:
                    # Only do the expensive biped head check if needed
                    show_item = not self.mesh_biped_head or ransack_agent(npk_entry.data, "biped head")
                else:
                    show_item = True
            else:
                show_item = False

            # Apply visibility
            self._list_view.setRowHidden(row, not show_item)


# Backward-compatible alias
NPKEntryFilter = ArchiveEntryFilter
