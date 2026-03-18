"""NPK entry type definitions for the NPK file format."""

from dataclasses import dataclass
from enum import IntFlag, auto
import os
from .enums import CompressionType, DecryptionType, NPKEntryFileCategories

class NPKEntryDataFlags(IntFlag):
    """Flags for NPK entry data."""
    NONE = 0
    TEXT = auto()
    NXS3_PACKED = auto()
    ROTOR_PACKED = auto()
    ENCRYPTED = auto()
    ERROR = auto()

@dataclass
class NPKReadOptions:
    """Options for reading NPK files."""

    decryption_key: int | None = None
    aes_key: bytes | None = None
    info_size: int | None = None

@dataclass
class NPKIndex:
    """Represents an index entry in an NPK file."""

    filename = ""

    file_signature: int = 0
    file_offset: int = 0
    file_length: int = 0
    file_original_length: int = 0
    zcrc: int = 0  # compressed CRC
    crc: int = 0   # decompressed CRC
    file_structure: bytes | None = None
    zip_flag: CompressionType = CompressionType.NONE
    encrypt_flag: DecryptionType = DecryptionType.NONE

    data_flags = NPKEntryDataFlags.NONE

    def __repr__(self) -> str:
        return (
            f"NPKIndex(offset=0x{self.file_offset:X}, "
            f"length={self.file_length}, "
            f"orig_length={self.file_original_length}, "
            f"compression={CompressionType.get_name(self.zip_flag)}, "
            f"encryption={DecryptionType.get_name(self.encrypt_flag)})"
        )

class NPKEntry(NPKIndex):
    """Represents a file entry in an NPK file, including the actual file data."""

    def __init__(self):
        super().__init__()
        self.data: bytes = b""
        self.extension: str = ""
        self.category: NPKEntryFileCategories = NPKEntryFileCategories.OTHER

    @property
    def is_compressed(self) -> bool:
        """Check if the entry is compressed."""
        return self.zip_flag != 0

    @property
    def is_encrypted(self) -> bool:
        """Check if the entry is encrypted."""
        return self.encrypt_flag != 0

    def get_data(self) -> bytes:
        """Get the file data."""
        return self.data

    def save_to_file(self, path: str) -> None:
        """Save the file data to the specified path."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(self.data)

    def __repr__(self) -> str:
        return (
            f"NPKEntry(filename='{self.filename}', "
            f"length={self.file_length}, "
            f"compression={CompressionType.get_name(self.zip_flag)}, "
            f"encryption={DecryptionType.get_name(self.encrypt_flag)})"
        )
