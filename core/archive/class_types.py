"""Archive entry type definitions for SKPW IDX+WPK packages."""

from dataclasses import dataclass
from enum import IntFlag, auto
import os
from .enums import CompressionType, DecryptionType, NPKEntryFileCategories

class NPKEntryDataFlags(IntFlag):
    NONE = 0
    TEXT = auto()
    NXS3_PACKED = auto()
    ROTOR_PACKED = auto()
    ENCRYPTED = auto()
    ERROR = auto()
    LOOSE_SOURCE = auto()

@dataclass
class NPKReadOptions:
    """Options kept largely for config compatibility."""
    decryption_key: int | None = None
    aes_key: bytes | None = None
    info_size: int | None = None
    validate_orig_size: bool = False

@dataclass
class NPKIndex:
    """Represents one IDX record."""
    filename: str = ""
    file_signature: int = 0
    file_offset: int = 0
    file_length: int = 0
    file_original_length: int = 0
    zcrc: int = 0
    crc: int = 0
    file_structure: bytes | None = None
    zip_flag: CompressionType = CompressionType.NONE
    encrypt_flag: DecryptionType = DecryptionType.NONE
    data_flags: NPKEntryDataFlags = NPKEntryDataFlags.NONE
    package_id: int = 0
    header_size: int = 0
    flags: int = 0
    hash16: bytes = b""
    payload_offset: int = 0

    def __repr__(self) -> str:
        return (
            f"NPKIndex(pkg={self.package_id}, offset=0x{self.file_offset:X}, "
            f"payload={self.file_length}, orig={self.file_original_length}, "
            f"tag={CompressionType.get_name(self.zip_flag)})"
        )

class NPKEntry(NPKIndex):
    def __init__(self):
        super().__init__()
        self.data: bytes = b""
        self.extension: str = ""
        self.category: NPKEntryFileCategories = NPKEntryFileCategories.OTHER
        self.stage1_tag: int = 0
        self.stage1_data: bytes | None = None
        self.stage2_data: bytes | None = None
        self.error_message: str | None = None
        self.source_path: str | None = None
        self.post_container: str | None = None

    @property
    def is_compressed(self) -> bool:
        return self.zip_flag != CompressionType.NONE

    @property
    def is_encrypted(self) -> bool:
        return self.encrypt_flag != DecryptionType.NONE

    def get_data(self) -> bytes:
        return self.data

    def save_to_file(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as f:
            f.write(self.data)
