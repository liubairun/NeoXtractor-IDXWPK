"""Enums used by the IDX+WPK archive reader."""
from enum import IntEnum, StrEnum

class NPKFileType(IntEnum):
    """Archive type enum kept for GUI compatibility."""
    SKPW = 0

    @classmethod
    def get_name(cls, flag: int) -> str:
        try:
            return cls(flag).name
        except ValueError:
            return f"UNKNOWN({flag})"

class CompressionType(IntEnum):
    """Stage-1 payload families in SKPW packages."""
    NONE = 0
    CA = 0x4341
    CP = 0x4350
    CX = 0x4358

    @classmethod
    def get_name(cls, flag: int) -> str:
        try:
            return cls(flag).name
        except ValueError:
            return f"UNKNOWN(0x{int(flag):04X})"

    @classmethod
    def _missing_(cls, value):
        if not isinstance(value, int):
            raise ValueError(f"Expected int, got {type(value).__name__}")
        obj = int.__new__(cls, int(value))
        obj._name_ = f"UNKNOWN(0x{value:04X})"
        obj._value_ = int(value)
        return obj

class DecryptionType(IntEnum):
    """Reserved for compatibility with the old GUI."""
    NONE = 0
    SKPW_STAGE1 = 1
    NXS3 = 2

    @classmethod
    def get_name(cls, flag: int) -> str:
        try:
            return cls(flag).name
        except ValueError:
            return f"UNKNOWN({flag})"

    @classmethod
    def _missing_(cls, value):
        if not isinstance(value, int):
            raise ValueError(f"Expected int, got {type(value).__name__}")
        obj = int.__new__(cls, int(value))
        obj._name_ = f"UNKNOWN({value})"
        obj._value_ = int(value)
        return obj

class NPKEntryFileCategories(StrEnum):
    """Categories used by the viewers and filters."""
    MESH = "Mesh"
    TEXTURE = "Texture"
    CHARACTER = "Character"
    SKIN = "Skin"
    OTHER = "Other"
