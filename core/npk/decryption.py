"""Provides decompression functions."""

from core.npk.enums import DecryptionType
from core.npk.class_types import NPKEntry, NPKEntryDataFlags
from core.logger import get_logger

def decrypt_entry(entry: NPKEntry, key: int | None = None) -> bytes:
    """
    Decrypts the data of an NPKEntry object based on its encryption type.
    Parameters:
        entry (NPKEntry): The entry containing the encrypted data and metadata.
        key (int | None, optional): The decryption key required for certain encryption types.
                                     Defaults to None.
    Returns:
        bytes: The decrypted data as a bytes object.
    Raises:
        ValueError: If the decryption key is required but not provided.
    Encryption Types:
        - BASIC_XOR: Performs a basic XOR decryption using a key array derived from the provided key.
                     Only the first 128 bytes (0x80) of the data are decrypted.
        - ADVANCED_XOR: Performs an advanced XOR decryption using a key array derived from the entry's
                        CRC and original file length. Decrypts a specific range of the data based on
                        the entry's metadata.
        - INCREMENTAL_XOR: Performs an incremental XOR decryption using a key derived from the entry's
                           CRC and original file length. Decrypts a specific range of the data with
                           an incrementing key.
    Notes:
        - The decryption process modifies the data in-place using a bytearray.
        - The decryption range and key generation depend on the entry's metadata, such as file length,
          original file length, and CRC.
    """

    # Convert data to bytearray for in-place modifications
    data = bytearray(entry.data)

    if entry.encrypt_flag == DecryptionType.BASIC_XOR:  # Basic XOR
        if key is None:
            get_logger().error("Decryption key is not set for file using 'BASIC XOR' decryption," + \
                               "did you use the correct config?")
            entry.data_flags |= NPKEntryDataFlags.ENCRYPTED
            return entry.data

        size = min(entry.file_length, 0x80)

        # Generate key array
        key_array = [(key + x) & 0xFF for x in range(0, 0x100)]

        # Apply XOR decryption
        for j in range(size):
            data[j] ^= key_array[j % 0xff]

    elif entry.encrypt_flag == DecryptionType.ADVANCED_XOR:  # Advanced XOR variants
        b = entry.crc ^ entry.file_original_length

        start = 0
        size = entry.file_length

        if size > 0x80:
            start = (entry.crc >> 1) % (size - 0x80)
            size = 2 * entry.file_original_length % 0x60 + 0x20

        # Generate key array
        key_array = [(x + b) & 0xFF for x in range(0, 0x81)]

        # Apply XOR decryption
        for j in range(size):
            data[start + j] ^= key_array[j % 0x80]

    elif entry.encrypt_flag == DecryptionType.INCREMENTAL_XOR:  # Incremental XOR
        v3 = int(entry.file_original_length)
        v4 = int(entry.crc)

        crc_key = (v3 ^ v4) & 0xff
        offset = 0
        length = 0

        if entry.file_length <= 0x80:
            length = entry.file_length
        else:
            offset = (v3 >> 1) % (entry.file_length - 0x80)
            length = ((v4 << 1) & 0xffffffff) % 0x60 + 0x20

        # Apply incremental XOR decryption
        for xx in range(offset, offset + length):
            data[xx] ^= crc_key
            crc_key = (crc_key + 1) & 0xff

    # Convert back to bytes
    return bytes(data)
