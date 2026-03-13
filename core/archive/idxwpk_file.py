"""SKPW IDX + WPK archive reader."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Dict, List
from collections import defaultdict

from core.logger import get_logger
from .class_types import NPKEntry, NPKEntryDataFlags, NPKIndex, NPKReadOptions
from .decompression import (
    decode_payload_stage1,
    trim_none_prefix,
    unpack_nxs3,
    get_neox_rsa_pubkey,
    maybe_unpack_dtsz,
)
from .detection import get_ext, get_file_category, is_binary
from .enums import CompressionType, DecryptionType, NPKFileType

HEAD_SIZE = 32
REC_SIZE = 36


def _u16(data: bytes) -> int:
    return int.from_bytes(data, 'little')


def _u32(data: bytes) -> int:
    return int.from_bytes(data, 'little')


class IDXWPKFile:
    """Main archive class used by the GUI, now backed by SKPW idx+wpk."""

    def __init__(self, file_path: str, options: NPKReadOptions = NPKReadOptions()):
        self.file_path = str(file_path)
        self.entries: Dict[int, NPKEntry] = {}
        self.indices: List[NPKIndex] = []
        self.file_count: int = 0
        self.valid_file_count: int = 0
        self.error_file_count: int = 0
        self.visible_indices: List[int] = []
        self._visible_index_lookup: dict[int, int] = {}
        self.index_offset: int = HEAD_SIZE
        self.hash_mode: int = 0
        self.encrypt_mode: int = 0
        self.info_size: int = REC_SIZE
        self.options = options
        self.file_type = NPKFileType.SKPW
        self._base_path = Path(self.file_path).resolve().parent
        self._stem = Path(self.file_path).resolve().stem
        self._wpk_cache: dict[int, io.BufferedReader | None] = {}
        self._loose_file_cache: dict[str, bytes] = {}
        self._loose_dir_index: dict[Path, dict[str, list[Path]]] = {}
        self._entry_sources: dict[int, dict[str, object]] = {}
        self._rsa_key = get_neox_rsa_pubkey()
        get_logger().info('Opening IDX file: %s', self.file_path)
        with open(self.file_path, 'rb') as file:
            self._read_header(file)
            self._read_indices(file)
        self._prepare_entry_sources()
        self._compute_entry_stats()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False

    def close(self):
        for fh in self._wpk_cache.values():
            try:
                if fh:
                    fh.close()
            except Exception:
                pass
        self._wpk_cache.clear()

    def _read_header(self, file: io.BufferedReader) -> bool:
        raw = file.read(HEAD_SIZE)
        if len(raw) < HEAD_SIZE:
            raise ValueError(f'IDX too short: {self.file_path}')
        if raw[:4] != b'SKPW':
            raise ValueError(f'Not a valid SKPW idx file: {self.file_path}')
        self.file_count = _u32(raw[12:16])
        get_logger().info('Archive type: SKPW IDX+WPK')
        get_logger().info('IDX record count: %d', self.file_count)
        return True

    def _read_indices(self, file: io.BufferedReader) -> None:
        file.seek(HEAD_SIZE)
        raw = file.read(self.file_count * REC_SIZE)
        self.indices = []
        for i in range(self.file_count):
            rec = raw[i * REC_SIZE:(i + 1) * REC_SIZE]
            if len(rec) != REC_SIZE:
                raise ValueError(f'Incomplete IDX record #{i}')
            index = NPKIndex()
            index.hash16 = rec[0:16]
            index.file_signature = int.from_bytes(index.hash16, 'big', signed=False)
            index.file_original_length = _u32(rec[0x10:0x14])
            index.package_id = rec[0x14]
            index.file_offset = _u32(rec[0x18:0x1C])
            index.payload_offset = index.file_offset
            index.file_length = _u32(rec[0x1C:0x20])
            index.header_size = _u16(rec[0x20:0x22])
            index.flags = _u16(rec[0x22:0x24])
            index.filename = index.hash16.hex().lower()
            index.zip_flag = CompressionType.NONE
            index.encrypt_flag = DecryptionType.SKPW_STAGE1
            self.indices.append(index)

    def _prepare_entry_sources(self) -> None:
        """Phase 1: resolve where each entry blob should come from.

        We only determine the source here. Actual payload slicing/decoding happens later,
        after all entries have been assigned a source.
        """
        self._entry_sources.clear()
        loose_root = self._get_loose_root()
        for i, idx in enumerate(self.indices):
            if 0 <= idx.package_id <= 15:
                path = self._base_path / f'{self._stem}{idx.package_id}.wpk'
                self._entry_sources[i] = {
                    'source_type': 'wpk',
                    'path': path,
                    'package_id': idx.package_id,
                }
            else:
                loose_path = self._find_loose_path_from_index(idx, loose_root)
                self._entry_sources[i] = {
                    'source_type': 'loose',
                    'path': loose_path,
                    'package_id': idx.package_id,
                }


    def _probe_entry_readable(self, index: int) -> bool:
        if not 0 <= index < len(self.indices):
            return False
        idx = self.indices[index]
        source = self._entry_sources.get(index)
        if not source:
            return False

        source_type = source.get('source_type')
        if source_type == 'wpk':
            fh = self._get_wpk(idx.package_id)
            if fh is None:
                return False
            total = idx.header_size + idx.file_length
            fh.seek(0, 2)
            wpk_size = fh.tell()
            return idx.file_offset >= 0 and (idx.file_offset + total) <= wpk_size

        loose_path = source.get('path')
        return loose_path is not None and Path(loose_path).exists()

    def _compute_entry_stats(self) -> None:
        visible_indices: list[int] = []
        bad_indices: list[int] = []
        for i in range(len(self.indices)):
            if self._probe_entry_readable(i):
                visible_indices.append(i)
            else:
                bad_indices.append(i)

        self.visible_indices = visible_indices
        self._visible_index_lookup = {real_index: visible_row for visible_row, real_index in enumerate(visible_indices)}
        self.valid_file_count = len(visible_indices)
        self.error_file_count = len(bad_indices)

        get_logger().info('Readable entries: %d', self.valid_file_count)
        get_logger().info('Invalid entries: %d', self.error_file_count)
        if bad_indices:
            get_logger().debug('Invalid entry indices: %s', bad_indices)

    def get_visible_index(self, row: int) -> int:
        if not 0 <= row < len(self.visible_indices):
            raise IndexError(f'Visible row out of range: {row}')
        return self.visible_indices[row]

    def get_visible_row(self, index: int) -> int:
        return self._visible_index_lookup.get(index, -1)

    def _get_wpk(self, package_id: int):
        if package_id in self._wpk_cache:
            return self._wpk_cache[package_id]
        path = self._base_path / f'{self._stem}{package_id}.wpk'
        if not path.exists():
            get_logger().warning('Missing WPK for package %d: %s', package_id, path)
            self._wpk_cache[package_id] = None
            return None
        fh = path.open('rb')
        self._wpk_cache[package_id] = fh
        return fh

    def _get_loose_root(self) -> Path:
        return self._base_path / self._stem

    def _build_loose_dir_index(self, root: Path) -> dict[str, list[Path]]:
        index: dict[str, list[Path]] = defaultdict(list)
        if not root.exists() or not root.is_dir():
            return index
        for path in root.rglob('*'):
            if not path.is_file():
                continue
            name = path.name.lower()
            stem = path.stem.lower()
            index[name].append(path)
            if stem != name:
                index[stem].append(path)
        return index

    def _get_loose_dir_index(self, root: Path) -> dict[str, list[Path]]:
        if root not in self._loose_dir_index:
            self._loose_dir_index[root] = self._build_loose_dir_index(root)
        return self._loose_dir_index[root]

    def _find_loose_path_from_index(self, idx: NPKIndex, root: Path | None = None) -> Path | None:
        root = root or self._get_loose_root()
        if not root.exists() or not root.is_dir():
            return None

        hash_name = idx.hash16.hex().lower()
        index = self._get_loose_dir_index(root)
        candidates: list[Path] = []
        for key in (hash_name, idx.filename.lower() if idx.filename else ''):
            if key and key in index:
                candidates.extend(index[key])
        if not candidates:
            for key, paths in index.items():
                if key == hash_name or key.startswith(hash_name + '.'):
                    candidates.extend(paths)
        if not candidates:
            return None
        candidates = sorted({p.resolve() for p in candidates}, key=lambda x: (len(x.parts), len(x.name)))
        return candidates[0]

    def _finalize_entry_data(self, entry: NPKEntry, final_data: bytes) -> bool:
        entry.data = final_data
        if self.options.validate_orig_size and entry.file_original_length and len(final_data) != entry.file_original_length:
            get_logger().debug(
                'Length mismatch for %s: expected %d got %d',
                entry.filename,
                entry.file_original_length,
                len(final_data),
            )
        if not is_binary(entry.data):
            entry.data_flags |= NPKEntryDataFlags.TEXT
        entry.extension = get_ext(entry.data, entry.data_flags)
        entry.category = get_file_category(entry.extension)
        entry.filename = f'{entry.hash16.hex().lower()}.{entry.extension}'
        return True

    def _postprocess_final_data(self, data: bytes, entry: NPKEntry) -> bytes:
        final_data, codec = maybe_unpack_dtsz(data)
        if codec is not None:
            entry.post_container = codec
            if codec == 'oodl':
                get_logger().warning('OODL payload is not supported for %s', entry.filename)
            elif final_data is not data:
                get_logger().debug('Post-container unpacked for %s using %s', entry.filename, codec)
        return final_data

    def _decode_payload_bytes(self, payload: bytes, entry: NPKEntry) -> bool:
        def _looks_like_stage1(data: bytes) -> bool:
            return len(data) >= 8 and int.from_bytes(data[:2], 'little') in (0x4341, 0x4350, 0x4358)

        payload, fmt = trim_none_prefix(payload)
        if fmt is not None:
            entry.stage2_data = payload

        if payload[:8] == b'NXS3\x03\x00\x00\x01':
            entry.data_flags |= NPKEntryDataFlags.NXS3_PACKED
            try:
                final_data = unpack_nxs3(payload, self._rsa_key)
                final_data = self._postprocess_final_data(final_data, entry)
                entry.encrypt_flag = DecryptionType.NXS3
                return self._finalize_entry_data(entry, final_data)
            except Exception as exc:
                get_logger().warning('Direct NXS3 decrypt failed for %s: %s', entry.filename, exc)
                entry.data_flags |= NPKEntryDataFlags.ENCRYPTED
                return self._finalize_entry_data(entry, payload)

        if _looks_like_stage1(payload):
            stage1 = decode_payload_stage1(payload)
            if stage1 is not None:
                body_stage1, tag = stage1
                entry.stage1_tag = tag
                entry.stage1_data = body_stage1
                entry.zip_flag = CompressionType(tag)
                entry.encrypt_flag = DecryptionType.SKPW_STAGE1

                body_stage2, fmt = trim_none_prefix(body_stage1)
                entry.stage2_data = body_stage2
                final_data = body_stage2
                if body_stage2[:8] == b'NXS3\x03\x00\x00\x01':
                    entry.data_flags |= NPKEntryDataFlags.NXS3_PACKED
                    try:
                        final_data = unpack_nxs3(body_stage2, self._rsa_key)
                        final_data = self._postprocess_final_data(final_data, entry)
                        entry.encrypt_flag = DecryptionType.NXS3
                    except Exception as exc:
                        get_logger().warning('NXS3 decrypt failed for %s: %s', entry.filename, exc)
                        final_data = body_stage2
                        entry.data_flags |= NPKEntryDataFlags.ENCRYPTED
                final_data = self._postprocess_final_data(final_data, entry)
                return self._finalize_entry_data(entry, final_data)

        payload = self._postprocess_final_data(payload, entry)
        return self._finalize_entry_data(entry, payload)

    def _read_wpk_blob(self, entry: NPKEntry) -> bytes:
        fh = self._get_wpk(entry.package_id)
        if fh is None:
            raise FileNotFoundError(f'Missing WPK for package {entry.package_id}')
        total = entry.header_size + entry.file_length
        fh.seek(entry.file_offset)
        blob = fh.read(total)
        if len(blob) != total:
            raise EOFError(f'Unexpected EOF while reading entry blob (wanted {total}, got {len(blob)})')
        return blob

    def _read_loose_blob(self, entry: NPKEntry, path: Path) -> bytes:
        cache_key = str(path)
        if cache_key in self._loose_file_cache:
            return self._loose_file_cache[cache_key]
        blob = path.read_bytes()
        self._loose_file_cache[cache_key] = blob
        return blob

    def _split_payload_from_blob(self, blob: bytes, entry: NPKEntry) -> bytes:
        """Phase 2: slice the actual payload from an entry blob.

        Normal WPK records are read as ``header_size + file_length`` bytes and loose
        files are read as whole files. If the blob is a WPD1 container, prefer the
        container metadata. Otherwise fall back to IDX header_size/file_length.
        """
        if not blob:
            raise ValueError('Empty entry blob')

        if len(blob) >= 0x30 and blob[:4] == b'1DPW':
            body_size = _u32(blob[0x20:0x24])
            body_off = 0x30
            body_end = body_off + body_size if body_size > 0 else len(blob)
            if body_off < len(blob):
                return blob[body_off:min(body_end, len(blob))]

        start = entry.header_size
        end = start + entry.file_length if entry.file_length > 0 else len(blob)

        if len(blob) >= end:
            payload = blob[start:end]
        elif len(blob) == entry.file_length:
            payload = blob
        elif len(blob) > start:
            payload = blob[start:]
            if entry.file_length > 0:
                payload = payload[:entry.file_length]
        else:
            raise ValueError(
                f'Entry blob too small for header_size={entry.header_size}, '
                f'file_length={entry.file_length}, blob_len={len(blob)}'
            )

        if len(payload) == 0:
            raise ValueError('Payload empty after split')
        return payload

    def is_entry_loaded(self, index: int) -> bool:
        return index in self.entries

    def read_entry(self, index: int) -> NPKEntry:
        if index in self.entries:
            return self.entries[index]
        entry = NPKEntry()
        if not 0 <= index < len(self.indices):
            entry.data_flags |= NPKEntryDataFlags.ERROR
            entry.error_message = 'Entry index out of range'
            return entry
        idx = self.indices[index]
        for attr in vars(idx):
            setattr(entry, attr, getattr(idx, attr))
        try:
            self._load_entry_data(index, entry)
        except Exception as exc:
            get_logger().exception('Failed to load entry %d', index)
            entry.data_flags |= NPKEntryDataFlags.ERROR
            entry.error_message = str(exc)
            entry.data = b''
            entry.extension = 'error'
        self.entries[index] = entry
        return entry

    def _load_entry_data(self, index: int, entry: NPKEntry):
        source = self._entry_sources.get(index)
        if not source:
            raise ValueError('Entry source was not prepared')

        source_type = source['source_type']
        blob: bytes
        if source_type == 'wpk':
            blob = self._read_wpk_blob(entry)
        else:
            loose_path = source.get('path')
            if loose_path is None:
                raise FileNotFoundError(
                    f'Loose resource not found for package {entry.package_id} '
                    f'under {self._get_loose_root()}'
                )
            loose_path = Path(loose_path)
            entry.data_flags |= NPKEntryDataFlags.LOOSE_SOURCE
            entry.source_path = str(loose_path)
            blob = self._read_loose_blob(entry, loose_path)

        payload = self._split_payload_from_blob(blob, entry)
        return self._decode_payload_bytes(payload, entry)


# Backward-compatible alias
NPKFile = IDXWPKFile
