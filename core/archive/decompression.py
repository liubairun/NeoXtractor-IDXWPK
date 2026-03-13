"""Stage decoding helpers for SKPW IDX+WPK archives."""

import struct
from typing import cast

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from core.archive.class_types import NPKEntry

MAGIC_ZSTD = 0x5A535444
MAGIC_ZLIB = 0x5A4C4942
MAGIC_LZ4F = 0x4C5A3446
MAGIC_OODL = 0x4F4F444C
MAGIC_NONE = 0x4E4F4E45

def derive_key(length: int, t: int) -> bytes:
    v10 = (t + (length & 0xFFFFFFFF)) & 0xFF
    v28 = (
        0x7C2E6B6A00000000
        | (((length & 0xFFFFFFFF) << 8) & 0xFFFF0000)
        | (v10 << 8)
        | (length % 0xFD)
    )
    v29 = (
        0x5C74656E00003630
        | (((v10 ^ 0x33) << 16) & 0xFFFFFFFF00FFFFFF)
        | (((v10 | 0x2E) << 24))
    )
    return struct.pack('<QQ', v28 & 0xFFFFFFFFFFFFFFFF, v29 & 0xFFFFFFFFFFFFFFFF)

def aes_decrypt_prefix(buf: bytearray, nbytes: int, key16: bytes) -> int:
    if nbytes <= 0:
        return 0
    done = (nbytes // 16) * 16
    if done == 0:
        return 0
    cipher = Cipher(algorithms.AES(key16), modes.ECB(), backend=default_backend())
    dec = cipher.decryptor()
    buf[:done] = dec.update(bytes(buf[:done])) + dec.finalize()
    return done

def xor_offset(buf: bytearray, offset: int, want: int, seed: int):
    if want <= 0:
        return
    m = min(offset, want)
    for i in range(m):
        buf[offset + i] ^= ((seed + i) + buf[i]) & 0xFF
    for i in range(want - m):
        buf[offset + m + i] ^= (seed + m + i) & 0xFF

def xor_linear(buf: bytearray, want: int, seed: int):
    for i in range(want):
        buf[i] ^= (seed + i) & 0xFF

def header_decode(buf: bytearray):
    n = min(64, len(buf))
    if n <= 0:
        return
    i, j = 0, n - 1
    while i < j:
        bi = buf[i] ^ 0x5A
        bj = buf[j] ^ 0x5A
        buf[i] = bj
        buf[j] = bi
        i += 1
        j -= 1
    if i == j:
        buf[i] ^= 0x5A

def decode_payload_stage1(payload: bytes):
    if len(payload) < 8:
        return None
    tag = int.from_bytes(payload[0:2], 'little')
    p = payload[2]
    t = payload[3]
    body = bytearray(payload[8:])
    length = len(body)
    nbytes = 0
    if length > 0 and p != 0:
        nbytes = min(length, (128 << (p - 1)))
    seed = (t + length) & 0xFFFFFFFF
    if tag in (0x4341, 0x4350):
        key = derive_key(length, t)
        done = aes_decrypt_prefix(body, nbytes, key)
        want = max(0, nbytes - done)
        if want > 0:
            xor_offset(body, done, want, seed)
    elif tag == 0x4358:
        xor_linear(body, nbytes, seed)
    else:
        return None
    header_decode(body)
    return bytes(body), tag

def trim_none_prefix(data: bytes):
    """Strip the generic ENON wrapper if present.

    ENON is an outer prefix, not a payload type by itself. After removing it,
    callers should inspect the real content and decide whether it is NXS3,
    CA/CP/CX stage1 payload, or already-plain data.
    """
    if len(data) >= 4 and data[:4] == b'ENON':
        data = data[4:]
        if len(data) >= 8 and data[:8] == b'NXS3\x03\x00\x00\x01':
            return data, 'nxs3'
        return data, 'enon'
    return data, None

def _decompress_zstd(frame: bytes) -> bytes:
    import io
    import zstandard as zstd

    dctx = zstd.ZstdDecompressor()
    try:
        return dctx.decompress(frame)
    except zstd.ZstdError:
        chunks: list[bytes] = []
        with dctx.stream_reader(io.BytesIO(frame)) as rdr:
            while True:
                chunk = rdr.read(1 << 20)
                if not chunk:
                    break
                chunks.append(chunk)
        return b''.join(chunks)


def _decompress_zlib(frame: bytes) -> bytes:
    import zlib

    last_exc = None
    for wbits in (15, -15, 31):
        try:
            return zlib.decompress(frame, wbits)
        except zlib.error as exc:
            last_exc = exc
    raise RuntimeError(f'ZLIB decompress failed: {last_exc}')


def _decompress_lz4f(frame: bytes) -> bytes:
    import lz4.frame as lz4f

    return lz4f.decompress(frame)


def try_decompress_dtsz_or_none(buf: bytes) -> bytes:
    if len(buf) < 4:
        raise ValueError('Length too short for DTSZ-like tag')

    tag = int.from_bytes(buf[:4], 'little')
    frame = bytes(memoryview(buf)[4:])

    if tag == MAGIC_ZSTD:
        return _decompress_zstd(frame)
    if tag == MAGIC_ZLIB:
        return _decompress_zlib(frame)
    if tag == MAGIC_LZ4F:
        return _decompress_lz4f(frame)
    if tag == MAGIC_NONE:
        return frame
    if tag == MAGIC_OODL:
        raise RuntimeError('OODL/Oodle payload is not supported')
    raise RuntimeError(f'Unknown DTSZ-like tag 0x{tag:08X}')


def maybe_unpack_dtsz(data: bytes) -> tuple[bytes, str | None]:
    """Try the post-NXS3/cleartext compression wrapper used by many SKPW assets.

    Returns ``(decoded_data, codec_name)`` when a supported wrapper is found, otherwise
    returns ``(original_data, None)``. Unsupported wrappers such as OODL are preserved
    as-is so the GUI can still export them.
    """
    if len(data) < 4:
        return data, None

    tag = int.from_bytes(data[:4], 'little')
    if tag not in (MAGIC_ZSTD, MAGIC_ZLIB, MAGIC_LZ4F, MAGIC_NONE, MAGIC_OODL):
        return data, None

    codec_map = {
        MAGIC_ZSTD: 'zstd',
        MAGIC_ZLIB: 'zlib',
        MAGIC_LZ4F: 'lz4f',
        MAGIC_NONE: 'none',
        MAGIC_OODL: 'oodl',
    }
    codec = codec_map[tag]

    if tag == MAGIC_OODL:
        return data, codec

    try:
        return try_decompress_dtsz_or_none(data), codec
    except Exception:
        return data, codec


def check_nxs3(entry: NPKEntry) -> bool:
    return entry.data[:8] == b'NXS3\x03\x00\x00\x01'

def check_rotor(entry: NPKEntry) -> bool:
    return False

def unpack_rotor(data: bytes):
    return data

def rsa_public_decrypt(signature: bytes, key: rsa.RSAPublicKey) -> bytes:
    public_numbers = key.public_numbers()
    e = public_numbers.e
    n = public_numbers.n
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        raise ValueError('Signature length mismatch')
    sig_int = int.from_bytes(signature, byteorder='big')
    m_int = pow(sig_int, e, n)
    decrypted = m_int.to_bytes(k, byteorder='big')
    if len(decrypted) < 2 or decrypted[0] != 0x00 or decrypted[1] != 0x01:
        raise ValueError('Invalid PKCS#1 padding')
    try:
        padding_end = decrypted.index(0x00, 2)
    except ValueError as exc:
        raise ValueError('Padding end not found') from exc
    return decrypted[padding_end + 1:]

def get_neox_rsa_pubkey():
    pem_key = b"""-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAOZAaZe2qB7dpT9Y8WfZIdDv+ooS1HsFEDW2hFnnvcuFJ4vIuPgKhISm
pY4/jT3aipwPNVTjM6yHbzOLhrnGJh7Ec3CQG/FZu6VKoCqVEtCeh15hjcu6QYtn
YWIEf8qgkylqsOQ3IIn76udV6m0AWC2jDlmLeRcR04w9NNw7+9t9AgMBAAE=
-----END RSA PUBLIC KEY-----"""
    return cast(rsa.RSAPublicKey, serialization.load_pem_public_key(pem_key, backend=default_backend()))

def unpack_nxs3(data: bytes, rsa_key: rsa.RSAPublicKey | None = None) -> bytes:
    if len(data) < 148:
        raise ValueError('NXS3 data too short')
    if data[:8] != b'NXS3\x03\x00\x00\x01':
        raise ValueError('Not a valid NXS3 file')
    if rsa_key is None:
        rsa_key = get_neox_rsa_pubkey()
    wrapped_key = rsa_public_decrypt(data[20:148], rsa_key)[:4]
    if len(wrapped_key) < 4:
        raise ValueError('Wrapped key too short')
    ephemeral_key = int.from_bytes(wrapped_key, 'little')
    decrypted = bytearray()
    for i, x in enumerate(data[148:]):
        val = x ^ ((ephemeral_key >> ((i % 4) * 8)) & 0xFF)
        decrypted.append(val)
        if i % 4 == 3:
            ror = ((ephemeral_key >> 19) | ((ephemeral_key << (32 - 19)) & 0xFFFFFFFF)) & 0xFFFFFFFF
            ephemeral_key = (ror + ((ror << 2) & 0xFFFFFFFF) + 0xE6546B64) & 0xFFFFFFFF
    return bytes(decrypted)
