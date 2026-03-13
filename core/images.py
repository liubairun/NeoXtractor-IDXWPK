"""Image conversion functions for various formats."""

# TODO: Code cleanup

import io
import math
from typing import cast
import texture2ddecoder
from PIL import Image, ImageFile
from bitstring import ConstBitStream

from core.binary_readers import read_uintle32, read_uintle64

#tga, ico, tiff, dds
def _pillow_image_conversion(data, fmt):
    return Image.open(io.BytesIO(data), "r", (fmt.upper(), "PNG"))

def image_to_png_data(img: Image.Image | ImageFile.ImageFile) -> bytes:
    """Convert an image to PNG data."""
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()

def _get_pitch(width):
    return max(1, ((width+3)//4) ) * 16

def _get_astc_file_size(width, height, block_x, block_y):
    return math.ceil(width/block_y) * math.ceil(height/block_x) * 16

def _decode_correct_format(fmt, data, width, height, block_x = 4, block_y = 4):
    match fmt:
        case "ASTC":
            data = texture2ddecoder.decode_astc(data, width, height, block_x, block_y)
        case "DXT1":
            data = texture2ddecoder.decode_bc1(data, width, height)
        case "DXT5":
            data = texture2ddecoder.decode_bc3(data, width, height)
        case "ETC2":
            data = texture2ddecoder.decode_etc2(data, width, height)
        case "ETC2A1":
            data = texture2ddecoder.decode_etc2a1(data, width, height)
        case "ETC2A8":
            data = texture2ddecoder.decode_etc2a8(data, width, height)
        case "PVRTC":
            data = texture2ddecoder.decode_pvrtc(data, width, height, False)
    return Image.frombytes("RGBA", (width, height), data, 'raw', ("BGRA"))

#this code was derived from TeaEffTeu's works and he slightly guided me, thank you very much for sharing!!
def compblks_convert(data):
    """Convert CompBlks to Image."""

    fmt = data[8:10]
    width = int.from_bytes(data[16:18], "little")
    height = int.from_bytes(data[18:20], "little")

    image_data = data[28:]
    if fmt == bytes([0xF3, 0x83]):
        return _decode_correct_format("DXT5", image_data, width, height)
    if fmt == bytes([0x78, 0x92]):
        return _decode_correct_format("ETC2A8", image_data, width, height)

def pvr_convert(data: bytes):
    """Convert PVR to Image."""

    f = ConstBitStream(io.BytesIO(data))
    f.read("pad64")
    pixel_format = read_uintle64(f)
    f.read("pad64")
    height, width, depth = f.readlist("3*uintle32")
    f.read("pad96")
    meta_data_size = read_uintle32(f)
    f.pos += meta_data_size * 8

    image_data = f.read("bytes")
    match pixel_format:
        case 3:
            return _decode_correct_format("PVRTC", image_data, width, height)
        case 7:
            return _decode_correct_format("DXT1", image_data, width, height)
        case 11:
            return _decode_correct_format("DXT5", image_data, width, height)
        case 27:
            return _decode_correct_format("ASTC", image_data, width, height, 4, 4)
        case 28:
            return _decode_correct_format("ASTC", image_data, width, height, 5, 4)
        case 29:
            return _decode_correct_format("ASTC", image_data, width, height, 5, 5)
        case 30:
            return _decode_correct_format("ASTC", image_data, width, height, 6, 5)
        case 31:
            return _decode_correct_format("ASTC", image_data, width, height, 6, 5)
        case 32:
            return _decode_correct_format("ASTC", image_data, width, height, 8, 5)
        case 33:
            return _decode_correct_format("ASTC", image_data, width, height, 8, 6)
        case 34:
            return _decode_correct_format("ASTC", image_data, width, height, 8, 8)
        case 35:
            return _decode_correct_format("ASTC", image_data, width, height, 10, 5)
        case 36:
            return _decode_correct_format("ASTC", image_data, width, height, 10, 6)
        case 37:
            return _decode_correct_format("ASTC", image_data, width, height, 10, 8)
        case 38:
            return _decode_correct_format("ASTC", image_data, width, height, 10, 10)
        case 39:
            return _decode_correct_format("ASTC", image_data, width, height, 12, 10)
        case 40:
            return _decode_correct_format("ASTC", image_data, width, height, 12, 12)
    raise ValueError(f"Unsupported PVR pixel format: {pixel_format}")

#https://registry.khronos.org/KTX/specs/1.0/ktxspec.v1.html
#https://github.com/KhronosGroup/KTX-Software/blob/main/lib/gl_format.h
def ktx_convert(data: bytes):
    """Convert KTX to Image."""
    f = ConstBitStream(io.BytesIO(data))
    f.read("pad224")
    glInternalFormat = read_uintle32(f)
    f.read("pad32")
    width, height = f.readlist("2*uintle32")
    f.read("pad128")
    bytesOfKeyValueData  = read_uintle32(f)
    f.read(f"pad{bytesOfKeyValueData*8}")
    image_size = read_uintle32(f)

    image_data = f.read(f"bytes{image_size}")
    match glInternalFormat:
        case 0x9274:
            return _decode_correct_format("ETC2", image_data, width, height)
        case 0x9276:
            return _decode_correct_format("ETC2A1", image_data, width, height)
        case 0x9278:
            return _decode_correct_format("ETC2A8", image_data, width, height)
        case 0x93B0:
            return _decode_correct_format("ASTC", image_data, width, height, 4, 4)
        case 0x93B1:
            return _decode_correct_format("ASTC", image_data, width, height, 5, 4)
        case 0x93B2:
            return _decode_correct_format("ASTC", image_data, width, height, 5, 5)
        case 0x93B3:
            return _decode_correct_format("ASTC", image_data, width, height, 6, 5)
        case 0x93B4:
            return _decode_correct_format("ASTC", image_data, width, height, 6, 5)
        case 0x93B5:
            return _decode_correct_format("ASTC", image_data, width, height, 8, 5)
        case 0x93B6:
            return _decode_correct_format("ASTC", image_data, width, height, 8, 6)
        case 0x93B7:
            return _decode_correct_format("ASTC", image_data, width, height, 8, 8)
        case 0x93B8:
            return _decode_correct_format("ASTC", image_data, width, height, 10, 5)
        case 0x93B9:
            return _decode_correct_format("ASTC", image_data, width, height, 10, 6)
        case 0x93BA:
            return _decode_correct_format("ASTC", image_data, width, height, 10, 8)
        case 0x93BB:
            return _decode_correct_format("ASTC", image_data, width, height, 10, 10)
        case 0x93BC:
            return _decode_correct_format("ASTC", image_data, width, height, 12, 10)
        case 0x93BD:
            return _decode_correct_format("ASTC", image_data, width, height, 12, 12)
    raise ValueError(f"Unknown KTX format: {glInternalFormat:#x}")

def astc_convert(data: bytes):
    """Convert ASTC to Image."""
    f = ConstBitStream(io.BytesIO(data))
    block_x, block_y = cast(tuple[int, int], f.readlist("pad32, 2*uintle8 , pad8"))
    width, height = f.readlist("2*uintle24, pad24")
    return _decode_correct_format("ASTC", f.read("bytes"), width, height, block_x, block_y)

def convert_image(data, extension):
    """Identify and convert image data to Image."""
    if extension == "dds":
        return _pillow_image_conversion(data, extension)
    if extension == "pvr":
        return pvr_convert(data)
    if extension in ("ktx", "ktx_low"):
        return ktx_convert(data)
    if extension == "astc":
        return astc_convert(data)
    if extension == "cbk":
        return compblks_convert(data)
    return None
