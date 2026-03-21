"""NeoX BXML decoder."""
# Source / attribution:
# Original script provided by Discord user JohnSmith.
# Modified and integrated for this project.

from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from io import BytesIO
from xml.dom import minidom

from .base import FormatDecodeResult, FormatProcessor

BXML_MAGIC = b"\xC1\x59\x41\x0D"


def _read_leb128(buf: BytesIO) -> int:
    result = 0
    shift = 0
    while True:
        byte = buf.read(1)
        if not byte:
            break
        value = byte[0]
        result |= (value & 0x7F) << shift
        if (value & 0x80) == 0:
            break
        shift += 7
    return result


def _read_null_terminated_utf8(buf: BytesIO) -> str:
    chars = bytearray()
    while True:
        b = buf.read(1)
        if b == b"\x00" or not b:
            break
        chars.extend(b)
    return chars.decode("utf-8", errors="ignore")


def _read_string_pool(buf: BytesIO) -> list[str]:
    count = _read_leb128(buf)
    strings: list[str] = []
    for _ in range(count):
        strings.append(_read_null_terminated_utf8(buf))
    return strings


def _read_bxml_value(buf: BytesIO, type_tag: int) -> str:
    if type_tag == 0:
        return ""
    if type_tag == 1:
        return _read_null_terminated_utf8(buf)
    if type_tag in (2, 4):
        data = buf.read(4)
        if len(data) != 4:
            return ""
        return str(struct.unpack("<i", data)[0])
    if type_tag == 5:
        data = buf.read(4)
        if len(data) != 4:
            return ""
        return str(round(struct.unpack("<f", data)[0], 4))
    if type_tag == 3:
        data = buf.read(1)
        if len(data) != 1:
            return ""
        return str(struct.unpack("<B", data)[0])
    if type_tag == 6:
        data = buf.read(4)
        if len(data) != 4:
            return ""
        length = struct.unpack("<I", data)[0]
        float_data = buf.read(length * 4)
        if len(float_data) != length * 4:
            return float_data.hex()
        try:
            floats = struct.unpack("<" + "f" * length, float_data)
            return "[" + ", ".join(f"{round(v, 4)}" for v in floats) + "]"
        except Exception:
            return float_data.hex()
    if type_tag in (7, 8):
        data = buf.read(8)
        if len(data) != 8:
            return ""
        return str(struct.unpack("<q", data)[0])
    return ""


def parse_bxml_bytes(data: bytes) -> str:
    buf = BytesIO(data)
    magic = buf.read(4)
    if magic != BXML_MAGIC:
        raise ValueError("Not a valid NeoX BXML payload.")

    total_size_raw = buf.read(8)
    if len(total_size_raw) != 8:
        raise ValueError("Truncated BXML header.")
    _total_size = struct.unpack("<Q", total_size_raw)[0]
    payload_start = buf.tell()

    tag_names = _read_string_pool(buf)
    attr_names = _read_string_pool(buf)

    attr_data_offset_raw = buf.read(8)
    if len(attr_data_offset_raw) != 8:
        raise ValueError("Missing BXML attribute data offset.")
    attr_data_offset = struct.unpack("<Q", attr_data_offset_raw)[0]

    node_count = _read_leb128(buf)
    nodes_info: list[dict[str, object]] = []
    for i in range(node_count):
        tag_idx = _read_leb128(buf)
        child_count = _read_leb128(buf)
        tag_name = tag_names[tag_idx] if 0 <= tag_idx < len(tag_names) else f"node_{i}"
        nodes_info.append({"tag": tag_name, "child_count": child_count})

    buf.seek(payload_start + attr_data_offset)

    for i in range(node_count):
        attr_count = _read_leb128(buf)
        attrs: dict[str, str] = {}
        for j in range(attr_count):
            attr_idx = _read_leb128(buf)
            type_tag_raw = buf.read(1)
            if not type_tag_raw:
                raise ValueError("Unexpected end of file while reading BXML attributes.")
            type_tag = type_tag_raw[0]
            key = attr_names[attr_idx] if 0 <= attr_idx < len(attr_names) else f"attr_{j}"
            attrs[key] = _read_bxml_value(buf, type_tag)
        nodes_info[i]["attrs"] = attrs

        node_type_tag_raw = buf.read(1)
        if not node_type_tag_raw:
            raise ValueError("Unexpected end of file while reading BXML node value.")
        node_type_tag = node_type_tag_raw[0]
        nodes_info[i]["value"] = _read_bxml_value(buf, node_type_tag)

    current_node_idx = 0

    def build_xml_tree():
        nonlocal current_node_idx
        if current_node_idx >= len(nodes_info):
            return None

        info = nodes_info[current_node_idx]
        current_node_idx += 1

        elem = ET.Element(str(info["tag"]), info.get("attrs", {}))
        value = info.get("value")
        if value:
            elem.text = str(value)

        for _ in range(int(info.get("child_count", 0))):
            child = build_xml_tree()
            if child is not None:
                elem.append(child)
        return elem

    root = build_xml_tree()
    if root is None:
        raise ValueError("BXML contains no nodes.")

    xml_bytes = ET.tostring(root, encoding="utf-8")
    pretty_xml = minidom.parseString(xml_bytes).toprettyxml(indent="  ")
    lines = pretty_xml.split("\n")
    if lines and lines[0].startswith("<?xml"):
        pretty_xml = "\n".join(lines[1:]).lstrip("\n")
    return pretty_xml



class NeoXBXMLProcessor(FormatProcessor):
    name = "BXML"
    priority = 10

    def probe(self, data: bytes, entry) -> bool:
        return data[:4] == BXML_MAGIC

    def decode(self, data: bytes, entry) -> FormatDecodeResult | None:
        xml_text = parse_bxml_bytes(data)
        return FormatDecodeResult(
            data=xml_text,
            extension="xml",
            is_text=True,
            processor_name=self.name,
            metadata={"input_extension": getattr(entry, "extension", "")},
        )
