"""Read selected pointer slots and tables from the original PE without executing it."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

EXPECTED_SHA256 = "834300c2a85b6427de2d4a4be2931ff2ea59fd70f48f31754f5c2181753bd786"
parser = argparse.ArgumentParser()
parser.add_argument("--target", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
data = args.target.read_bytes()
digest = hashlib.sha256(data).hexdigest()
if digest != EXPECTED_SHA256:
    raise ValueError("Game.dll identity does not match the established case")
pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
    raise ValueError("Invalid PE signature")
section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
optional_offset = pe_offset + 24
if struct.unpack_from("<H", data, optional_offset)[0] != 0x20B:
    raise ValueError("Expected PE32+")
image_base = struct.unpack_from("<Q", data, optional_offset + 24)[0]
sections = []
for index in range(section_count):
    start = optional_offset + optional_size + index * 40
    virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, start + 8)
    if raw_offset + raw_size > len(data):
        raise ValueError("Section exceeds the file")
    sections.append({"name_raw_hex": data[start:start + 8].hex(), "rva": rva,
                     "raw_size": raw_size, "raw_offset": raw_offset, "virtual_size": virtual_size})


def mapped(rva, size):
    """Require a unique raw-backed mapping for the entire requested range."""
    matches = [s for s in sections if s["rva"] <= rva and rva + size <= s["rva"] + s["raw_size"]]
    if len(matches) != 1:
        raise ValueError(f"Non-unique or absent file backing at RVA {rva:#x}")
    section = matches[0]
    offset = section["raw_offset"] + rva - section["rva"]
    return section, offset


def observation(rva, size):
    """Return exact original bytes and both image and file locations."""
    section, offset = mapped(rva, size)
    return {"rva": hex(rva), "preferred_va": hex(image_base + rva),
            "file_offset": hex(offset), "length": size, "bytes_hex": data[offset:offset + size].hex(),
            "section_name_raw_hex": section["name_raw_hex"]}


def utf16_at(va):
    """Read a null-terminated UTF-16LE value within its observed raw section."""
    rva = va - image_base
    section, offset = mapped(rva, 2)
    end = section["raw_offset"] + section["raw_size"]
    stop = offset
    while stop + 2 <= end:
        if data[stop:stop + 2] == b"\x00\x00":
            return {**observation(rva, stop + 2 - offset), "text": data[offset:stop].decode("utf-16-le")}
        stop += 2
    raise ValueError("UTF-16 name has no terminator inside its raw section")


slot = observation(0x6BC748, 8)
slot["qword_value"] = hex(int.from_bytes(bytes.fromhex(slot["bytes_hex"]), "little"))
names = []
for index in range(6):
    entry = observation(0x846B50 + index * 16, 16)
    name_va, numeric_qword = struct.unpack("<QQ", bytes.fromhex(entry["bytes_hex"]))
    names.append({"index": index, "entry": entry, "name": utf16_at(name_va),
                  "value_qword": hex(numeric_qword), "returned_low32": numeric_qword & 0xFFFFFFFF})
registry_records = []
for rva in (0x937120, 0x937138, 0x937150):
    entry = observation(rva, 24)
    label_va, mask, associated_value = struct.unpack("<QQQ", bytes.fromhex(entry["bytes_hex"]))
    registry_records.append({"entry": entry, "label": utf16_at(label_va),
                             "mask": hex(mask), "associated_value": hex(associated_value)})
status_records = []
for index in range(7):
    entry = observation(0x937190 + index * 24, 24)
    label_va, lookup_key, associated_value = struct.unpack("<QQQ", bytes.fromhex(entry["bytes_hex"]))
    status_records.append({"index": index, "entry": entry, "label": utf16_at(label_va),
                           "lookup_key": hex(lookup_key), "associated_value": hex(associated_value)})
output = {"source_path": str(args.target.resolve()), "source_sha256": digest,
          "image_base": hex(image_base), "comparison_pointer_slot": slot,
          "counter_name_table": names, "registry_records": registry_records,
          "status_registration_table": status_records, "status_separator": utf16_at(image_base + 0x78F1CC),
          "provider": "auxiliary original-PE byte reader", "target_executed": False,
          "limitations": ["Original file pointer bytes do not establish a runtime-resolved import or comparison semantics.",
                          "Preferred image addresses are not observed process addresses."]}
with args.output.open("x", encoding="utf-8") as stream:
    json.dump(output, stream, ensure_ascii=False, indent=2)
print(json.dumps({"sha256": digest, "comparison_pointer_value": slot["qword_value"],
                  "names": [{"name": item["name"]["text"], "value": item["returned_low32"]} for item in names]}))
