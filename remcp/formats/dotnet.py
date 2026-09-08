""".NET assembly metadata introspection.

First principle: a .NET assembly is a PE file whose payload is CLI metadata,
and CLI metadata is a directory of heaps -- #Strings holds every identifier,
#US holds every user-authored string, the #~ tables header holds exact row
counts. Nothing here needs disassembly or a VA space; the SMath field test
hand-rolled exactly this walk, and this module makes it a first-class
capability with the two layout bugs already fixed (stream headers are
offset-then-size-then-name, and the version string carries its own padding).

The parser is deliberately split into pure functions over bytes so the
metadata walk is unit-testable without a real assembly on disk.
"""

from __future__ import annotations

import struct
from pathlib import Path

from ..errors import FormatError

BSJB = b"BSJB"

# Analysis bounds.
MAX_IDENTIFIERS = 500_000
MAX_USER_STRINGS = 200_000

_TABLE_NAMES = {
    0x00: "Module",
    0x01: "TypeRef",
    0x02: "TypeDef",
    0x03: "FieldPtr",
    0x04: "Field",
    0x05: "MethodPtr",
    0x06: "MethodDef",
    0x07: "ParamPtr",
    0x08: "Param",
    0x09: "InterfaceImpl",
    0x0A: "MemberRef",
    0x0B: "Constant",
    0x0C: "CustomAttribute",
    0x0D: "FieldMarshal",
    0x0E: "DeclSecurity",
    0x0F: "ClassLayout",
    0x10: "FieldLayout",
    0x11: "StandAloneSig",
    0x12: "EventMap",
    0x13: "EventPtr",
    0x14: "Event",
    0x15: "PropertyMap",
    0x16: "PropertyPtr",
    0x17: "Property",
    0x18: "MethodSemantics",
    0x19: "MethodImpl",
    0x1A: "ModuleRef",
    0x1B: "TypeSpec",
    0x1C: "ImplMap",
    0x1D: "FieldRVA",
    0x1E: "EncLog",
    0x1F: "EncMap",
    0x20: "Assembly",
    0x21: "AssemblyProcessor",
    0x22: "AssemblyOS",
    0x23: "AssemblyRef",
    0x24: "AssemblyRefProcessor",
    0x25: "AssemblyRefOS",
    0x26: "File",
    0x27: "ExportedType",
    0x28: "ManifestResource",
    0x29: "NestedClass",
    0x2A: "GenericParam",
    0x2B: "MethodSpec",
    0x2C: "GenericParamConstraint",
}


def parse_metadata_root(meta: bytes) -> dict:
    """Parse the BSJB metadata root: version string + stream directory.

    Layout (ECMA-335 II.24.2.1): signature, version header, padded version
    string, flags, stream count, then per stream: offset, size, name padded
    to a 4-byte boundary. Offsets are relative to the start of the root.
    """
    if len(meta) < 16 or meta[:4] != BSJB:
        raise FormatError("metadata root does not start with the BSJB signature")
    ver_len = struct.unpack_from("<I", meta, 12)[0]
    if ver_len > 256:
        raise FormatError(f"metadata version length {ver_len} is not sane")
    version = (
        meta[16 : 16 + ver_len].split(b"\x00")[0].decode("ascii", errors="replace")
    )
    p = 16 + ((ver_len + 3) & ~3)
    if p + 4 > len(meta):
        raise FormatError("metadata root truncated before the stream count")
    _flags, nstreams = struct.unpack_from("<HH", meta, p)
    p += 4
    streams: dict[str, dict] = {}
    for _ in range(nstreams):
        if p + 8 > len(meta):
            raise FormatError("metadata root truncated inside a stream header")
        off, size = struct.unpack_from("<II", meta, p)
        nul = meta.find(b"\x00", p + 8)
        if nul == -1:
            raise FormatError("stream name is not null-terminated")
        name = meta[p + 8 : nul].decode("ascii", errors="replace")
        streams[name] = {"offset": off, "size": size}
        p = (nul + 1 + 3) & ~3
    return {"version": version, "streams": streams}


def split_strings_heap(heap: bytes, *, min_len: int = 1) -> list[str]:
    """#Strings: null-terminated UTF-8 identifiers."""
    out = [s.decode("utf-8", errors="replace") for s in heap.split(b"\x00")]
    return [s for s in out if len(s) >= min_len][:MAX_IDENTIFIERS]


def split_us_heap(heap: bytes) -> list[str]:
    """#US: compressed-length-prefixed UTF-16LE user strings.

    The last byte of each blob is a flag byte, not string data; it is kept out
    of the decoded text. A corrupt length never aborts the walk: the decoder
    resynchronizes one byte at a time.
    """
    out: list[str] = []
    i = 1  # byte 0 is the always-empty first entry
    n = len(heap)
    while i < n and len(out) < MAX_USER_STRINGS:
        b0 = heap[i]
        if b0 < 0x80:
            ln, adv = b0, 1
        elif b0 < 0xC0:
            if i + 1 >= n:
                break
            ln, adv = ((b0 & 0x3F) << 8) | heap[i + 1], 2
        else:
            if i + 3 >= n:
                break
            ln, adv = (
                ((b0 & 0x1F) << 24)
                | (heap[i + 1] << 16)
                | (heap[i + 2] << 8)
                | heap[i + 3],
                4,
            )
        if ln == 0 or ln > 1 << 22 or i + adv + ln > n:
            i += 1  # desynchronized; resync byte-by-byte
            continue
        body = heap[i + adv : i + adv + ln]
        if ln % 2 == 1:
            body = body[:-1]  # trailing flag byte
        out.append(body.decode("utf-16-le", errors="replace"))
        i += adv + ln
    return out


def table_row_counts(tilde: bytes) -> dict[str, int]:
    """Row counts per metadata table from the #~ header, without parsing rows.

    The tables header (ECMA-335 II.24.2.6) ends with one 4-byte row count for
    every set bit in the 64-bit Valid bitvector, ascending table id.
    """
    if len(tilde) < 24:
        raise FormatError("#~ stream too small to hold a tables header")
    valid = struct.unpack_from("<Q", tilde, 8)[0]
    p = 24
    out: dict[str, int] = {}
    for table_id in range(64):
        if not (valid >> table_id) & 1:
            continue
        if p + 4 > len(tilde):
            raise FormatError("#~ header truncated inside the row counts")
        rows = struct.unpack_from("<I", tilde, p)[0]
        p += 4
        out[_TABLE_NAMES.get(table_id, f"table_{table_id:#04x}")] = rows
    return out


def parse_cli(path: Path) -> dict:
    """Full CLI metadata inventory of a PE file. FormatError if not .NET."""
    import pefile

    try:
        pe = pefile.PE(str(path), fast_load=True)
    except pefile.PEFormatError as exc:
        raise FormatError(f"{path.name} is not a PE file: {exc}") from exc

    dir14 = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    if not dir14.VirtualAddress:
        raise FormatError(
            f"{path.name} has no CLI runtime header (data directory 14 is empty); "
            "it is a native PE, not a .NET assembly"
        )
    cor = pe.get_data(dir14.VirtualAddress, 72)
    (
        _cb,
        clr_major,
        clr_minor,
        meta_rva,
        meta_size,
        _flags,
        entry_token,
    ) = struct.unpack_from("<IHHIIII", cor, 0)
    if meta_rva == 0 or meta_size == 0:
        raise FormatError("CLI header names no metadata root; assembly is malformed")

    meta = pe.get_data(meta_rva, meta_size)
    root = parse_metadata_root(meta)

    identifiers: list[str] = []
    user_strings: list[str] = []
    tables: dict[str, int] = {}
    for name, spec in root["streams"].items():
        blob = meta[spec["offset"] : spec["offset"] + spec["size"]]
        if name == "#Strings":
            identifiers = split_strings_heap(blob, min_len=1)
        elif name == "#US":
            user_strings = split_us_heap(blob)
        elif name in ("#~", "#-"):
            try:
                tables = table_row_counts(blob)
            except FormatError:
                tables = {}

    machine = pe.FILE_HEADER.Machine
    entry_table = _TABLE_NAMES.get(entry_token >> 24, f"table_{entry_token >> 24:#04x}")
    return {
        "path": str(path),
        "name": path.name,
        "machine": "i386"
        if machine == 0x14C
        else ("amd64" if machine == 0x8664 else hex(machine)),
        "clr_runtime_target": f"{clr_major}.{clr_minor}",
        "metadata_version": root["version"],
        "entry_point": {
            "token": f"0x{entry_token:08X}",
            "table": entry_table,
            "row": entry_token & 0xFFFFFF,
        },
        "streams": {
            k: {"offset": v["offset"], "size": v["size"]}
            for k, v in root["streams"].items()
        },
        "identifier_count": len(identifiers),
        "user_string_count": len(user_strings),
        "table_rows": tables,
        "identifiers": identifiers,
        "user_strings": user_strings,
    }
