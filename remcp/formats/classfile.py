"""Java class file and jar introspection.

First principle: a JVM target is not a mystery blob. The constant pool of a
class file is a plaintext inventory of every name the code can reference, and
a jar is a directory of such inventories. The Starsector field test sniffed
starfarer_obf.jar as "zip" and the analysis had to leave the tool entirely --
these parsers close that gap without pretending a class file has a VA space:
there is no Image subclass here, no disassembly, no fabricated addresses.
Constant-pool indices are reported as indices, entry paths as entry paths.

Everything is bounds-checked; a truncated or corrupt entry raises FormatError
for single-class parses and is recorded per-entry (never silently dropped)
for jar scans.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

from ..errors import FormatError

MAGIC = 0xCAFEBABE

# Constant pool tags (JVMS table 4.4A). Unknown tags abort the parse: a wrong
# guess here desynchronizes the whole pool and every answer after it.
_TAGS = {
    1: "Utf8",
    3: "Integer",
    4: "Float",
    5: "Long",
    6: "Double",
    7: "Class",
    8: "String",
    9: "Fieldref",
    10: "Methodref",
    11: "InterfaceMethodref",
    12: "NameAndType",
    15: "MethodHandle",
    16: "MethodType",
    17: "Dynamic",
    18: "InvokeDynamic",
    19: "Module",
    20: "Package",
}

# Analysis bounds so a hostile or corrupt archive cannot exhaust memory.
MAX_ENTRIES = 200_000
MAX_CLASSES = 50_000
MAX_STRING_RESULTS = 50_000

_ACC_PUBLIC, _ACC_FINAL, _ACC_SUPER = 0x0001, 0x0010, 0x0020
_ACC_INTERFACE, _ACC_ABSTRACT = 0x0200, 0x0400
_ACC_SYNTHETIC, _ACC_ANNOTATION, _ACC_ENUM = 0x1000, 0x2000, 0x4000


class _Reader:
    """Big-endian cursor that refuses to read past the buffer."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def _need(self, n: int) -> None:
        if self.pos + n > len(self.data):
            raise FormatError(
                f"class file truncated at byte {self.pos}: needed {n} more bytes, "
                f"{len(self.data) - self.pos} remain"
            )

    def u1(self) -> int:
        self._need(1)
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u2(self) -> int:
        self._need(2)
        v = int.from_bytes(self.data[self.pos : self.pos + 2], "big")
        self.pos += 2
        return v

    def u4(self) -> int:
        self._need(4)
        v = int.from_bytes(self.data[self.pos : self.pos + 4], "big")
        self.pos += 4
        return v

    def bytes(self, n: int) -> bytes:
        self._need(n)
        v = self.data[self.pos : self.pos + n]
        self.pos += n
        return v

    def skip(self, n: int) -> None:
        if n < 0:
            raise FormatError(f"negative skip of {-n} bytes; pool is desynchronized")
        self._need(n)
        self.pos += n


def _class_flags(flags: int) -> list[str]:
    out = []
    for bit, name in (
        (_ACC_PUBLIC, "public"),
        (_ACC_FINAL, "final"),
        (_ACC_SUPER, "super"),
        (_ACC_INTERFACE, "interface"),
        (_ACC_ABSTRACT, "abstract"),
        (_ACC_SYNTHETIC, "synthetic"),
        (_ACC_ANNOTATION, "annotation"),
        (_ACC_ENUM, "enum"),
    ):
        if flags & bit:
            out.append(name)
    return out


class _Pool:
    """Parsed constant pool. Index 0 is unused by the format; long/double
    occupy two slots, which every index computation must respect."""

    def __init__(self, count: int) -> None:
        self.count = count
        self.entries: dict[int, dict] = {}
        self.utf8: dict[int, str] = {}

    def utf8_at(self, idx: int) -> str | None:
        return self.utf8.get(idx)

    def class_at(self, idx: int) -> str | None:
        e = self.entries.get(idx)
        if not e or e["tag"] != "Class":
            return None
        return self.utf8_at(e["name_index"])


def _parse_pool(r: _Reader) -> _Pool:
    count = r.u2()
    pool = _Pool(count)
    idx = 1
    while idx < count:
        tag = r.u1()
        name = _TAGS.get(tag)
        if name is None:
            raise FormatError(
                f"unknown constant pool tag {tag} at index {idx}; refusing to guess "
                "the layout of the remaining pool"
            )
        if name == "Utf8":
            length = r.u2()
            raw = r.bytes(length)
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:  # pragma: no cover - decode with replace cannot raise
                text = ""
            pool.utf8[idx] = text
            pool.entries[idx] = {"tag": name}
        elif name in ("Integer", "Float"):
            r.skip(4)
            pool.entries[idx] = {"tag": name}
        elif name in ("Long", "Double"):
            r.skip(8)
            pool.entries[idx] = {"tag": name}
            idx += 1  # 8-byte constants take two pool slots
        elif name == "Class":
            pool.entries[idx] = {"tag": name, "name_index": r.u2()}
        elif name == "String":
            pool.entries[idx] = {"tag": name, "string_index": r.u2()}
        elif name in ("Fieldref", "Methodref", "InterfaceMethodref"):
            pool.entries[idx] = {
                "tag": name,
                "class_index": r.u2(),
                "nat_index": r.u2(),
            }
        elif name == "NameAndType":
            pool.entries[idx] = {
                "tag": name,
                "name_index": r.u2(),
                "desc_index": r.u2(),
            }
        elif name == "MethodHandle":
            pool.entries[idx] = {"tag": name, "kind": r.u1(), "ref_index": r.u2()}
        elif name == "MethodType":
            pool.entries[idx] = {"tag": name, "desc_index": r.u2()}
        elif name in ("Dynamic", "InvokeDynamic"):
            pool.entries[idx] = {
                "tag": name,
                "bootstrap_index": r.u2(),
                "nat_index": r.u2(),
            }
        elif name in ("Module", "Package"):
            pool.entries[idx] = {"tag": name, "name_index": r.u2()}
        else:  # pragma: no cover - table covers all _TAGS values
            raise FormatError(f"unhandled tag {name}")
        idx += 1
    return pool


def _parse_members(r: _Reader, pool: _Pool, kind: str) -> list[dict]:
    out = []
    for _ in range(r.u2()):
        flags = r.u2()
        name = pool.utf8_at(r.u2()) or "?"
        desc = pool.utf8_at(r.u2()) or "?"
        attr_names = []
        for _ in range(r.u2()):
            attr_name = pool.utf8_at(r.u2()) or "?"
            r.skip(r.u4())
            attr_names.append(attr_name)
        out.append(
            {
                "kind": kind,
                "name": name,
                "descriptor": desc,
                "flags": flags,
                "attributes": attr_names,
            }
        )
    return out


def parse_class(data: bytes) -> dict:
    """Parse one class file's structure. Raises FormatError on anything that
    does not parse cleanly; no partial-guess fallback exists."""
    r = _Reader(data)
    if r.u4() != MAGIC:
        raise FormatError("not a Java class file: bad magic")
    minor = r.u2()
    major = r.u2()
    pool = _parse_pool(r)
    flags = r.u2()
    this_idx = r.u2()
    super_idx = r.u2()
    this_class = pool.class_at(this_idx)
    super_class = pool.class_at(super_idx) if super_idx else None
    interfaces = [pool.class_at(r.u2()) or "?" for _ in range(r.u2())]
    fields = _parse_members(r, pool, "field")
    methods = _parse_members(r, pool, "method")
    class_attrs = []
    for _ in range(r.u2()):
        attr_name = pool.utf8_at(r.u2()) or "?"
        r.skip(r.u4())
        class_attrs.append(attr_name)

    if this_class is None:
        raise FormatError(
            "this_class does not resolve to a Utf8 entry; pool is corrupt"
        )

    return {
        "class": this_class,
        "super_class": super_class,
        "interfaces": interfaces,
        "flags": flags,
        "flag_names": _class_flags(flags),
        "version": {"major": major, "minor": minor, "java": _java_version(major)},
        "fields": fields,
        "methods": methods,
        "class_attributes": class_attrs,
        "source_file": None,
        "cp_size": pool.count - 1,
        "cp_utf8_count": len(pool.utf8),
        "strings": [{"cp_index": i, "text": t} for i, t in sorted(pool.utf8.items())],
    }


def _java_version(major: int) -> str:
    known = {
        45: "1.1",
        46: "1.2",
        47: "1.3",
        48: "1.4",
        49: "5",
        50: "6",
        51: "7",
        52: "8",
        53: "9",
        54: "10",
        55: "11",
        56: "12",
        57: "13",
        58: "14",
        59: "15",
        60: "16",
        61: "17",
        62: "18",
        63: "19",
        64: "20",
        65: "21",
        66: "22",
        67: "23",
        68: "24",
        69: "25",
    }
    return known.get(major, f"major {major}")


def is_class_file(head: bytes) -> bool:
    return len(head) >= 4 and int.from_bytes(head[:4], "big") == MAGIC


def scan_jar(path: Path, *, want_strings: bool = False) -> dict:
    """Inventory a jar: class summaries, packages, manifest, unparsed entries.

    With want_strings, also collects every constant-pool Utf8 string with its
    source entry and pool index. This is the field-tested Starsector workflow.
    """
    try:
        zf = zipfile.ZipFile(str(path))
    except zipfile.BadZipFile as exc:
        raise FormatError(f"{path.name} is not a readable zip/jar: {exc}") from exc

    classes: list[dict] = []
    all_strings: list[dict] = []
    unparsed: list[dict] = []
    resources = 0
    manifest: dict[str, str] = {}
    truncated_entries = 0
    with zf:
        names = zf.namelist()
        if len(names) > MAX_ENTRIES:
            raise FormatError(
                f"jar has {len(names):,} entries, over the {MAX_ENTRIES:,} bound"
            )
        for name in names:
            if name.endswith("/"):
                continue
            try:
                data = zf.read(name)
            except Exception as exc:
                unparsed.append({"entry": name, "reason": f"unreadable: {exc}"})
                continue
            if name == "META-INF/MANIFEST.MF":
                manifest = _parse_manifest(data)
                continue
            if name.endswith(".class") and is_class_file(data[:4]):
                if len(classes) >= MAX_CLASSES:
                    truncated_entries += 1
                    continue
                try:
                    info = parse_class(data)
                except FormatError as exc:
                    unparsed.append({"entry": name, "reason": str(exc)})
                    continue
                pkg = (
                    info["class"].rsplit("/", 1)[0].replace("/", ".")
                    if "/" in info["class"]
                    else ""
                )
                classes.append(
                    {
                        "entry": name,
                        "class": info["class"],
                        "package": pkg,
                        "super_class": info["super_class"],
                        "interfaces": len(info["interfaces"]),
                        "fields": len(info["fields"]),
                        "methods": len(info["methods"]),
                        "flag_names": info["flag_names"],
                        "java": info["version"]["java"],
                    }
                )
                if want_strings:
                    for s in info["strings"]:
                        if len(all_strings) < MAX_STRING_RESULTS:
                            all_strings.append(
                                {
                                    "entry": name,
                                    "cp_index": s["cp_index"],
                                    "text": s["text"],
                                }
                            )
                        else:
                            truncated_entries += 1
                            break
            else:
                resources += 1

    packages: dict[str, int] = {}
    for c in classes:
        packages[c["package"]] = packages.get(c["package"], 0) + 1
    return {
        "entry_count": len(names),
        "class_count": len(classes),
        "resource_count": resources,
        "manifest": manifest,
        "classes": classes,
        "packages": sorted(
            ({"package": k, "classes": v} for k, v in packages.items()),
            key=lambda p: -p["classes"],
        ),
        "unparsed": unparsed,
        "strings": all_strings,
        "truncated": truncated_entries,
    }


def _parse_manifest(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in data.decode("utf-8", errors="replace").splitlines():
        if ": " in line:
            k, v = line.split(": ", 1)
            out[k] = v
    return out


def filter_strings(strings: list[dict], pattern: str, limit: int) -> list[dict]:
    if not pattern:
        return strings[:limit]
    rx = re.compile(pattern, re.IGNORECASE)
    out = []
    for s in strings:
        if rx.search(s["text"]):
            out.append(s)
            if len(out) >= limit:
                break
    return out


def resolve(path_str: str) -> Path:
    """Validate a JVM target: an existing .class file or a zip-based jar."""
    from . import resolve_target

    p = resolve_target(path_str)
    return p
