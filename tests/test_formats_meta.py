"""Tests for the managed-runtime format modules (JVM classfile, .NET dotnet).

Each blob is synthesized byte-for-byte so the tests run on any machine; the
two field-test targets (Starsector's obf jar, SMath's Solver.exe) are covered
by skipif-marked tests that run only where those files exist.
"""

from __future__ import annotations

import struct
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from remcp.errors import FormatError
from remcp.formats import classfile, dotnet


def _utf8(idx: int, text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack(">BH", 1, len(raw)) + raw


def _class(idx: int, name_idx: int) -> bytes:
    return struct.pack(">BH", 7, name_idx)


def build_minimal_class() -> bytes:
    """One class `Test` extends java/lang/Object with `static void main(String[])`.

    Pool layout is fixed so the long/double two-slot rule is exercised by
    build_class_after_long() below against the same parser.
    """
    cp = b""
    cp += _utf8(1, "Test")  # 1
    cp += _class(2, 1)  # 2 Class -> Test
    cp += _utf8(3, "java/lang/Object")  # 3
    cp += _class(4, 3)  # 4 Class -> Object
    cp += _utf8(5, "main")  # 5
    cp += _utf8(6, "([Ljava/lang/String;)V")  # 6
    cp += struct.pack(">BHH", 12, 5, 6)  # 7 NameAndType
    cp += _utf8(8, "Code")  # 8
    out = struct.pack(">IHH", 0xCAFEBABE, 0, 52)
    out += struct.pack(">H", 9) + cp
    out += struct.pack(">HHHH", 0x0021, 2, 4, 0)  # access, this, super, ifaces
    out += struct.pack(">H", 0)  # fields count
    out += struct.pack(">H", 1)  # methods count
    out += struct.pack(
        ">HHHHH", 0x0009, 5, 6, 1, 8
    )  # method: flags,name,desc,1 attr,"Code"
    out += struct.pack(">I", 0)  # attribute length 0
    out += struct.pack(">H", 0)  # class attributes
    return out


def build_class_after_long() -> bytes:
    """Class name index sits after a Long entry: the parser must skip slot 2."""
    cp = struct.pack(">Bq", 5, 1)  # 1: Long (occupies slots 1 and 2)
    cp += _utf8(3, "AfterLong")
    cp += _class(4, 3)
    out = struct.pack(">IHH", 0xCAFEBABE, 0, 52)
    out += struct.pack(">H", 5) + cp
    out += struct.pack(">HHHH", 0x0021, 4, 0, 0)
    out += struct.pack(">H", 0) + struct.pack(">H", 0) + struct.pack(">H", 0)
    return out


def test_parse_minimal_class():
    info = classfile.parse_class(build_minimal_class())
    assert info["class"] == "Test"
    assert info["super_class"] == "java/lang/Object"
    assert info["version"]["java"] == "8"
    assert len(info["methods"]) == 1
    m = info["methods"][0]
    assert m["name"] == "main"
    assert m["descriptor"] == "([Ljava/lang/String;)V"
    assert m["attributes"] == ["Code"]
    texts = [s["text"] for s in info["strings"]]
    assert "main" in texts and "java/lang/Object" in texts


def test_long_takes_two_pool_slots():
    info = classfile.parse_class(build_class_after_long())
    assert info["class"] == "AfterLong"


def test_truncated_class_is_refused():
    blob = build_minimal_class()[:-8]
    with pytest.raises(FormatError):
        classfile.parse_class(blob)


def test_unknown_pool_tag_is_refused():
    head = struct.pack(">IHH", 0xCAFEBABE, 0, 52)
    head += struct.pack(">H", 3) + struct.pack(">B", 99) + b"\x00" * 8
    with pytest.raises(FormatError):
        classfile.parse_class(head)


def test_scan_jar(tmp_path):
    jar = tmp_path / "t.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nCreated-By: test\n")
        zf.writestr("Test.class", build_minimal_class())
        zf.writestr("res/logo.png", b"\x89PNG fake")
    scan = classfile.scan_jar(jar, want_strings=True)
    assert scan["class_count"] == 1
    assert scan["resource_count"] == 1
    assert scan["manifest"]["Created-By"] == "test"
    assert scan["packages"] == [{"package": "", "classes": 1}]
    texts = [s["text"] for s in scan["strings"]]
    assert "java/lang/Object" in texts
    assert scan["unparsed"] == []


def test_scan_jar_records_corrupt_entries(tmp_path):
    jar = tmp_path / "bad.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("Broken.class", b"\xca\xfe\xba\xbe" + b"\xff" * 4)
    scan = classfile.scan_jar(jar)
    assert scan["class_count"] == 0
    assert len(scan["unparsed"]) == 1
    assert scan["unparsed"][0]["entry"] == "Broken.class"


# ---------------------------------------------------------------- .NET


def build_metadata_blob() -> bytes:
    strings_data = b"A\0B\0C\0"
    us_data = b"\x00" + b"\x05" + "hi".encode("utf-16-le") + b"\x00"
    tilde = (
        struct.pack("<I", 0)  # reserved
        + bytes([2, 0, 0, 0])  # major, minor, heapsizes, reserved
        + struct.pack("<Q", (1 << 0x00) | (1 << 0x02) | (1 << 0x04) | (1 << 0x06))
        + struct.pack("<Q", 0)  # sorted
        + struct.pack("<IIII", 1, 3, 7, 9)  # rows: Module, TypeDef, Field, MethodDef
    )
    version = b"v4.0.30319\x00"
    version = version + b"\x00" * ((4 - len(version) % 4) % 4)
    names = [b"#Strings\x00", b"#US\x00", b"#~\x00\x00"]

    def padded(n: bytes) -> bytes:
        return n + b"\x00" * ((4 - len(n) % 4) % 4)

    header_len = sum(8 + len(padded(n)) for n in names)
    base = 16 + len(version) + 4 + header_len
    blobs = [strings_data, us_data, tilde]
    stream_specs = []
    off = base
    for name, blob in zip(names, blobs):
        stream_specs.append((name, off, len(blob)))
        off += len(blob)
    header = b""
    for name, o, size in stream_specs:
        header += struct.pack("<II", o, size) + padded(name)
    root = b"BSJB" + struct.pack("<HHII", 1, 1, 0, len(version)) + version
    root += struct.pack("<HH", 0, 3) + header
    assert len(root) == base, (len(root), base)
    return root + strings_data + us_data + tilde


def test_metadata_root_streams():
    root = dotnet.parse_metadata_root(build_metadata_blob())
    assert root["version"] == "v4.0.30319"
    assert set(root["streams"]) == {"#Strings", "#US", "#~"}
    assert root["streams"]["#Strings"]["size"] == 6


def test_split_strings_heap():
    assert dotnet.split_strings_heap(b"A\0B\0C\0") == ["A", "B", "C"]


def test_split_us_heap_strips_flag_byte():
    heap = b"\x00" + b"\x05" + "hi".encode("utf-16-le") + b"\x00"
    assert dotnet.split_us_heap(heap) == ["hi"]


def test_table_row_counts():
    root = dotnet.parse_metadata_root(build_metadata_blob())
    tilde = build_metadata_blob()[root["streams"]["#~"]["offset"] :]
    counts = dotnet.table_row_counts(tilde)
    assert counts == {"Module": 1, "TypeDef": 3, "Field": 7, "MethodDef": 9}


def test_parse_cli_rejects_non_pe(tmp_path):
    jar = tmp_path / "t.jar"
    with zipfile.ZipFile(jar, "w") as zf:
        zf.writestr("x", b"y")
    with pytest.raises(FormatError):
        dotnet.parse_cli(jar)


# ------------------------------------------------- optional field targets

SMATH = Path(r"C:\Users\mnehm\AppData\Local\Programs\SMath Studio\Solver.exe")
STARFARER = Path(r"H:\01_Games\Starsector\starsector-core\starfarer_obf.jar")

smath = pytest.mark.skipif(not SMATH.exists(), reason="SMath Solver.exe not present")
starfarer = pytest.mark.skipif(
    not STARFARER.exists(), reason="starfarer_obf.jar not present"
)


@smath
def test_dotnet_on_real_assembly():
    info = dotnet.parse_cli(SMATH)
    assert info["clr_runtime_target"] == "2.5"
    assert info["identifier_count"] > 1000
    assert "SMath.Manager" in info["identifiers"]
    assert (
        "hello" in " ".join(info["user_strings"]).lower()
        or info["user_string_count"] > 100
    )
    assert info["table_rows"].get("TypeDef", 0) > 10
    assert info["table_rows"].get("MethodDef", 0) > info["table_rows"].get("TypeDef", 0)


@starfarer
def test_java_on_real_obf_jar():
    scan = classfile.scan_jar(STARFARER, want_strings=False)
    assert scan["class_count"] > 2500
    assert "yGuard" in " ".join(scan["manifest"].values())
    pkgs = {p["package"] for p in scan["packages"]}
    assert "com.fs.starfarer.loading.specs" in pkgs
    assert scan["manifest"].get("Created-By") == "yGuard Bytecode Obfuscator 4.1.0"
