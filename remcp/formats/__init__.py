"""Container detection and loading.

First principle: detect the format from the bytes, never from the extension.
An extension is a claim by whoever named the file; the magic is evidence.
"""
from __future__ import annotations

import os
import struct
from pathlib import Path

from ..errors import FormatError, TargetError, UnsupportedError

# Hard ceiling so a mistyped path at a disk image cannot exhaust memory.
MAX_BYTES = int(os.environ.get("REMCP_MAX_FILE_BYTES", str(512 * 1024 * 1024)))

_ARCHIVE_MAGIC = {
    b"PK\x03\x04": "zip/jar/apk",
    b"\x1f\x8b": "gzip",
    b"BZh": "bzip2",
    b"\xfd7zXZ": "xz",
    b"!<arch>\n": "ar/static library",
    b"\x7fELF\x00": None,  # not real; keeps the table honest about ELF below
}


def sniff(data: bytes) -> str:
    """Return a format tag from the leading bytes."""
    if len(data) < 4:
        return "unknown"
    if data[:2] == b"MZ":
        # Follow e_lfanew to confirm a PE signature; an MZ with no PE header
        # is a DOS executable, which is a different thing.
        if len(data) >= 0x40:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if 0 < e_lfanew < len(data) - 4 and data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00":
                return "pe"
        return "dos_mz"
    if data[:4] == b"\x7fELF":
        return "elf"
    le = struct.unpack_from("<I", data, 0)[0]
    if le in (0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE):
        return "macho"
    be = struct.unpack_from(">I", data, 0)[0]
    if be in (0xCAFEBABE, 0xBEBAFECA) or le in (0xCAFEBABE, 0xBEBAFECA):
        # 0xCAFEBABE is ambiguous: Mach-O fat archive and Java class file.
        # Java class files carry a version pair right after the magic.
        return "macho_fat" if be == 0xCAFEBABE and len(data) >= 8 and struct.unpack_from(">I", data, 4)[0] < 64 else "java_class"
    if data[:8] == b"!<arch>\n":
        return "ar"
    if data[:4] == b"PK\x03\x04":
        return "zip"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    return "unknown"


def resolve_target(path_str: str) -> Path:
    """Validate a target path before any bytes are read."""
    if not path_str or not path_str.strip():
        raise TargetError("no target path given")
    p = Path(path_str).expanduser()
    try:
        p = p.resolve(strict=False)
    except OSError as exc:
        raise TargetError(f"cannot resolve path: {exc}", path=path_str) from exc
    if not p.exists():
        raise TargetError(f"not found: {p}", path=str(p))
    if p.is_dir():
        raise TargetError(f"path is a directory, not a binary: {p}", path=str(p))
    if not p.is_file():
        raise TargetError(f"not a regular file: {p}", path=str(p))
    size = p.stat().st_size
    if size == 0:
        raise TargetError(f"file is empty: {p}", path=str(p))
    if size > MAX_BYTES:
        raise TargetError(
            f"file is {size:,} bytes, over the {MAX_BYTES:,}-byte limit; "
            "raise REMCP_MAX_FILE_BYTES to override",
            path=str(p),
            size=size,
            limit=MAX_BYTES,
        )
    return p


def load(
    path_str: str,
    *,
    raw_arch: str | None = None,
    raw_bits: int | None = None,
    raw_endian: str = "little",
    raw_base: int = 0,
):
    """Load a target into an Image, dispatching on detected format.

    Passing raw_arch/raw_bits forces headerless interpretation, which is the
    only way to analyze firmware dumps and extracted code regions.
    """
    path = resolve_target(path_str)
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise TargetError(f"cannot read {path}: {exc}", path=str(path)) from exc

    if raw_arch is not None or raw_bits is not None:
        from .raw import RawImage

        if raw_arch is None or raw_bits is None:
            raise TargetError(
                "headerless analysis needs both raw_arch and raw_bits; "
                "nothing about a blob's architecture can be inferred safely"
            )
        return RawImage(
            path, data, arch=raw_arch, bits=raw_bits, endian=raw_endian, base_va=raw_base
        )

    kind = sniff(data)
    if kind == "pe":
        from .pe import PEImage

        return PEImage(path, data)
    if kind == "elf":
        from .elf import ELFImage

        return ELFImage(path, data)
    if kind in ("macho", "macho_fat"):
        from .macho import MachOImage

        return MachOImage(path, data)

    human = {
        "dos_mz": "a 16-bit DOS MZ executable with no PE header",
        "java_class": "a Java class file",
        "ar": "a static library archive (ar)",
        "zip": "a ZIP-based container (jar/apk/appx)",
        "gzip": "gzip-compressed data",
        "unknown": "an unrecognized container",
    }.get(kind, kind)
    hint = ""
    if kind == "java_class":
        hint = " Use the re_java tool for JVM class introspection."
    elif kind == "zip":
        hint = " If it is a jar, use the re_java tool for JVM introspection."
    raise UnsupportedError(
        f"{path.name} is {human}. Supported containers: PE, ELF, Mach-O. "
        "For firmware or extracted code, pass raw_arch and raw_bits to "
        "analyze it as a headerless blob." + hint,
        detected=kind,
        path=str(path),
    )
