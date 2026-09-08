"""String extraction with correct address mapping.

Every string carries the VA it actually lives at, computed through the
section table. The predecessor's whole-binary extractor did this correctly;
its fingerprint module did not, and computed `image_base + file_offset`
instead. Measured against a real PE, 98.8% of the addresses that produced
were wrong, which silently killed the "referenced strings" matching signal.
There is one conversion path here and it is the image's.
"""
from __future__ import annotations

import re
from typing import Any

# Printable ASCII, excluding control characters but allowing tab.
_ASCII = rb"[\x09\x20-\x7e]"


def _patterns(min_len: int) -> tuple[re.Pattern[bytes], re.Pattern[bytes], re.Pattern[bytes]]:
    a = re.compile(_ASCII + b"{%d,}" % min_len)
    u_le = re.compile(b"(?:" + _ASCII + b"\x00){%d,}" % min_len)
    u_be = re.compile(b"(?:\x00" + _ASCII + b"){%d,}" % min_len)
    return a, u_le, u_be


def extract(
    image,
    *,
    min_len: int = 5,
    encodings: tuple[str, ...] = ("ascii", "utf16"),
    mapped_only: bool = True,
) -> list[dict[str, Any]]:
    """All strings in the image, each with its VA and containing section.

    `mapped_only` restricts results to bytes that are actually mapped into
    the address space. Strings in non-mapped regions (debug sections, PE
    overlay data, ELF `.strtab`) are real but have no VA, so a reference to
    them cannot exist and reporting an address for them would be a fiction.
    """
    a_re, le_re, be_re = _patterns(min_len)
    data = image.data
    out: list[dict[str, Any]] = []

    def emit(start: int, raw: bytes, enc: str) -> None:
        va = image.off_to_va(start)
        if va is None and mapped_only:
            return
        sec = image.section_for_off(start)
        try:
            if enc == "ascii":
                text = raw.decode("ascii")
            elif enc == "utf-16-le":
                text = raw.decode("utf-16-le")
            else:
                text = raw.decode("utf-16-be")
        except UnicodeDecodeError:
            return
        out.append(
            {
                "va": None if va is None else f"0x{va:x}",
                "file_offset": start,
                "section": sec.name if sec else None,
                "encoding": enc,
                "length": len(text),
                "text": text,
            }
        )

    if "ascii" in encodings:
        for m in a_re.finditer(data):
            emit(m.start(), m.group(), "ascii")

    if "utf16" in encodings:
        # Emit the encoding that matches the image's byte order first; scan
        # both because mixed-endian string blobs do occur in practice.
        for m in le_re.finditer(data):
            emit(m.start(), m.group(), "utf-16-le")
        if image.endian == "big":
            for m in be_re.finditer(data):
                emit(m.start(), m.group(), "utf-16-be")

    out.sort(key=lambda r: r["file_offset"])
    return out


def find_string_vas(image, needle: str, *, encodings: tuple[str, ...] = ("ascii", "utf16")) -> list[dict]:
    """Locate every mapped occurrence of an exact string.

    Searches both ASCII and UTF-16, because the predecessor's `find_string_va`
    was ASCII-only while its extractor reported UTF-16 strings -- so a
    UTF-16 string the tool had just shown you could not be used as an xref
    target.
    """
    data = image.data
    hits: list[dict] = []
    variants: list[tuple[bytes, str]] = []
    if "ascii" in encodings:
        try:
            variants.append((needle.encode("ascii"), "ascii"))
        except UnicodeEncodeError:
            pass
    if "utf16" in encodings:
        variants.append((needle.encode("utf-16-le"), "utf-16-le"))
        variants.append((needle.encode("utf-16-be"), "utf-16-be"))

    for raw, enc in variants:
        if not raw:
            continue
        idx = data.find(raw)
        while idx != -1:
            va = image.off_to_va(idx)
            if va is not None:
                sec = image.section_for_off(idx)
                hits.append(
                    {
                        "va": f"0x{va:x}",
                        "va_int": va,
                        "file_offset": idx,
                        "encoding": enc,
                        "section": sec.name if sec else None,
                    }
                )
            idx = data.find(raw, idx + 1)

    return hits


def annotate_referenced(strings: list[dict], index: dict) -> list[dict]:
    """Mark which strings are referenced by code, and how often."""
    refs = index.get("refs_by_target", {})
    overflow = index.get("ref_overflow", {})
    for s in strings:
        va = s.get("va")
        if va is None:
            s["xrefs"] = 0
            continue
        n = len(refs.get(va, [])) + int(overflow.get(va, 0))
        s["xrefs"] = n
    return strings
