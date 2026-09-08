"""Cross-references, from code operands and from data pointers.

First principle: a reference can come from anywhere that is mapped.

The predecessor scanned executable sections only. Vtables, relocation
targets, pointer tables, jump tables, RTTI descriptors and C++ virtual
dispatch tables all live in `.rdata`/`.data`, so for any C++ binary the most
interesting half of the reference graph was structurally invisible. Its
branch detection was also a raw byte hunt for `0xE8`/`0xE9`, which matches
those bytes wherever they appear inside an operand, and both scan loops
started at `find(..., 1)` so a match at offset 0 could never be found.

Two passes replace that:

  code    decoded operands from the cached code index -- immediates, memory
          displacements, PC-relative effective addresses, direct branches
  data    the target encoded as a pointer-width word, located anywhere in
          any mapped section, at any alignment
"""
from __future__ import annotations

from typing import Any


def _parse_int(text: str) -> int:
    t = text.strip().lower().replace("_", "")
    if t.startswith(("0x", "-0x")):
        return int(t, 16)
    if t.startswith("0b"):
        return int(t, 2)
    if t.startswith("0o"):
        return int(t, 8)
    # A bare hex-looking token is far more likely an address than a decimal.
    if any(c in "abcdef" for c in t.lstrip("-")):
        return int(t, 16)
    return int(t, 10)


def parse_va(text: str) -> int:
    return _parse_int(text)


def code_refs(index: dict, va: int) -> list[dict]:
    """References recorded by the decoded-operand pass."""
    key = f"0x{va:x}"
    out = []
    for site, kind in index.get("refs_by_target", {}).get(key, []):
        out.append({"site_va": site, "kind": kind, "via": "code_operand"})
    return out


def data_refs(image, va: int, *, limit: int = 2000) -> tuple[list[dict], int]:
    """Occurrences of `va` as a pointer-width word in any mapped section.

    Returns (references, total_found). Scans at every byte offset rather than
    only pointer-aligned ones: misaligned pointers are rare but real, and a
    substring search costs no more than an aligned stride.
    """
    n = image.pointer_size()
    order = "little" if image.endian == "little" else "big"
    try:
        needle = va.to_bytes(n, order)
    except OverflowError:
        return [], 0

    out: list[dict] = []
    total = 0
    for sec in image.sections:
        if sec.filesize <= 0:
            continue
        blob = image.data[sec.fileoff : sec.file_end]
        idx = blob.find(needle)
        while idx != -1:
            total += 1
            if len(out) < limit:
                site_va = sec.va + idx
                out.append(
                    {
                        "site_va": f"0x{site_va:x}",
                        "kind": f"ptr{n * 8}",
                        "via": "data_scan",
                        "section": sec.name,
                        "aligned": (site_va % n) == 0,
                        "executable_section": sec.x,
                    }
                )
            idx = blob.find(needle, idx + 1)
    return out, total


def xrefs_to(image, index: dict, va: int, *, limit: int = 2000) -> dict[str, Any]:
    """Every reference to one address, from both passes, with counts."""
    image.require_va(va)

    code = code_refs(index, va)
    overflow = int(index.get("ref_overflow", {}).get(f"0x{va:x}", 0))
    data, data_total = data_refs(image, va, limit=limit)

    sec = image.section_for_va(va)
    callers = [
        {"site_va": a, "target_va": b}
        for a, b in index.get("call_edges", [])
        if b == f"0x{va:x}"
    ]

    return {
        "target_va": f"0x{va:x}",
        "target_section": sec.name if sec else None,
        "target_is_code": bool(sec and sec.x),
        "code_refs": code,
        "code_ref_count": len(code) + overflow,
        "code_refs_clipped": overflow > 0,
        "data_refs": data,
        "data_ref_count": data_total,
        "data_refs_clipped": data_total > len(data),
        "direct_callers": callers,
        "total": len(code) + overflow + data_total,
    }


def xrefs_to_string(
    image, index: dict, needle: str, *, limit: int = 2000
) -> dict[str, Any]:
    """Resolve a string to its address(es), then report references to each."""
    from .strings import find_string_vas

    hits = find_string_vas(image, needle)
    if not hits:
        return {"string": needle, "found": False, "occurrences": [], "xrefs": []}

    results = []
    for h in hits:
        results.append(
            {"occurrence": h, "refs": xrefs_to(image, index, h["va_int"], limit=limit)}
        )
    return {
        "string": needle,
        "found": True,
        "occurrence_count": len(hits),
        "encodings": sorted({h["encoding"] for h in hits}),
        "xrefs": results,
    }
