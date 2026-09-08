"""The image abstraction: one address model, three spaces, no guessing.

First principle: an address is meaningless without the space it lives in.

Three spaces exist and they are not interchangeable:

  file offset  a byte index into the file on disk
  RVA          an offset from the image's load base, in the virtual layout
  VA           image_base + RVA, the address code actually references

The single most damaging bug class in the audited predecessor was silently
treating one as another. `fingerprint_functions.py:162` computed string VAs
as `image_base + file_offset`, which is only correct when a section's file
offset equals its virtual offset -- measured against a real binary, 98.8% of
the resulting addresses were wrong, and the "referenced strings" matching
signal built on them was dead.

The fix is structural, not a patch: raw arithmetic between spaces is not
available. Conversions go through the section table, they return None for
addresses that do not map, and callers must handle that.
"""
from __future__ import annotations

import bisect
import hashlib
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal

from .errors import AddressError

Arch = Literal["x86", "arm", "aarch64", "mips", "ppc", "riscv", "sparc", "unknown"]
Endian = Literal["little", "big"]


def shannon_entropy(data: bytes) -> float | None:
    """Byte-level Shannon entropy in bits/byte, or None for empty input."""
    if not data:
        return None
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


@dataclass
class Section:
    """One mapped region. `va` is absolute (image_base already applied)."""

    name: str
    va: int
    vsize: int
    fileoff: int
    filesize: int
    r: bool = True
    w: bool = False
    x: bool = False
    entropy: float | None = None

    @property
    def va_end(self) -> int:
        # Virtual size governs the address space; file size governs what is
        # actually readable from disk. A BSS-style section has vsize > filesize.
        return self.va + max(self.vsize, self.filesize)

    @property
    def file_end(self) -> int:
        return self.fileoff + self.filesize

    def perms(self) -> str:
        return ("r" if self.r else "-") + ("w" if self.w else "-") + ("x" if self.x else "-")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "va": f"0x{self.va:x}",
            "vsize": self.vsize,
            "fileoff": self.fileoff,
            "filesize": self.filesize,
            "perms": self.perms(),
            "entropy": None if self.entropy is None else round(self.entropy, 3),
        }


@dataclass
class Symbol:
    name: str
    va: int
    size: int = 0
    kind: str = "unknown"  # func | object | import | export | thunk
    source: str = ""       # symtab | export_table | import_table | heuristic

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "va": f"0x{self.va:x}",
            "size": self.size,
            "kind": self.kind,
            "source": self.source,
        }


@dataclass
class ImportRef:
    """An imported callable. `slot_va` is where the resolved pointer lands."""

    library: str
    name: str
    slot_va: int | None

    @property
    def qualified(self) -> str:
        lib = self.library.lower()
        if lib.endswith(".dll") or lib.endswith(".so") or ".so." in lib:
            lib = lib.rsplit(".so", 1)[0] if ".so" in lib else lib[:-4]
        return f"{lib}!{self.name}"

    def to_dict(self) -> dict:
        return {
            "library": self.library,
            "name": self.name,
            "qualified": self.qualified,
            "slot_va": None if self.slot_va is None else f"0x{self.slot_va:x}",
        }


class Image:
    """A parsed binary with an explicit, queryable address model.

    Subclasses fill in the fields; all address translation is implemented
    once, here, so no format-specific parser can get it wrong.
    """

    # --- populated by subclasses -------------------------------------------
    fmt: str = "unknown"
    arch: Arch = "unknown"
    bits: int = 0
    endian: Endian = "little"
    image_base: int = 0
    entry_va: int | None = None
    is_library: bool = False
    sections: list[Section]
    imports: list[ImportRef]
    exports: list[Symbol]
    symbols: list[Symbol]
    format_notes: list[str]

    def __init__(self, path: Path, data: bytes) -> None:
        self.path = path
        self.data = data
        self.sections = []
        self.imports = []
        self.exports = []
        self.symbols = []
        self.format_notes = []
        self._sha256: str | None = None
        self._va_index: list[tuple[int, int, Section]] = []
        self._off_index: list[tuple[int, int, Section]] = []
        # Precomputed bisect keys. Rebuilding these per lookup turned
        # `contains_va` into an O(sections) allocation, and the code index
        # calls it several times per decoded instruction -- measured at
        # millions of calls on a 16 MB image.
        self._va_keys: list[int] = []
        self._off_keys: list[int] = []

    # --- identity ----------------------------------------------------------

    @property
    def sha256(self) -> str:
        if self._sha256 is None:
            self._sha256 = hashlib.sha256(self.data).hexdigest()
        return self._sha256

    @property
    def size(self) -> int:
        return len(self.data)

    def identity(self) -> dict:
        """The content-addressed identity every result is keyed against."""
        return {
            "path": str(self.path),
            "name": self.path.name,
            "size": self.size,
            "sha256": self.sha256,
            "format": self.fmt,
            "arch": self.arch,
            "bits": self.bits,
            "endian": self.endian,
            "image_base": f"0x{self.image_base:x}",
            "entry_va": None if self.entry_va is None else f"0x{self.entry_va:x}",
            "is_library": self.is_library,
        }

    # --- index construction ------------------------------------------------

    def _build_indexes(self) -> None:
        """Sort sections into lookup tables for O(log n) translation."""
        va_pairs = sorted(
            ((s.va, s.va_end, s) for s in self.sections if s.va_end > s.va),
            key=lambda t: t[0],
        )
        off_pairs = sorted(
            ((s.fileoff, s.file_end, s) for s in self.sections if s.filesize > 0),
            key=lambda t: t[0],
        )
        self._va_index = list(va_pairs)
        self._off_index = list(off_pairs)
        self._va_keys = [t[0] for t in self._va_index]
        self._off_keys = [t[0] for t in self._off_index]

    def finalize(self) -> "Image":
        """Compute derived data once the subclass has populated sections."""
        for sec in self.sections:
            if sec.entropy is None and sec.filesize > 0:
                blob = self.data[sec.fileoff : sec.file_end]
                sec.entropy = shannon_entropy(blob)
        self._build_indexes()
        return self

    # --- address translation ----------------------------------------------

    def section_for_va(self, va: int) -> Section | None:
        idx = bisect.bisect_right(self._va_keys, va) - 1
        if idx < 0:
            return None
        lo, hi, sec = self._va_index[idx]
        return sec if lo <= va < hi else None

    def section_for_off(self, off: int) -> Section | None:
        idx = bisect.bisect_right(self._off_keys, off) - 1
        if idx < 0:
            return None
        lo, hi, sec = self._off_index[idx]
        return sec if lo <= off < hi else None

    def off_to_va(self, off: int) -> int | None:
        """File offset -> VA, or None if the offset is not mapped.

        Never `image_base + off`. That shortcut is the bug this method exists
        to make impossible.
        """
        sec = self.section_for_off(off)
        if sec is None:
            return None
        return sec.va + (off - sec.fileoff)

    def va_to_off(self, va: int) -> int | None:
        """VA -> file offset, or None if the VA has no bytes on disk.

        Returns None for addresses inside a section's virtual tail (BSS),
        which is a real condition callers must handle rather than read
        whatever bytes happen to follow.
        """
        sec = self.section_for_va(va)
        if sec is None:
            return None
        delta = va - sec.va
        if delta >= sec.filesize:
            return None
        return sec.fileoff + delta

    def va_to_rva(self, va: int) -> int:
        return va - self.image_base

    def rva_to_va(self, rva: int) -> int:
        return self.image_base + rva

    def contains_va(self, va: int) -> bool:
        return self.section_for_va(va) is not None

    def read_va(self, va: int, length: int) -> bytes | None:
        """Read `length` bytes at a VA, clipped to the containing section."""
        off = self.va_to_off(va)
        if off is None:
            return None
        sec = self.section_for_va(va)
        assert sec is not None
        avail = sec.file_end - off
        return self.data[off : off + min(length, max(avail, 0))]

    def require_va(self, va: int) -> Section:
        sec = self.section_for_va(va)
        if sec is None:
            raise AddressError(
                f"VA 0x{va:x} is not inside any mapped section of {self.path.name}",
                image_base=f"0x{self.image_base:x}",
                sections=[s.to_dict() for s in self.sections],
            )
        return sec

    # --- convenience -------------------------------------------------------

    # Entropy at or above this in an executable section means the bytes are
    # encrypted, packed or compressed, and decoding them yields noise.
    PACKED_ENTROPY = 7.5

    def exec_sections(self) -> list[Section]:
        return [s for s in self.sections if s.x and s.filesize > 0]

    def is_packed(self, sec: Section) -> bool:
        return bool(sec.x and sec.entropy is not None and sec.entropy >= self.PACKED_ENTROPY)

    def packed_exec_sections(self) -> list[Section]:
        return [s for s in self.exec_sections() if self.is_packed(s)]

    def analyzable_exec_sections(self) -> list[Section]:
        return [s for s in self.exec_sections() if not self.is_packed(s)]

    def data_sections(self) -> list[Section]:
        return [s for s in self.sections if not s.x and s.filesize > 0]

    def import_by_slot(self) -> dict[int, ImportRef]:
        return {i.slot_va: i for i in self.imports if i.slot_va is not None}

    def pointer_size(self) -> int:
        return max(self.bits // 8, 1)

    def unpack_pointer(self, blob: bytes, off: int) -> int | None:
        """Read a pointer-sized little/big-endian word out of `blob`."""
        n = self.pointer_size()
        if off < 0 or off + n > len(blob):
            return None
        return int.from_bytes(blob[off : off + n], self.endian)

    def known_symbol_vas(self) -> dict[int, Symbol]:
        out: dict[int, Symbol] = {}
        for group in (self.symbols, self.exports):
            for s in group:
                out.setdefault(s.va, s)
        return out

    def iter_code(self, *, include_packed: bool = False) -> Iterable[tuple[Section, bytes]]:
        """Executable sections worth decoding.

        Packed sections are excluded by default. Sweeping encrypted bytes on
        a real 16.5 MB image produced 5,080,489 "instructions", 385,328 jump
        edges and 47,240 indirect call sites in 394 seconds -- every one of
        them noise, because `.text` was CEG-encrypted at rest. Refusing that
        work by default is elimination; `include_packed` is the deliberate
        override for a caller who knows the section is really code.
        """
        secs = self.exec_sections() if include_packed else self.analyzable_exec_sections()
        for sec in secs:
            yield sec, self.data[sec.fileoff : sec.file_end]
