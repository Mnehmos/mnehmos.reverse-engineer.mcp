"""Raw / headerless blobs: firmware dumps, shellcode, extracted regions.

There is no header to trust, so the caller supplies the architecture and load
address. Nothing is inferred: a wrong guess here produces exactly the kind of
silent garbage this engine exists to refuse, so the parameters are required
rather than defaulted.
"""
from __future__ import annotations

from pathlib import Path

from ..image import Image, Section


class RawImage(Image):
    fmt = "raw"

    def __init__(
        self,
        path: Path,
        data: bytes,
        *,
        arch: str,
        bits: int,
        endian: str = "little",
        base_va: int = 0,
        executable: bool = True,
    ) -> None:
        super().__init__(path, data)
        self.arch = arch  # type: ignore[assignment]
        self.bits = bits
        self.endian = endian  # type: ignore[assignment]
        self.image_base = base_va
        self.entry_va = base_va if executable else None
        self.is_library = False
        self.format_notes.append(
            f"headerless blob; arch/bits/base supplied by caller "
            f"({arch}/{bits}/{endian} @ 0x{base_va:x})"
        )
        self.sections.append(
            Section(
                name="blob",
                va=base_va,
                vsize=len(data),
                fileoff=0,
                filesize=len(data),
                r=True,
                w=False,
                x=executable,
            )
        )
        self.finalize()
