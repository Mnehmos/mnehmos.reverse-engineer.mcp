"""ELF parsing onto the common Image model."""
from __future__ import annotations

import io
from pathlib import Path

from ..errors import FormatError
from ..image import Image, ImportRef, Section, Symbol

SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_WRITE = 0x1

# e_machine -> (arch, bits_hint, note). Bits come from the ELF class, not here.
MACHINE = {
    2: ("sparc", "SPARC"),
    3: ("x86", "Intel 80386"),
    8: ("mips", "MIPS"),
    20: ("ppc", "PowerPC"),
    21: ("ppc", "PowerPC 64"),
    40: ("arm", "ARM"),
    62: ("x86", "AMD x86-64"),
    183: ("aarch64", "AArch64"),
    243: ("riscv", "RISC-V"),
}


class ELFImage(Image):
    fmt = "elf"

    def __init__(self, path: Path, data: bytes) -> None:
        super().__init__(path, data)
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:  # pragma: no cover - dependency is declared
            raise FormatError("pyelftools is required to parse ELF images") from exc

        try:
            elf = ELFFile(io.BytesIO(data))
        except Exception as exc:
            raise FormatError(f"{path.name} does not parse as ELF: {exc}") from exc

        self.bits = 64 if elf.elfclass == 64 else 32
        self.endian = "little" if elf.little_endian else "big"

        em = elf.header["e_machine"]
        em_num = elf.header["e_machine"] if isinstance(em, int) else None
        # pyelftools gives symbolic names like 'EM_X86_64'; map both ways.
        symbolic = {
            "EM_386": ("x86", "Intel 80386"),
            "EM_X86_64": ("x86", "AMD x86-64"),
            "EM_ARM": ("arm", "ARM"),
            "EM_AARCH64": ("aarch64", "AArch64"),
            "EM_MIPS": ("mips", "MIPS"),
            "EM_PPC": ("ppc", "PowerPC"),
            "EM_PPC64": ("ppc", "PowerPC 64"),
            "EM_RISCV": ("riscv", "RISC-V"),
            "EM_SPARC": ("sparc", "SPARC"),
            "EM_SPARCV9": ("sparc", "SPARC v9"),
        }
        if isinstance(em, str) and em in symbolic:
            self.arch, note = symbolic[em]
        elif em_num is not None and em_num in MACHINE:
            self.arch, note = MACHINE[em_num]
        else:
            self.arch, note = "unknown", str(em)
        self.format_notes.append(f"e_machine {em} ({note})")

        etype = elf.header["e_type"]
        self.elf_type = str(etype)
        # ET_DYN covers both PIE executables and shared objects.
        self.is_library = str(etype) == "ET_DYN"

        # Image base: the lowest virtual address among loadable segments.
        # A PIE object reports 0 here, which is correct -- its VAs are
        # link-time addresses and the real base is chosen at load time.
        loads = [
            seg for seg in elf.iter_segments() if str(seg["p_type"]) == "PT_LOAD"
        ]
        self.image_base = min((int(s["p_vaddr"]) for s in loads), default=0)

        entry = int(elf.header["e_entry"])
        self.entry_va = entry or None

        for sec in elf.iter_sections():
            flags = int(sec["sh_flags"])
            # Only ALLOC sections occupy memory. Including .symtab or
            # .debug_* in the address index would let a file offset in a
            # non-mapped section translate to a bogus VA.
            if not flags & SHF_ALLOC:
                continue
            sh_type = str(sec["sh_type"])
            filesize = 0 if sh_type == "SHT_NOBITS" else int(sec["sh_size"])
            self.sections.append(
                Section(
                    name=sec.name or "",
                    va=int(sec["sh_addr"]),
                    vsize=int(sec["sh_size"]),
                    fileoff=int(sec["sh_offset"]),
                    filesize=max(0, min(filesize, len(data) - int(sec["sh_offset"]))),
                    r=True,
                    w=bool(flags & SHF_WRITE),
                    x=bool(flags & SHF_EXECINSTR),
                )
            )

        if not self.sections:
            # Stripped-section objects still have segments; fall back to them
            # so address translation keeps working.
            for i, seg in enumerate(loads):
                p_flags = int(seg["p_flags"])
                self.sections.append(
                    Section(
                        name=f"seg{i}",
                        va=int(seg["p_vaddr"]),
                        vsize=int(seg["p_memsz"]),
                        fileoff=int(seg["p_offset"]),
                        filesize=max(0, min(int(seg["p_filesz"]), len(data) - int(seg["p_offset"]))),
                        r=bool(p_flags & 0x4),
                        w=bool(p_flags & 0x2),
                        x=bool(p_flags & 0x1),
                    )
                )
            self.format_notes.append("no ALLOC sections; using PT_LOAD segments")

        self._read_symbols(elf)
        self.finalize()

    def _read_symbols(self, elf) -> None:
        from elftools.elf.sections import SymbolTableSection

        needed: list[str] = []
        for sec in elf.iter_sections():
            if str(sec["sh_type"]) == "SHT_DYNAMIC":
                try:
                    for tag in sec.iter_tags():
                        if str(tag["d_tag"]) == "DT_NEEDED":
                            needed.append(str(tag.needed))
                except Exception:
                    pass

        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection):
                continue
            is_dyn = sec.name == ".dynsym"
            for sym in sec.iter_symbols():
                name = sym.name
                if not name:
                    continue
                info = sym["st_info"]
                stype = str(info["type"])
                shndx = sym["st_shndx"]
                va = int(sym["st_value"])
                undefined = str(shndx) == "SHN_UNDEF" or shndx == 0

                if undefined and is_dyn and stype in ("STT_FUNC", "STT_NOTYPE"):
                    # An undefined dynamic symbol is an import. ELF does not
                    # bind it to a specific library in the symbol table, so
                    # the library is unknown unless versioning says otherwise.
                    self.imports.append(
                        ImportRef(
                            library=needed[0] if len(needed) == 1 else "",
                            name=name,
                            slot_va=None,
                        )
                    )
                    continue
                if undefined or va == 0:
                    continue

                kind = {"STT_FUNC": "func", "STT_OBJECT": "object"}.get(stype, "unknown")
                self.symbols.append(
                    Symbol(
                        name=name,
                        va=va,
                        size=int(sym["st_size"]),
                        kind=kind,
                        source="dynsym" if is_dyn else "symtab",
                    )
                )
                if is_dyn and str(info["bind"]) == "STB_GLOBAL" and kind == "func":
                    self.exports.append(
                        Symbol(name=name, va=va, size=int(sym["st_size"]), kind="export", source="dynsym")
                    )

        self.needed_libraries = needed

    def identity(self) -> dict:
        d = super().identity()
        d["elf_type"] = self.elf_type
        d["needed_libraries"] = getattr(self, "needed_libraries", [])
        return d
