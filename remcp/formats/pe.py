"""PE/COFF parsing onto the common Image model."""
from __future__ import annotations

from pathlib import Path

from ..errors import FormatError
from ..image import Image, ImportRef, Section, Symbol

SCN_EXECUTE = 0x20000000
SCN_READ = 0x40000000
SCN_WRITE = 0x80000000
CHAR_DLL = 0x2000

# machine -> (arch, bits, endian, note)
MACHINE = {
    0x014C: ("x86", 32, "little", "i386"),
    0x8664: ("x86", 64, "little", "AMD64"),
    0x01C0: ("arm", 32, "little", "ARM (little-endian)"),
    0x01C2: ("arm", 32, "little", "ARM Thumb-2 / THUMB"),
    0x01C4: ("arm", 32, "little", "ARMNT (Thumb-2)"),
    0xAA64: ("aarch64", 64, "little", "ARM64"),
    0x0166: ("mips", 32, "little", "MIPS little-endian"),
    0x0266: ("mips", 32, "little", "MIPS16"),
    0x01F0: ("ppc", 32, "little", "PowerPC"),
    0x01F1: ("ppc", 32, "little", "PowerPC with FPU"),
    0x0200: ("unknown", 64, "little", "Intel Itanium (IA-64)"),
    0x5032: ("riscv", 32, "little", "RISC-V 32"),
    0x5064: ("riscv", 64, "little", "RISC-V 64"),
}


class PEImage(Image):
    fmt = "pe"

    def __init__(self, path: Path, data: bytes) -> None:
        super().__init__(path, data)
        import pefile

        try:
            pe = pefile.PE(data=data, fast_load=True)
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
                ]
            )
        except Exception as exc:  # pefile raises PEFormatError and friends
            raise FormatError(f"{path.name} does not parse as PE: {exc}") from exc

        self._pe = pe
        oh = pe.OPTIONAL_HEADER
        fh = pe.FILE_HEADER

        machine = fh.Machine
        if machine in MACHINE:
            self.arch, self.bits, self.endian, note = MACHINE[machine]
            self.format_notes.append(f"machine 0x{machine:04x} ({note})")
        else:
            self.arch, self.bits, self.endian = "unknown", 0, "little"
            self.format_notes.append(f"unrecognized machine type 0x{machine:04x}")

        self.image_base = int(oh.ImageBase)
        self.is_library = bool(fh.Characteristics & CHAR_DLL)
        self.entry_va = (
            self.image_base + oh.AddressOfEntryPoint if oh.AddressOfEntryPoint else None
        )
        self.timestamp = int(fh.TimeDateStamp)
        self.subsystem = int(oh.Subsystem)
        self.has_tls = hasattr(pe, "DIRECTORY_ENTRY_TLS")

        for s in pe.sections:
            name = s.Name.rstrip(b"\x00").decode("utf-8", "replace")
            ch = s.Characteristics
            self.sections.append(
                Section(
                    name=name,
                    va=self.image_base + s.VirtualAddress,
                    vsize=int(s.Misc_VirtualSize),
                    fileoff=int(s.PointerToRawData),
                    # SizeOfRawData can exceed the file for malformed images.
                    filesize=max(0, min(int(s.SizeOfRawData), len(data) - int(s.PointerToRawData))),
                    r=bool(ch & SCN_READ),
                    w=bool(ch & SCN_WRITE),
                    x=bool(ch & SCN_EXECUTE),
                )
            )

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                lib = (entry.dll or b"").decode("utf-8", "replace")
                for imp in entry.imports:
                    nm = (
                        imp.name.decode("utf-8", "replace")
                        if imp.name
                        else f"ord#{imp.ordinal}"
                    )
                    self.imports.append(
                        ImportRef(library=lib, name=nm, slot_va=int(imp.address) if imp.address else None)
                    )

        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                nm = (
                    exp.name.decode("utf-8", "replace")
                    if exp.name
                    else f"ord#{exp.ordinal}"
                )
                if exp.address:
                    self.exports.append(
                        Symbol(
                            name=nm,
                            va=self.image_base + int(exp.address),
                            kind="export",
                            source="export_table",
                        )
                    )

        self.finalize()

    def identity(self) -> dict:
        d = super().identity()
        d["pe_timestamp"] = f"0x{self.timestamp:08x}"
        d["subsystem"] = self.subsystem
        d["has_tls"] = self.has_tls
        return d
