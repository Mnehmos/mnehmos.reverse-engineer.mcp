"""Mach-O parsing onto the common Image model.

Hand-rolled against the documented load-command layout rather than delegated
to a helper library, because the only thing this layer must get exactly right
is the segment/section address mapping, and that is worth owning directly.
Fat/universal binaries are detected and refused with a clear message rather
than analyzed as whichever slice happens to be first.
"""
from __future__ import annotations

import struct
from pathlib import Path

from ..errors import FormatError, UnsupportedError
from ..image import Image, ImportRef, Section, Symbol

MH_MAGIC32 = 0xFEEDFACE
MH_MAGIC64 = 0xFEEDFACF
MH_CIGAM32 = 0xCEFAEDFE  # byte-swapped 32-bit
MH_CIGAM64 = 0xCFFAEDFE  # byte-swapped 64-bit
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA

LC_SEGMENT = 0x01
LC_SYMTAB = 0x02
LC_LOAD_DYLIB = 0x0C
LC_ID_DYLIB = 0x0D
LC_LOAD_WEAK_DYLIB = 0x18
LC_SEGMENT_64 = 0x19
LC_REEXPORT_DYLIB = 0x1F
LC_MAIN = 0x80000028

VM_PROT_READ = 0x1
VM_PROT_WRITE = 0x2
VM_PROT_EXECUTE = 0x4

CPU_ARCH_ABI64 = 0x01000000
CPU_TYPE_X86 = 7
CPU_TYPE_ARM = 12
CPU_TYPE_POWERPC = 18

MH_EXECUTE = 0x2
MH_DYLIB = 0x6
MH_BUNDLE = 0x8

N_TYPE = 0x0E
N_SECT = 0x0E
N_EXT = 0x01
N_STAB = 0xE0
N_UNDF = 0x00


def _cpu(cputype: int) -> tuple[str, int, str]:
    """cputype -> (arch, bits, note)."""
    is64 = bool(cputype & CPU_ARCH_ABI64)
    base = cputype & ~CPU_ARCH_ABI64
    bits = 64 if is64 else 32
    if base == CPU_TYPE_X86:
        return ("x86", bits, "x86_64" if is64 else "i386")
    if base == CPU_TYPE_ARM:
        return ("aarch64" if is64 else "arm", bits, "arm64" if is64 else "arm")
    if base == CPU_TYPE_POWERPC:
        return ("ppc", bits, "ppc64" if is64 else "ppc")
    return ("unknown", bits, f"cputype {cputype}")


class MachOImage(Image):
    fmt = "macho"

    def __init__(self, path: Path, data: bytes) -> None:
        super().__init__(path, data)
        if len(data) < 28:
            raise FormatError(f"{path.name} is too small to be Mach-O")

        magic = struct.unpack_from(">I", data, 0)[0]
        if magic in (FAT_MAGIC, FAT_CIGAM):
            raise UnsupportedError(
                f"{path.name} is a fat/universal Mach-O containing multiple "
                "architecture slices. Extract one slice first "
                "(`lipo -thin <arch>`) and analyze it directly -- analyzing "
                "an arbitrary slice would attribute results to the wrong "
                "architecture.",
                container="fat_macho",
            )

        le_magic = struct.unpack_from("<I", data, 0)[0]
        if le_magic == MH_MAGIC64:
            end, self.bits = "<", 64
        elif le_magic == MH_MAGIC32:
            end, self.bits = "<", 32
        elif le_magic == MH_CIGAM64:
            end, self.bits = ">", 64
        elif le_magic == MH_CIGAM32:
            end, self.bits = ">", 32
        else:
            raise FormatError(f"{path.name} has no Mach-O magic (got 0x{le_magic:08x})")

        self.endian = "little" if end == "<" else "big"
        self._end = end

        # mach_header[_64]: magic, cputype, cpusubtype, filetype, ncmds,
        # sizeofcmds, flags[, reserved]
        cputype, _cpusub, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(
            end + "iiIIII", data, 4
        )
        self.arch, bits_from_cpu, note = _cpu(cputype)
        if bits_from_cpu != self.bits:
            self.format_notes.append(
                f"magic says {self.bits}-bit but cputype says {bits_from_cpu}-bit; trusting magic"
            )
        self.format_notes.append(f"cputype 0x{cputype:08x} ({note}), filetype {filetype}")
        self.filetype = filetype
        self.is_library = filetype in (MH_DYLIB, MH_BUNDLE)

        hdr_size = 32 if self.bits == 64 else 28
        off = hdr_size
        self.dylibs: list[str] = []
        symtab: tuple[int, int, int, int] | None = None
        entry_off: int | None = None
        segments: list[tuple[int, int]] = []  # (vmaddr, fileoff) for LC_SEGMENT*

        for _ in range(ncmds):
            if off + 8 > len(data):
                self.format_notes.append("load command table truncated")
                break
            cmd, cmdsize = struct.unpack_from(end + "II", data, off)
            if cmdsize < 8 or off + cmdsize > len(data):
                self.format_notes.append(f"invalid load command size {cmdsize} at offset {off}")
                break

            if cmd in (LC_SEGMENT, LC_SEGMENT_64):
                self._read_segment(data, off, cmd, segments)
            elif cmd == LC_SYMTAB:
                symtab = struct.unpack_from(end + "IIII", data, off + 8)
            elif cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB):
                name_off = struct.unpack_from(end + "I", data, off + 8)[0]
                start = off + name_off
                if 0 < name_off < cmdsize and start < len(data):
                    raw = data[start : off + cmdsize].split(b"\x00", 1)[0]
                    self.dylibs.append(raw.decode("utf-8", "replace"))
            elif cmd == LC_MAIN:
                entry_off = struct.unpack_from(end + "Q", data, off + 8)[0]

            off += cmdsize

        # __TEXT's vmaddr is the image base for a Mach-O.
        text = [s for s in self.sections if s.name.startswith("__TEXT")]
        self.image_base = min((s.va for s in segments_vaddrs(segments)), default=0)
        if text:
            self.image_base = min(self.image_base or text[0].va, text[0].va)

        if entry_off is not None:
            self.entry_va = self.image_base + entry_off

        if symtab:
            self._read_symtab(data, *symtab)

        self.finalize()

    def _read_segment(self, data: bytes, off: int, cmd: int, segments: list) -> None:
        end = self._end
        wide = cmd == LC_SEGMENT_64
        # segment_command: cmd, cmdsize, segname[16], vmaddr, vmsize,
        # fileoff, filesize, maxprot, initprot, nsects, flags
        segname = data[off + 8 : off + 24].split(b"\x00", 1)[0].decode("utf-8", "replace")
        if wide:
            vmaddr, vmsize, fileoff, filesize, _maxprot, initprot, nsects, _flags = struct.unpack_from(
                end + "QQQQiiII", data, off + 24
            )
            sect_off = off + 24 + 48
            sect_size = 80
        else:
            vmaddr, vmsize, fileoff, filesize, _maxprot, initprot, nsects, _flags = struct.unpack_from(
                end + "IIIIiiII", data, off + 24
            )
            sect_off = off + 24 + 32
            sect_size = 68

        segments.append((vmaddr, fileoff))

        if nsects == 0:
            # A segment with no sections (e.g. __PAGEZERO, __LINKEDIT) still
            # occupies address space and must be mappable.
            self.sections.append(
                Section(
                    name=segname,
                    va=vmaddr,
                    vsize=vmsize,
                    fileoff=fileoff,
                    filesize=max(0, min(filesize, len(data) - fileoff)),
                    r=bool(initprot & VM_PROT_READ),
                    w=bool(initprot & VM_PROT_WRITE),
                    x=bool(initprot & VM_PROT_EXECUTE),
                )
            )
            return

        for i in range(nsects):
            so = sect_off + i * sect_size
            if so + sect_size > len(data):
                self.format_notes.append(f"section table truncated in segment {segname}")
                break
            sectname = data[so : so + 16].split(b"\x00", 1)[0].decode("utf-8", "replace")
            if wide:
                addr, size, foff = struct.unpack_from(end + "QQI", data, so + 32)
            else:
                addr, size, foff = struct.unpack_from(end + "III", data, so + 32)
            self.sections.append(
                Section(
                    name=f"{segname},{sectname}",
                    va=addr,
                    vsize=size,
                    fileoff=foff,
                    filesize=max(0, min(size, len(data) - foff)) if foff else 0,
                    r=bool(initprot & VM_PROT_READ),
                    w=bool(initprot & VM_PROT_WRITE),
                    x=bool(initprot & VM_PROT_EXECUTE),
                )
            )

    def _read_symtab(self, data: bytes, symoff: int, nsyms: int, stroff: int, strsize: int) -> None:
        end = self._end
        nlist_size = 16 if self.bits == 64 else 12
        strend = min(stroff + strsize, len(data))

        for i in range(nsyms):
            so = symoff + i * nlist_size
            if so + nlist_size > len(data):
                self.format_notes.append("symbol table truncated")
                break
            if self.bits == 64:
                n_strx, n_type, n_sect, _n_desc, n_value = struct.unpack_from(
                    end + "IBBHQ", data, so
                )
            else:
                n_strx, n_type, n_sect, _n_desc, n_value = struct.unpack_from(
                    end + "IBBhI", data, so
                )
            if n_type & N_STAB:  # debug symbol
                continue
            ns = stroff + n_strx
            if not (stroff <= ns < strend):
                continue
            name = data[ns:strend].split(b"\x00", 1)[0].decode("utf-8", "replace")
            if not name:
                continue

            if (n_type & N_TYPE) == N_UNDF:
                self.imports.append(ImportRef(library="", name=name, slot_va=None))
                continue
            if n_value == 0:
                continue

            sym = Symbol(name=name, va=n_value, kind="func", source="symtab")
            self.symbols.append(sym)
            if n_type & N_EXT:
                self.exports.append(
                    Symbol(name=name, va=n_value, kind="export", source="symtab")
                )

    def identity(self) -> dict:
        d = super().identity()
        d["filetype"] = self.filetype
        d["dylibs"] = self.dylibs
        return d


class _V:
    __slots__ = ("va",)

    def __init__(self, va: int) -> None:
        self.va = va


def segments_vaddrs(segments: list[tuple[int, int]]) -> list[_V]:
    """Nonzero segment virtual addresses, as objects with a `.va`.

    __PAGEZERO maps address 0 and must not be treated as the image base.
    """
    return [_V(v) for v, _f in segments if v]
