"""Disassembly: architecture derived from the image, never assumed.

First principle: decode with the architecture the header declares, or refuse.

The audited predecessor hardcoded `Cs(CS_ARCH_X86, CS_MODE_32)` in two places
and `-processor x86:LE:32:default` in a third. Feeding it a 64-bit PE produced
1,187 fabricated call edges and zero warnings, even though the inspector one
call earlier correctly printed "AMD64 (64-bit x64)". The capability check
existed and nothing consulted it.
"""
from __future__ import annotations

from typing import Iterator

import capstone as cs

from .errors import UnsupportedError

# (arch, bits, endian) -> (capstone arch, capstone mode, human label)
_TABLE: dict[tuple[str, int, str], tuple[int, int, str]] = {
    ("x86", 16, "little"): (cs.CS_ARCH_X86, cs.CS_MODE_16, "x86-16"),
    ("x86", 32, "little"): (cs.CS_ARCH_X86, cs.CS_MODE_32, "x86-32"),
    ("x86", 64, "little"): (cs.CS_ARCH_X86, cs.CS_MODE_64, "x86-64"),
    ("arm", 32, "little"): (cs.CS_ARCH_ARM, cs.CS_MODE_ARM | cs.CS_MODE_LITTLE_ENDIAN, "ARM (A32, LE)"),
    ("arm", 32, "big"): (cs.CS_ARCH_ARM, cs.CS_MODE_ARM | cs.CS_MODE_BIG_ENDIAN, "ARM (A32, BE)"),
    ("aarch64", 64, "little"): (cs.CS_ARCH_ARM64, cs.CS_MODE_LITTLE_ENDIAN, "AArch64 (LE)"),
    ("aarch64", 64, "big"): (cs.CS_ARCH_ARM64, cs.CS_MODE_BIG_ENDIAN, "AArch64 (BE)"),
    ("mips", 32, "little"): (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_LITTLE_ENDIAN, "MIPS32 (LE)"),
    ("mips", 32, "big"): (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS32 | cs.CS_MODE_BIG_ENDIAN, "MIPS32 (BE)"),
    ("mips", 64, "little"): (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS64 | cs.CS_MODE_LITTLE_ENDIAN, "MIPS64 (LE)"),
    ("mips", 64, "big"): (cs.CS_ARCH_MIPS, cs.CS_MODE_MIPS64 | cs.CS_MODE_BIG_ENDIAN, "MIPS64 (BE)"),
    ("ppc", 32, "big"): (cs.CS_ARCH_PPC, cs.CS_MODE_32 | cs.CS_MODE_BIG_ENDIAN, "PowerPC 32 (BE)"),
    ("ppc", 32, "little"): (cs.CS_ARCH_PPC, cs.CS_MODE_32 | cs.CS_MODE_LITTLE_ENDIAN, "PowerPC 32 (LE)"),
    ("ppc", 64, "big"): (cs.CS_ARCH_PPC, cs.CS_MODE_64 | cs.CS_MODE_BIG_ENDIAN, "PowerPC 64 (BE)"),
    ("ppc", 64, "little"): (cs.CS_ARCH_PPC, cs.CS_MODE_64 | cs.CS_MODE_LITTLE_ENDIAN, "PowerPC 64 (LE)"),
    ("sparc", 32, "big"): (cs.CS_ARCH_SPARC, cs.CS_MODE_BIG_ENDIAN, "SPARC (BE)"),
    ("sparc", 64, "big"): (cs.CS_ARCH_SPARC, cs.CS_MODE_V9 | cs.CS_MODE_BIG_ENDIAN, "SPARC v9 (BE)"),
    ("riscv", 32, "little"): (cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV32, "RISC-V 32"),
    ("riscv", 64, "little"): (cs.CS_ARCH_RISCV, cs.CS_MODE_RISCV64, "RISC-V 64"),
}


def supported() -> list[str]:
    return sorted(f"{a}/{b}/{e}" for (a, b, e) in _TABLE)


def decoder_for(image) -> tuple["cs.Cs", str]:
    """Build a capstone decoder matching the image, or raise UnsupportedError."""
    key = (image.arch, image.bits, image.endian)
    if key not in _TABLE:
        raise UnsupportedError(
            f"no disassembler configured for {image.arch}/{image.bits}-bit/"
            f"{image.endian}-endian ({image.fmt}). Refusing rather than "
            "decoding with the wrong architecture, which yields plausible "
            "but fabricated instructions.",
            arch=image.arch,
            bits=image.bits,
            endian=image.endian,
            supported=supported(),
        )
    arch, mode, label = _TABLE[key]
    md = cs.Cs(arch, mode)
    md.detail = True
    md.skipdata = False
    return md, label


def sweep(md: "cs.Cs", blob: bytes, start_va: int) -> Iterator["cs.CsInsn"]:
    """Linear sweep that resumes after undecodable bytes.

    Stopping at the first bad byte loses the rest of a section; skipping one
    byte and retrying recovers alignment, which matters for stripped or
    data-interleaved code. Progress is guaranteed: the position always
    advances by at least one byte per iteration.
    """
    pos = 0
    n = len(blob)
    while pos < n:
        advanced = pos
        for insn in md.disasm(blob[pos:], start_va + pos):
            advanced = insn.address - start_va + insn.size
            yield insn
        if advanced <= pos:
            pos += 1
        else:
            pos = advanced


def branch_target(insn) -> int | None:
    """Absolute target of a direct branch, or None if not direct.

    Uses decoded operands rather than string-matching `op_str`, so it works
    across architectures instead of only for x86's `0x...` formatting.
    """
    try:
        ops = insn.operands
    except Exception:
        return None
    for op in ops:
        if op.type == _imm_type(insn):
            return int(op.imm)
    return None


def _imm_type(insn) -> int:
    """The immediate operand-type constant for this instruction's arch."""
    arch = insn._cs.arch
    if arch == cs.CS_ARCH_X86:
        return cs.x86.X86_OP_IMM
    if arch == cs.CS_ARCH_ARM:
        return cs.arm.ARM_OP_IMM
    if arch == cs.CS_ARCH_ARM64:
        return cs.arm64.ARM64_OP_IMM
    if arch == cs.CS_ARCH_MIPS:
        return cs.mips.MIPS_OP_IMM
    if arch == cs.CS_ARCH_PPC:
        return cs.ppc.PPC_OP_IMM
    if arch == cs.CS_ARCH_SPARC:
        return cs.sparc.SPARC_OP_IMM
    return 2  # capstone's generic IMM ordinal


def is_call(insn) -> bool:
    return _in_groups(insn, cs.CS_GRP_CALL)


def is_jump(insn) -> bool:
    return _in_groups(insn, cs.CS_GRP_JUMP)


def is_ret(insn) -> bool:
    return _in_groups(insn, cs.CS_GRP_RET)


def _in_groups(insn, grp: int) -> bool:
    try:
        return grp in insn.groups
    except Exception:
        return False


def masked_bytes(insn, image) -> list[bool]:
    """Per-byte mask: True where the byte must be wildcarded in a signature.

    A signature is only version-proof if the bytes that move between builds
    are wildcarded. Those are exactly the encoded immediates and memory
    displacements that name an address inside the image, plus every relative
    branch displacement.

    The predecessor's masking was a no-op: `fixed = min(fixed, len(insn.bytes))`
    where `fixed` already equalled `len(insn.bytes)`. Only `call`/`jmp` rel32
    got wildcarded, so `mov eax, 0x11F1234` kept its absolute address literal
    and the resulting "masked signature" could not survive a layout change --
    which is the one thing it was built to do.

    Rather than re-deriving instruction encodings, this finds the candidate
    values and locates their little/big-endian encodings inside the
    instruction bytes. That is robust across architectures and immune to
    operand-format changes in the disassembler.
    """
    raw = bytes(insn.bytes)
    mask = [False] * len(raw)
    candidates: list[int] = []

    # Relative branches: the encoded field is a displacement, so the absolute
    # target is not what is in the bytes. Mask the whole tail after the opcode
    # by locating the displacement value directly.
    if is_call(insn) or is_jump(insn):
        tgt = branch_target(insn)
        if tgt is not None:
            candidates.append(tgt)
            candidates.append(tgt - (insn.address + insn.size))  # rel displacement

    try:
        ops = insn.operands
    except Exception:
        ops = []

    imm_t = _imm_type(insn)
    for op in ops:
        if op.type == imm_t:
            v = int(op.imm)
            # Only address-like immediates move between builds. Small
            # constants (loop bounds, flags, struct offsets) are stable and
            # are exactly the signal a signature should keep.
            if image.contains_va(v) or image.contains_va(v & 0xFFFFFFFF):
                candidates.append(v)
        else:
            mem = getattr(op, "mem", None)
            disp = getattr(mem, "disp", None) if mem is not None else None
            if disp:
                d = int(disp)
                if image.contains_va(d) or image.contains_va(d & 0xFFFFFFFF):
                    candidates.append(d)
                # x86-64 RIP-relative: the effective address is disp + next PC.
                if image.contains_va(insn.address + insn.size + d):
                    candidates.append(d)

    widths = (8, 4, 2) if image.bits == 64 else (4, 2)
    order = "little" if image.endian == "little" else "big"
    for val in candidates:
        for width in widths:
            for signed in (False, True):
                try:
                    enc = int(val).to_bytes(width, order, signed=signed)
                except (OverflowError, ValueError):
                    continue
                idx = raw.find(enc)
                while idx != -1:
                    for k in range(idx, idx + width):
                        mask[k] = True
                    idx = raw.find(enc, idx + 1)
    return mask


def signature(insns, image, max_bytes: int = 96) -> str:
    """An IDA-style masked byte pattern over a sequence of instructions."""
    parts: list[str] = []
    used = 0
    for insn in insns:
        raw = bytes(insn.bytes)
        if used + len(raw) > max_bytes:
            break
        mask = masked_bytes(insn, image)
        for i, b in enumerate(raw):
            parts.append("??" if mask[i] else f"{b:02X}")
        used += len(raw)
    return " ".join(parts)
