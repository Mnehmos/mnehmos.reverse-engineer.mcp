"""The code index: one disassembly pass, many answers.

First principle: disassemble once, answer many questions.

Cross-references, the call graph, function boundaries and instruction counts
are all projections of a single linear sweep. Computing them separately means
paying for the sweep repeatedly; the predecessor did exactly that, and
`re_callgraph` on the default target took just under six minutes per call.

What this pass records that the predecessor's did not:

* **Every in-image operand reference**, taken from decoded operands rather
  than a byte hunt for `0xE8`. That covers `push imm32`, `lea`, x86-64
  RIP-relative addressing and non-x86 architectures for free.
* **Indirect call sites.** The predecessor emitted no edge for `call rax` or
  `call [rcx+0x24]`, so in a C++ binary every virtual dispatch was invisible.
  An indirect site is not a resolved edge, but recording that dispatch
  happens *here* is strictly better than recording nothing.
* **Jump thunks.** `jmp` was tested in the predecessor's mnemonic check and
  then never recorded, losing every import thunk and tail call.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

import capstone as cs

from . import disasm

# Guard rails so one enormous image cannot produce an unbounded cache entry.
MAX_SITES_PER_TARGET = 256
MAX_TOTAL_REFS = 2_000_000

# Common function prologues by architecture, used only as a weak supplement to
# real evidence (symbols, exports, call targets).
_PROLOGUES: dict[tuple[str, int], tuple[bytes, ...]] = {
    ("x86", 32): (b"\x55\x8b\xec", b"\x55\x89\xe5", b"\x8b\xff\x55\x8b\xec"),
    ("x86", 64): (b"\x48\x89\x5c\x24", b"\x55\x48\x8b\xec", b"\x48\x83\xec", b"\x40\x53"),
}


def _hx(v: int) -> str:
    return f"0x{v:x}"


def build(image, *, max_insns: int = 40_000_000, include_packed: bool = False) -> dict[str, Any]:
    """Sweep every analyzable executable section once and record all facts.

    Packed sections are skipped unless `include_packed` is set; see
    `Image.iter_code` for why that default is not laziness.
    """
    md, decoder_label = disasm.decoder_for(image)
    skipped = [s.name for s in image.packed_exec_sections()] if not include_packed else []

    iat = image.import_by_slot()
    known = image.known_symbol_vas()

    refs_by_target: dict[int, list[tuple[int, str]]] = defaultdict(list)
    call_edges: list[tuple[int, int]] = []
    jump_edges: list[tuple[int, int]] = []
    import_calls: list[tuple[int, int]] = []
    indirect: list[tuple[int, str, str]] = []
    call_targets: set[int] = set()
    branch_targets: set[int] = set()
    insn_count = 0
    truncated = False
    total_refs = 0
    refs_truncated = False
    ref_overflow: dict[int, int] = defaultdict(int)
    # Non-address immediates, keyed by value. These are the magic numbers an
    # optimiser materialises inline rather than loading from a table, and
    # they are how algorithm identification finds SHA/CRC/AES round
    # constants in code that has no data tables left.
    immediates: dict[int, list[int]] = defaultdict(list)

    for sec, blob in image.iter_code(include_packed=include_packed):
        for insn in disasm.sweep(md, blob, sec.va):
            insn_count += 1
            if insn_count > max_insns:
                truncated = True
                break

            call = disasm.is_call(insn)
            jump = disasm.is_jump(insn)

            if call or jump:
                tgt = disasm.branch_target(insn)
                if tgt is not None and image.contains_va(tgt):
                    if call:
                        call_edges.append((insn.address, tgt))
                        call_targets.add(tgt)
                    else:
                        jump_edges.append((insn.address, tgt))
                        branch_targets.add(tgt)
                else:
                    # Indirect, or a target outside the image. Either way the
                    # edge is unresolved -- record the site, not a guess.
                    slot = _memory_slot(insn, image)
                    if slot is not None and slot in iat:
                        import_calls.append((insn.address, slot))
                    elif call:
                        indirect.append((insn.address, insn.mnemonic, insn.op_str))

            for value in _plain_immediates(insn, image):
                bucket_i = immediates[value]
                if len(bucket_i) < 24:
                    bucket_i.append(insn.address)

            for target, kind in _operand_refs(insn, image):
                bucket = refs_by_target[target]
                if len(bucket) >= MAX_SITES_PER_TARGET or total_refs >= MAX_TOTAL_REFS:
                    # Keep counting so the reported total stays truthful even
                    # when the stored site list is clipped.
                    ref_overflow[target] += 1
                    refs_truncated = True
                    continue
                bucket.append((insn.address, kind))
                total_refs += 1
        if truncated:
            break

    func_starts = _function_starts(image, call_targets, known)

    return {
        "schema": 2,
        "sha256": image.sha256,
        "decoder": decoder_label,
        "skipped_packed_sections": skipped,
        "include_packed": include_packed,
        "insn_count": insn_count,
        "truncated": truncated,
        "refs_truncated": refs_truncated,
        "refs_by_target": {
            _hx(t): [[_hx(s), k] for s, k in sites] for t, sites in refs_by_target.items()
        },
        "ref_overflow": {_hx(t): n for t, n in ref_overflow.items()},
        "immediates": {_hx(v): [_hx(a) for a in sites]
                       for v, sites in immediates.items()},
        "call_edges": [[_hx(a), _hx(b)] for a, b in call_edges],
        "jump_edges": [[_hx(a), _hx(b)] for a, b in jump_edges],
        "import_calls": [
            [_hx(site), _hx(slot), iat[slot].qualified] for site, slot in import_calls
        ],
        "indirect_calls": [[_hx(a), m, o] for a, m, o in indirect],
        "func_starts": [_hx(v) for v in func_starts],
        "call_target_count": len(call_targets),
    }


def _memory_slot(insn, image) -> int | None:
    """Absolute address of a memory operand, for import-thunk resolution."""
    try:
        ops = insn.operands
    except Exception:
        return None
    for op in ops:
        mem = getattr(op, "mem", None)
        if mem is None:
            continue
        disp = int(getattr(mem, "disp", 0) or 0)
        if not disp:
            continue
        base = getattr(mem, "base", 0)
        # x86-64 reaches the IAT through RIP-relative addressing, so the slot
        # address is disp + the address of the next instruction.
        if base and insn._cs.arch == cs.CS_ARCH_X86:
            if base == cs.x86.X86_REG_RIP:
                return insn.address + insn.size + disp
        if image.contains_va(disp):
            return disp
    return None


def _plain_immediates(insn, image):
    """Immediates that are NOT in-image addresses -- real constants.

    An address is a layout artifact; a magic number is a fact about the
    algorithm. Only the second kind is worth indexing by value.
    """
    try:
        ops = insn.operands
    except Exception:
        return
    imm_t = disasm._imm_type(insn)
    for op in ops:
        if op.type != imm_t:
            continue
        v = int(op.imm)
        if -0xFFFF <= v <= 0xFFFF:
            continue  # too common to carry information
        if image.contains_va(v) or image.contains_va(v & 0xFFFFFFFF):
            continue
        yield v & 0xFFFFFFFFFFFFFFFF


def _operand_refs(insn, image):
    """Yield (target_va, kind) for every operand naming an in-image address."""
    try:
        ops = insn.operands
    except Exception:
        return
    imm_t = disasm._imm_type(insn)
    for op in ops:
        if op.type == imm_t:
            v = int(op.imm)
            if image.contains_va(v):
                yield v, f"imm:{insn.mnemonic}"
            elif v > 0 and image.contains_va(v & 0xFFFFFFFF):
                yield v & 0xFFFFFFFF, f"imm32:{insn.mnemonic}"
            continue
        mem = getattr(op, "mem", None)
        if mem is None:
            continue
        disp = int(getattr(mem, "disp", 0) or 0)
        if not disp:
            continue
        if image.contains_va(disp):
            yield disp, f"mem:{insn.mnemonic}"
            continue
        eff = insn.address + insn.size + disp
        base = getattr(mem, "base", 0)
        if base and image.contains_va(eff):
            # RIP/PC-relative reference.
            yield eff, f"pcrel:{insn.mnemonic}"


def _function_starts(image, call_targets: set[int], known: dict[int, Any]) -> list[int]:
    """Function entry points, strongest evidence first.

    Symbols and exports are facts. Call targets are strong evidence. Prologue
    byte patterns are a weak heuristic and are only added where nothing
    better is available, because a pattern match inside data or in the middle
    of an instruction is indistinguishable from a real entry point.
    """
    starts: set[int] = set()
    starts.update(known.keys())
    starts.update(s.va for s in image.exports)
    if image.entry_va is not None:
        starts.add(image.entry_va)
    starts.update(call_targets)

    if not known and not image.exports:
        pats = _PROLOGUES.get((image.arch, image.bits), ())
        for sec, blob in image.iter_code(include_packed=False):
            for pat in pats:
                i = blob.find(pat)
                while i != -1:
                    starts.add(sec.va + i)
                    i = blob.find(pat, i + 1)

    return sorted(v for v in starts if image.contains_va(v))


def load(
    image, *, use_cache: bool = True, include_packed: bool = False
) -> tuple[dict[str, Any], bool]:
    from .cache import get_or_build

    return get_or_build(
        image.sha256,
        "codeindex",
        {"schema": 2, "include_packed": include_packed},
        lambda: build(image, include_packed=include_packed),
        enabled=use_cache,
    )
