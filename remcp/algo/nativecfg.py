"""Native control-flow recovery: basic blocks, dominators, natural loops.

The call graph answers "what calls what". This answers "what shape is this
function" -- how many branches, how deeply nested its loops are, whether it
has a single exit. That is the structural half of algorithm recovery: a
routine with one tight loop over a 256-entry table and a handful of XORs is
recognisable as a cipher's key schedule long before anyone reads its
operands.

Boundaries are estimated, and the estimate is reported rather than hidden. A
function's end is taken as the next known entry point, refined by scanning
for a return that is followed by padding or a new prologue.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .. import disasm


@dataclass
class NBlock:
    start: int
    end: int
    insns: int
    terminator: str
    succs: list[int] = field(default_factory=list)
    preds: list[int] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "start": f"0x{self.start:x}",
            "end": f"0x{self.end:x}",
            "instructions": self.insns,
            "terminator": self.terminator,
            "successors": [f"0x{s:x}" for s in self.succs],
            "predecessors": [f"0x{p:x}" for p in self.preds],
            "calls": self.calls[:8],
        }


def _dominators(blocks: dict[int, NBlock], entry: int) -> dict[int, set[int]]:
    nodes = set(blocks)
    if entry not in nodes:
        return {}
    dom = {n: set(nodes) for n in nodes}
    dom[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for n in nodes:
            if n == entry:
                continue
            preds = blocks[n].preds
            new = set(nodes)
            if preds:
                for p in preds:
                    new &= dom[p]
            else:
                new = set()
            new |= {n}
            if new != dom[n]:
                dom[n] = new
                changed = True
    return dom


def build_function_cfg(image, index: dict, va: int, *,
                       max_bytes: int = 65536) -> dict:
    """Recover one function's control-flow graph."""
    from ..graph import FunctionMap

    image.require_va(va)
    md, decoder = disasm.decoder_for(image)

    starts = [int(s, 16) for s in index.get("func_starts", [])]
    fmap = FunctionMap(starts)
    lo, hi = fmap.extent(va, hard_cap=max_bytes)
    if lo != va:
        lo, hi = va, min(va + max_bytes, hi if hi > va else va + max_bytes)

    blob = image.read_va(lo, hi - lo) or b""
    insns = list(disasm.sweep(md, blob, lo))

    # Trim at a return followed by padding or an obvious new frame.
    for i, ins in enumerate(insns):
        if disasm.is_ret(ins) and i + 1 < len(insns):
            nxt = bytes(insns[i + 1].bytes)[:1]
            if nxt in (b"\xcc", b"\x90"):
                insns = insns[: i + 1]
                break

    if not insns:
        return {"function": f"0x{va:x}", "resolved": False,
                "reason": "no instructions decoded at this address"}

    by_pc = {i.address: i for i in insns}
    in_range = set(by_pc)

    leaders = {insns[0].address}
    for idx, ins in enumerate(insns):
        if disasm.is_jump(ins) or disasm.is_call(ins) or disasm.is_ret(ins):
            tgt = disasm.branch_target(ins)
            if disasm.is_jump(ins) and tgt is not None and tgt in in_range:
                leaders.add(tgt)
            if idx + 1 < len(insns):
                if disasm.is_jump(ins) or disasm.is_ret(ins):
                    leaders.add(insns[idx + 1].address)

    blocks: dict[int, NBlock] = {}
    cur: list = []
    cur_start = insns[0].address
    imports = {int(s, 16): q for s, _slot, q in
               ((a, b, c) for a, b, c in index.get("import_calls", []))}

    def flush(nxt_addr: int | None) -> None:
        if not cur:
            return
        last = cur[-1]
        calls = []
        for ins in cur:
            if disasm.is_call(ins):
                q = imports.get(ins.address)
                if q:
                    calls.append(q)
                else:
                    t = disasm.branch_target(ins)
                    calls.append(f"0x{t:x}" if t is not None else f"indirect:{ins.op_str}")
        b = NBlock(start=cur_start, end=last.address + last.size, insns=len(cur),
                   terminator=last.mnemonic, calls=calls)
        if disasm.is_ret(last):
            pass
        elif disasm.is_jump(last):
            t = disasm.branch_target(last)
            if t is not None and t in in_range:
                b.succs.append(t)
            cond = last.mnemonic not in ("jmp", "b", "br")
            if cond and nxt_addr is not None:
                b.succs.append(nxt_addr)
        elif nxt_addr is not None:
            b.succs.append(nxt_addr)
        blocks[cur_start] = b

    for idx, ins in enumerate(insns):
        if ins.address in leaders and cur:
            nxt = ins.address
            flush(nxt)
            cur, cur_start = [], ins.address
        cur.append(ins)
    flush(None)

    for s, b in blocks.items():
        b.succs = [t for t in b.succs if t in blocks]
    for s, b in blocks.items():
        for t in b.succs:
            blocks[t].preds.append(s)

    entry = insns[0].address
    dom = _dominators(blocks, entry)
    back_edges = [(s, t) for s, b in blocks.items() for t in b.succs
                  if t in dom.get(s, ())]

    loops = []
    for tail, head in back_edges:
        body = {head, tail}
        # The standard natural-loop walk seeds the worklist with the
        # tail only when it differs from the header. Pushing the header
        # itself makes the traversal escape backwards through the
        # header's *external* predecessors, so a one-block self-loop was
        # reported as a four-block loop.
        stack = [tail] if tail != head else []
        while stack:
            n = stack.pop()
            for p in blocks[n].preds:
                if p not in body:
                    body.add(p)
                    stack.append(p)
        loops.append({
            "header": f"0x{head:x}",
            "tail": f"0x{tail:x}",
            "blocks": len(body),
            "body": [f"0x{b:x}" for b in sorted(body)][:32],
        })
    loops.sort(key=lambda x: -x["blocks"])

    exits = [s for s, b in blocks.items() if not b.succs]
    edge_count = sum(len(b.succs) for b in blocks.values())

    names = {s.va: s.name for s in image.symbols + image.exports}
    return {
        "function": f"0x{va:x}",
        "name": names.get(va),
        "resolved": True,
        "decoder": decoder,
        "estimated_extent": {"start": f"0x{lo:x}",
                             "end": f"0x{insns[-1].address + insns[-1].size:x}",
                             "size": insns[-1].address + insns[-1].size - lo},
        "instruction_count": len(insns),
        "block_count": len(blocks),
        "edge_count": edge_count,
        "cyclomatic_complexity": edge_count - len(blocks) + 2 if blocks else 0,
        "loop_count": len(loops),
        "loops": loops,
        "exit_blocks": [f"0x{e:x}" for e in sorted(exits)],
        "single_exit": len(exits) == 1,
        "blocks": [blocks[s].to_dict() for s in sorted(blocks)],
    }
