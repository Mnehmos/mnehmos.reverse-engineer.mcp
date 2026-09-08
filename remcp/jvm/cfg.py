"""Control-flow graph, dominators and natural loops over JVM bytecode.

Structure recovery is what separates a bytecode listing from readable logic.
Loops are found the standard way -- a back edge is an edge whose target
dominates its source -- and if/else regions are bounded by the immediate
post-dominator of the branching block, which is the join point where both
arms reconverge.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .bytecode import (
    BRANCH_OPS,
    GOTO_OPS,
    Insn,
    RETURN_OPS,
    SWITCH_OPS,
)


@dataclass
class Block:
    start: int
    insns: list[Insn] = field(default_factory=list)
    succs: list[int] = field(default_factory=list)
    preds: list[int] = field(default_factory=list)
    is_handler: bool = False

    @property
    def end(self) -> int:
        return self.insns[-1].pc + self.insns[-1].size if self.insns else self.start

    @property
    def terminator(self) -> Insn | None:
        return self.insns[-1] if self.insns else None

    def to_dict(self) -> dict:
        t = self.terminator
        return {
            "start": self.start,
            "end": self.end,
            "instructions": len(self.insns),
            "terminator": t.mnemonic if t else None,
            "successors": list(self.succs),
            "predecessors": list(self.preds),
            "exception_handler": self.is_handler,
        }


class CFG:
    def __init__(self, insns: list[Insn], exceptions=()) -> None:
        self.insns = insns
        self.by_pc = {i.pc: i for i in insns}
        self.blocks: dict[int, Block] = {}
        self.entry = insns[0].pc if insns else 0
        self._build(list(exceptions))

    # --- construction ------------------------------------------------------

    def _leaders(self, exceptions) -> set[int]:
        leaders: set[int] = set()
        if self.insns:
            leaders.add(self.insns[0].pc)
        for idx, insn in enumerate(self.insns):
            m = insn.mnemonic
            if m in BRANCH_OPS or m in GOTO_OPS or m in SWITCH_OPS:
                for t in insn.targets:
                    leaders.add(t)
            if m in BRANCH_OPS or m in RETURN_OPS or m in GOTO_OPS \
                    or m in SWITCH_OPS or m == "athrow":
                nxt = idx + 1
                if nxt < len(self.insns):
                    leaders.add(self.insns[nxt].pc)
        for e in exceptions:
            leaders.add(e.handler_pc)
            leaders.add(e.start_pc)
        return {pc for pc in leaders if pc in self.by_pc}

    def _build(self, exceptions) -> None:
        if not self.insns:
            return
        leaders = self._leaders(exceptions)
        handler_pcs = {e.handler_pc for e in exceptions}

        cur: Block | None = None
        for insn in self.insns:
            if insn.pc in leaders or cur is None:
                cur = Block(start=insn.pc, is_handler=insn.pc in handler_pcs)
                self.blocks[insn.pc] = cur
            cur.insns.append(insn)

        starts = sorted(self.blocks)
        for i, s in enumerate(starts):
            b = self.blocks[s]
            t = b.terminator
            if t is None:
                continue
            m = t.mnemonic
            nxt = starts[i + 1] if i + 1 < len(starts) else None

            if m in RETURN_OPS or m == "athrow":
                pass
            elif m in GOTO_OPS:
                b.succs = [t.targets[0]] if t.targets else []
            elif m in BRANCH_OPS:
                b.succs = ([t.targets[0]] if t.targets else []) + ([nxt] if nxt is not None else [])
            elif m in SWITCH_OPS:
                b.succs = list(dict.fromkeys(t.targets))
            elif nxt is not None:
                b.succs = [nxt]

            b.succs = [s2 for s2 in b.succs if s2 in self.blocks]

        # Exception edges: a handler is reachable from any block in its range.
        for e in exceptions:
            if e.handler_pc not in self.blocks:
                continue
            for s in starts:
                if e.start_pc <= s < e.end_pc and e.handler_pc not in self.blocks[s].succs:
                    self.blocks[s].succs.append(e.handler_pc)

        for s, b in self.blocks.items():
            for t in b.succs:
                self.blocks[t].preds.append(s)

    # --- dominators --------------------------------------------------------

    def dominators(self) -> dict[int, set[int]]:
        starts = set(self.blocks)
        if not starts:
            return {}
        dom = {s: set(starts) for s in starts}
        dom[self.entry] = {self.entry}
        changed = True
        while changed:
            changed = False
            for s in starts:
                if s == self.entry:
                    continue
                preds = self.blocks[s].preds
                if not preds:
                    new = {s}
                else:
                    new = set(starts)
                    for p in preds:
                        new &= dom[p]
                    new |= {s}
                if new != dom[s]:
                    dom[s] = new
                    changed = True
        return dom

    def back_edges(self) -> list[tuple[int, int]]:
        """Edges (from, to) where `to` dominates `from` -- i.e. loops."""
        dom = self.dominators()
        out = []
        for s, b in self.blocks.items():
            for t in b.succs:
                if t in dom.get(s, ()):
                    out.append((s, t))
        return out

    def natural_loops(self) -> list[dict]:
        loops = []
        for tail, head in self.back_edges():
            body = {head, tail}
            # The standard natural-loop walk seeds the worklist with the
            # tail only when it differs from the header. Pushing the header
            # itself makes the traversal escape backwards through the
            # header's *external* predecessors, so a one-block self-loop was
            # reported as a four-block loop.
            stack = [tail] if tail != head else []
            while stack:
                n = stack.pop()
                for p in self.blocks[n].preds:
                    if p not in body:
                        body.add(p)
                        stack.append(p)
            exits = sorted({t for n in body for t in self.blocks[n].succs if t not in body})
            loops.append({
                "header": head,
                "tail": tail,
                "body_blocks": sorted(body),
                "size": len(body),
                "exits": exits,
                "nested_in": [],
            })
        for a in loops:
            for b in loops:
                if a is b:
                    continue
                if set(a["body_blocks"]) < set(b["body_blocks"]):
                    a["nested_in"].append(b["header"])
        loops.sort(key=lambda x: (-x["size"], x["header"]))
        return loops

    def post_dominators(self) -> dict[int, set[int]]:
        starts = set(self.blocks)
        exits = [s for s, b in self.blocks.items() if not b.succs]
        if not starts:
            return {}
        pdom = {s: set(starts) for s in starts}
        for e in exits:
            pdom[e] = {e}
        changed = True
        while changed:
            changed = False
            for s in starts:
                if s in exits:
                    continue
                succs = self.blocks[s].succs
                if not succs:
                    new = {s}
                else:
                    new = set(starts)
                    for t in succs:
                        new &= pdom[t]
                    new |= {s}
                if new != pdom[s]:
                    pdom[s] = new
                    changed = True
        return pdom

    def immediate_post_dominator(self, s: int) -> int | None:
        pdom = self.post_dominators()
        cands = pdom.get(s, set()) - {s}
        if not cands:
            return None
        # The immediate post-dominator is post-dominated by no other candidate.
        for c in sorted(cands):
            if all(c == o or c not in pdom.get(o, set()) - {o} for o in cands):
                return c
        return min(cands)

    def to_dict(self) -> dict:
        loops = self.natural_loops()
        return {
            "entry": self.entry,
            "block_count": len(self.blocks),
            "edge_count": sum(len(b.succs) for b in self.blocks.values()),
            "loops": loops,
            "loop_count": len(loops),
            "max_loop_depth": max((1 + len(l["nested_in"]) for l in loops), default=0),
            "blocks": [self.blocks[s].to_dict() for s in sorted(self.blocks)],
        }


def cyclomatic_complexity(cfg: CFG) -> int:
    """E - N + 2. A rough but useful gauge of how tangled a method is."""
    if not cfg.blocks:
        return 0
    e = sum(len(b.succs) for b in cfg.blocks.values())
    n = len(cfg.blocks)
    return e - n + 2
