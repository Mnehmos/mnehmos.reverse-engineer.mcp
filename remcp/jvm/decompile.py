"""JVM decompiler: operand-stack reconstruction and control-flow structuring.

Two passes.

**Expressions.** The JVM is a stack machine, so `iload_1; iload_2; iadd;
istore_3` is really `v3 = v1 + v2`. Simulating the operand stack with
symbolic values instead of concrete ones recovers the expression tree the
compiler flattened. This is exact, not heuristic: the stack discipline is
part of the verified class-file contract.

**Control flow.** Bytecode has only conditional jumps. Loops are recovered
from back edges (an edge whose target dominates its source) and if/else
regions from the immediate post-dominator, which is the join where both arms
reconverge.

Where a region does not fit a recognized shape -- irreducible control flow,
`jsr`/`ret` subroutines, heavily obfuscated jump tables -- the emitter falls
back to a labelled goto listing and says so in `structured: false` rather
than inventing a shape that reads well and is wrong. That distinction is the
whole point: a decompiler that always produces clean-looking output is
lying some of the time and never tells you when.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .bytecode import CONDITIONS, INVERT, Insn, decode
from .cfg import CFG, cyclomatic_complexity
from .classfile import (
    Code,
    Member,
    Pool,
    descriptor_slots,
    parse_method_descriptor,
    parse_type,
    simple_name,
)

# Java operator precedence; higher binds tighter.
P_PRIMARY = 15
P_UNARY = 14
P_MUL = 12
P_ADD = 11
P_SHIFT = 10
P_REL = 9
P_EQ = 8
P_AND = 7
P_XOR = 6
P_OR = 5
P_TERN = 2
P_ASSIGN = 1


@dataclass
class Expr:
    text: str
    prec: int = P_PRIMARY
    # Marks the uninitialised reference `new` pushes before <init> runs.
    new_type: str | None = None

    def paren(self, need: int) -> str:
        return f"({self.text})" if self.prec < need else self.text

    def __str__(self) -> str:
        return self.text


def _lit(v: Any) -> Expr:
    if isinstance(v, str):
        return Expr('"' + v.replace("\\", "\\\\").replace('"', '\\"')
                    .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + '"')
    if v is None:
        return Expr("null")
    if isinstance(v, bool):
        return Expr("true" if v else "false")
    return Expr(str(v))


BINOPS = {
    "iadd": ("+", P_ADD), "ladd": ("+", P_ADD), "fadd": ("+", P_ADD), "dadd": ("+", P_ADD),
    "isub": ("-", P_ADD), "lsub": ("-", P_ADD), "fsub": ("-", P_ADD), "dsub": ("-", P_ADD),
    "imul": ("*", P_MUL), "lmul": ("*", P_MUL), "fmul": ("*", P_MUL), "dmul": ("*", P_MUL),
    "idiv": ("/", P_MUL), "ldiv": ("/", P_MUL), "fdiv": ("/", P_MUL), "ddiv": ("/", P_MUL),
    "irem": ("%", P_MUL), "lrem": ("%", P_MUL), "frem": ("%", P_MUL), "drem": ("%", P_MUL),
    "ishl": ("<<", P_SHIFT), "lshl": ("<<", P_SHIFT),
    "ishr": (">>", P_SHIFT), "lshr": (">>", P_SHIFT),
    "iushr": (">>>", P_SHIFT), "lushr": (">>>", P_SHIFT),
    "iand": ("&", P_AND), "land": ("&", P_AND),
    "ior": ("|", P_OR), "lor": ("|", P_OR),
    "ixor": ("^", P_XOR), "lxor": ("^", P_XOR),
}

CASTS = {
    "i2l": "long", "i2f": "float", "i2d": "double", "l2i": "int", "l2f": "float",
    "l2d": "double", "f2i": "int", "f2l": "long", "f2d": "double", "d2i": "int",
    "d2l": "long", "d2f": "float", "i2b": "byte", "i2c": "char", "i2s": "short",
}

LOAD_RE = re.compile(r"^([ilfda])load(?:_(\d))?$")
STORE_RE = re.compile(r"^([ilfda])store(?:_(\d))?$")
CONST_RE = re.compile(r"^([ilfd])const_(m1|\d)$")
ARRAY_LOAD = {"iaload": "int", "laload": "long", "faload": "float", "daload": "double",
              "aaload": "ref", "baload": "byte", "caload": "char", "saload": "short"}
ARRAY_STORE = {"iastore", "lastore", "fastore", "dastore", "aastore", "bastore",
               "castore", "sastore"}


class Locals:
    """Names for local slots, preferring real debug names when present."""

    def __init__(self, member: Member, code: Code) -> None:
        self.code = code
        self.names: dict[int, str] = {}
        params, _ret = parse_method_descriptor(member.descriptor)
        slot = 0
        if not member.is_static:
            self.names[0] = "this"
            slot = 1
        self.boolean_names: set[str] = set()
        for i, p in enumerate(params):
            self.names.setdefault(slot, f"a{i}")
            if p == "boolean":
                self.boolean_names.add(self.name(slot, 0))
            slot += 2 if p in ("long", "double") else 1
        self.param_slots = slot
        for lv in (code.local_vars if code else []):
            if lv.descriptor == "Z":
                self.boolean_names.add(lv.name)

    def name(self, index: int, pc: int) -> str:
        real = self.code.local_name(index, pc) if self.code else None
        if real:
            return real
        return self.names.get(index) or f"v{index}"


@dataclass
class Statement:
    pc: int
    text: str
    kind: str = "stmt"


@dataclass
class BlockCode:
    start: int
    statements: list[Statement] = field(default_factory=list)
    condition: str | None = None      # for conditional terminators
    condition_target: int | None = None
    stack_out: list[Expr] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class StackSim:
    """Symbolic execution of one basic block's operand stack."""

    def __init__(self, pool: Pool, locals_: Locals, member: Member) -> None:
        self.pool = pool
        self.locals = locals_
        self.member = member

    def run(self, block_insns: list[Insn], stack_in: list[Expr]) -> BlockCode:
        st: list[Expr] = list(stack_in)
        bc = BlockCode(start=block_insns[0].pc if block_insns else 0)
        out = bc.statements

        def pop() -> Expr:
            return st.pop() if st else Expr("/*stack underflow*/")

        def popn(n: int) -> list[Expr]:
            vals = [pop() for _ in range(n)]
            return list(reversed(vals))

        for insn in block_insns:
            m = insn.mnemonic
            o = insn.operands
            pc = insn.pc

            try:
                if m == "nop":
                    continue
                if m == "aconst_null":
                    st.append(Expr("null")); continue

                mc = CONST_RE.match(m)
                if mc:
                    v = mc.group(2)
                    st.append(Expr("-1" if v == "m1" else v)); continue

                if m in ("bipush", "sipush"):
                    st.append(Expr(str(o["value"]))); continue

                if m in ("ldc", "ldc_w", "ldc2_w"):
                    st.append(_lit(self.pool.constant_at(o["index"]))); continue

                ml = LOAD_RE.match(m)
                if ml:
                    idx = int(ml.group(2)) if ml.group(2) is not None else o.get("index", 0)
                    st.append(Expr(self.locals.name(idx, pc))); continue

                ms = STORE_RE.match(m)
                if ms:
                    idx = int(ms.group(2)) if ms.group(2) is not None else o.get("index", 0)
                    val = pop()
                    out.append(Statement(pc, f"{self.locals.name(idx, pc)} = {val.text};"))
                    continue

                if m == "iinc":
                    n = self.locals.name(o["index"], pc)
                    c = o["const"]
                    if c == 1:
                        out.append(Statement(pc, f"{n}++;"))
                    elif c == -1:
                        out.append(Statement(pc, f"{n}--;"))
                    elif c < 0:
                        out.append(Statement(pc, f"{n} -= {-c};"))
                    else:
                        out.append(Statement(pc, f"{n} += {c};"))
                    continue

                if m in BINOPS:
                    op, prec = BINOPS[m]
                    b, a = pop(), pop()
                    st.append(Expr(f"{a.paren(prec)} {op} {b.paren(prec + 1)}", prec))
                    continue

                if m in ("ineg", "lneg", "fneg", "dneg"):
                    a = pop(); st.append(Expr(f"-{a.paren(P_UNARY)}", P_UNARY)); continue

                if m in CASTS:
                    a = pop()
                    st.append(Expr(f"({CASTS[m]}) {a.paren(P_UNARY)}", P_UNARY)); continue

                if m in ("lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg"):
                    b, a = pop(), pop()
                    st.append(Expr(f"compare({a.text}, {b.text})")); continue

                if m == "arraylength":
                    a = pop(); st.append(Expr(f"{a.paren(P_PRIMARY)}.length")); continue

                if m in ARRAY_LOAD:
                    i, arr = pop(), pop()
                    st.append(Expr(f"{arr.paren(P_PRIMARY)}[{i.text}]")); continue

                if m in ARRAY_STORE:
                    v, i, arr = pop(), pop(), pop()
                    out.append(Statement(pc, f"{arr.paren(P_PRIMARY)}[{i.text}] = {v.text};"))
                    continue

                if m in ("pop", "pop2"):
                    v = pop()
                    if "(" in v.text:  # a discarded call still has to run
                        out.append(Statement(pc, f"{v.text};"))
                    if m == "pop2" and st:
                        pop()
                    continue

                if m == "dup":
                    if st:
                        st.append(st[-1])
                    continue
                if m == "dup_x1":
                    if len(st) >= 2:
                        st.insert(-2, st[-1])
                    continue
                if m == "dup_x2":
                    if len(st) >= 3:
                        st.insert(-3, st[-1])
                    continue
                if m == "dup2":
                    if len(st) >= 2:
                        st.extend(st[-2:])
                    elif st:
                        st.append(st[-1])
                    continue
                if m in ("dup2_x1", "dup2_x2"):
                    if len(st) >= 2:
                        st.extend(st[-2:])
                    continue
                if m == "swap":
                    if len(st) >= 2:
                        st[-1], st[-2] = st[-2], st[-1]
                    continue

                if m == "getstatic":
                    r = self.pool.fieldref(o["index"])
                    st.append(Expr(f"{simple_name(r[0])}.{r[1]}" if r else "?.?"))
                    continue
                if m == "getfield":
                    r = self.pool.fieldref(o["index"])
                    obj = pop()
                    nm = r[1] if r else "?"
                    st.append(Expr(f"{obj.paren(P_PRIMARY)}.{nm}"))
                    continue
                if m == "putstatic":
                    r = self.pool.fieldref(o["index"])
                    v = pop()
                    out.append(Statement(pc, f"{simple_name(r[0])}.{r[1]} = {v.text};" if r
                                         else f"?.? = {v.text};"))
                    continue
                if m == "putfield":
                    r = self.pool.fieldref(o["index"])
                    v, obj = pop(), pop()
                    nm = r[1] if r else "?"
                    out.append(Statement(pc, f"{obj.paren(P_PRIMARY)}.{nm} = {v.text};"))
                    continue

                if m == "new":
                    cls = self.pool.class_at(o["index"]) or "?"
                    st.append(Expr(f"new {simple_name(cls)}", P_PRIMARY, new_type=cls))
                    continue
                if m == "newarray":
                    n = pop()
                    st.append(Expr(f"new {o['type']}[{n.text}]")); continue
                if m == "anewarray":
                    cls = self.pool.class_at(o["index"]) or "?"
                    n = pop()
                    st.append(Expr(f"new {simple_name(cls)}[{n.text}]")); continue
                if m == "multianewarray":
                    cls = self.pool.class_at(o["index"]) or "?"
                    dims = popn(o["dimensions"])
                    st.append(Expr(f"new {simple_name(cls)}"
                                   + "".join(f"[{d.text}]" for d in dims)))
                    continue

                if m == "checkcast":
                    cls = self.pool.class_at(o["index"]) or "?"
                    a = pop()
                    st.append(Expr(f"({simple_name(cls)}) {a.paren(P_UNARY)}", P_UNARY))
                    continue
                if m == "instanceof":
                    cls = self.pool.class_at(o["index"]) or "?"
                    a = pop()
                    st.append(Expr(f"{a.paren(P_REL)} instanceof {simple_name(cls)}", P_REL))
                    continue

                if m.startswith("invoke"):
                    self._invoke(insn, st, out)
                    continue

                if m == "athrow":
                    v = pop()
                    out.append(Statement(pc, f"throw {v.text};", "throw"))
                    continue
                if m == "return":
                    out.append(Statement(pc, "return;", "return"))
                    continue
                if m in ("ireturn", "lreturn", "freturn", "dreturn", "areturn"):
                    v = pop()
                    out.append(Statement(pc, f"return {v.text};", "return"))
                    continue

                if m in ("monitorenter", "monitorexit"):
                    v = pop()
                    out.append(Statement(pc, f"/* {m} {v.text} */", "monitor"))
                    continue

                if m in CONDITIONS:
                    op, argc, _zero = CONDITIONS[m]
                    if argc == 2:
                        b, a = pop(), pop()
                        bc.condition = f"{a.paren(P_EQ)} {op} {b.paren(P_EQ + 1)}"
                    else:
                        a = pop()
                        if op.endswith("null"):
                            bc.condition = f"{a.paren(P_EQ)} {op}"
                        elif op in ("!=", "==") and (
                            _looks_boolean(a)
                            or a.text in self.locals.boolean_names
                        ):
                            # `ifeq` on a boolean is `!x`, not `x == 0`.
                            bc.condition = a.text if op == "!=" else f"!{a.paren(P_UNARY)}"
                        else:
                            bc.condition = f"{a.paren(P_EQ)} {op} 0"
                    bc.condition_target = insn.targets[0] if insn.targets else None
                    continue

                if m in ("goto", "goto_w"):
                    continue
                if m in ("tableswitch", "lookupswitch"):
                    v = pop()
                    bc.condition = f"switch ({v.text})"
                    continue

                if m in ("jsr", "jsr_w", "ret"):
                    bc.notes.append(f"{m} at {pc}: subroutines are not structured")
                    continue

                bc.notes.append(f"unmodelled opcode {m} at {pc}")
            except Exception as exc:  # a malformed method must not kill the pass
                bc.notes.append(f"{m} at {pc}: {type(exc).__name__}")

        bc.stack_out = st
        return bc

    def _invoke(self, insn: Insn, st: list[Expr], out: list[Statement]) -> None:
        m = insn.mnemonic
        pc = insn.pc
        if m == "invokedynamic":
            desc = self.pool.invokedynamic_at(insn.operands["index"]) or "<dynamic>"
            nat = re.search(r"\.([^(]+)(\(.*\))", desc or "")
            params, ret = parse_method_descriptor(nat.group(2)) if nat else ([], "?")
            args = popn_list(st, len(params))
            name = nat.group(1) if nat else "invokeDynamic"

            # Java 9+ compiles string concatenation to an invokedynamic call
            # on StringConcatFactory rather than a StringBuilder chain, so
            # `"a " + x` arrives here. Rendering the raw indy call would make
            # every formatted string in a modern jar unreadable.
            if name.startswith("makeConcat"):
                if args:
                    joined = " + ".join(a.paren(P_ADD) for a in args)
                    st.append(Expr(joined, P_ADD))
                else:
                    st.append(Expr('""'))
                return

            call = Expr(f"{name}({', '.join(a.text for a in args)}) /* indy */")
            if ret == "void":
                out.append(Statement(pc, f"{call.text};"))
            else:
                st.append(call)
            return

        r = self.pool.methodref(insn.operands["index"])
        if not r:
            return
        cls, name, desc = r
        params, ret = parse_method_descriptor(desc)
        args = popn_list(st, len(params))
        argtext = ", ".join(a.text for a in args)

        if m == "invokestatic":
            call = Expr(f"{simple_name(cls)}.{name}({argtext})")
        else:
            obj = st.pop() if st else Expr("?")
            if name == "<init>":
                if obj.new_type is not None:
                    # new/dup/invokespecial<init> is one construction expression.
                    ctor = Expr(f"new {simple_name(obj.new_type)}({argtext})")
                    if st and st[-1] is obj:
                        st.pop()
                    st.append(ctor)
                    return
                out.append(Statement(pc, f"{'super' if cls != self.member.name else 'this'}"
                                         f"({argtext});"))
                return
            target = obj.paren(P_PRIMARY)
            call = Expr(f"{target}.{name}({argtext})")

        if ret == "void":
            out.append(Statement(pc, f"{call.text};", "call"))
        else:
            st.append(call)


def popn_list(st: list[Expr], n: int) -> list[Expr]:
    vals = []
    for _ in range(n):
        vals.append(st.pop() if st else Expr("?"))
    return list(reversed(vals))


def _looks_boolean(e: Expr) -> bool:
    t = e.text
    return (
        t.endswith(")") and (".is" in t or ".has" in t or ".equals(" in t or
                             ".contains(" in t or ".startsWith(" in t or ".endsWith(" in t)
    ) or " instanceof " in t


# --------------------------------------------------------------------------
# String-builder folding
# --------------------------------------------------------------------------

_SB_CHAIN = re.compile(
    r"new StringBuilder\(([^()]*)\)((?:\.append\((?:[^()]|\([^()]*\))*\))+)\.toString\(\)"
)
_APPEND = re.compile(r"\.append\(((?:[^()]|\([^()]*\))*)\)")


def fold_string_builders(text: str) -> str:
    """Rewrite `new StringBuilder().append(a).append(b).toString()` as `a + b`.

    javac compiles every `+` on strings into this chain, so leaving it
    unfolded makes ordinary string formatting unreadable.
    """
    def repl(mo: re.Match) -> str:
        seed = mo.group(1).strip()
        parts = [m.group(1).strip() for m in _APPEND.finditer(mo.group(2))]
        if seed and seed not in ('""',):
            parts.insert(0, seed)
        if not parts:
            return '""'
        # An appended argument that is itself an expression must keep its
        # parentheses. `sb.append(size + 1)` folded to `"pop_" + size + 1`
        # means `"pop_3" + 1` -> "pop_31", which is a different string.
        # Observed against real code: Starsector's `increaseMarketSize`
        # decompiled to `addCondition("population_" + market.getSize() + 1)`
        # when the bytecode plainly computes `getSize() + 1` first.
        return " + ".join(
            f"({p})" if _has_toplevel_operator(p) else p for p in parts
        )

    prev = None
    cur = text
    for _ in range(4):  # nested builders need a couple of passes
        prev, cur = cur, _SB_CHAIN.sub(repl, cur)
        if cur == prev:
            break
    return cur


# --------------------------------------------------------------------------
# Structuring
# --------------------------------------------------------------------------


def _reverse_postorder(cfg: CFG) -> list[int]:
    seen: set[int] = set()
    order: list[int] = []

    def visit(n: int) -> None:
        stack = [(n, iter(cfg.blocks[n].succs))]
        seen.add(n)
        while stack:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                order.append(node)
                stack.pop()
            elif nxt not in seen and nxt in cfg.blocks:
                seen.add(nxt)
                stack.append((nxt, iter(cfg.blocks[nxt].succs)))

    if cfg.entry in cfg.blocks:
        visit(cfg.entry)
    for b in sorted(cfg.blocks):
        if b not in seen:
            visit(b)
    return list(reversed(order))


def _detect_ternary(cfg: CFG, head: int, code: dict[int, BlockCode]) -> tuple | None:
    """Recognise a conditional that produces a *value* rather than a branch.

    `condition(object != null, msg)` compiles to a jump over `iconst_1` into
    `iconst_0` -- a diamond whose arms each push one value and reconverge.
    Treating that as control flow yields `if (x != null) {} else {}` with the
    argument lost, which is how `Preconditions.notNull` first decompiled.

    Returns (join, expression) when the shape matches.
    """
    hb = cfg.blocks.get(head)
    hc = code.get(head)
    if hb is None or hc is None or not hc.condition or len(hb.succs) != 2:
        return None
    taken = hc.condition_target
    fall = next((s for s in hb.succs if s != taken), None)
    if taken is None or fall is None:
        return None

    arms = []
    for arm in (fall, taken):
        ab, ac = cfg.blocks.get(arm), code.get(arm)
        if ab is None or ac is None:
            return None
        if ac.statements or len(ab.preds) != 1 or len(ac.stack_out) != 1:
            return None
        if len(ab.succs) > 1:
            return None
        arms.append((arm, ab, ac))

    (_f, fb, fc), (_t, tb, tc) = arms
    fj = fb.succs[0] if fb.succs else None
    tj = tb.succs[0] if tb.succs else None
    if fj is None or fj != tj:
        return None

    cond = _invert_condition(hc.condition, "")  # fall-through is the `true` arm
    a, b = fc.stack_out[0], tc.stack_out[0]
    if {a.text, b.text} == {"0", "1"}:
        expr = Expr(cond if a.text == "1" else _invert_condition(cond, ""), P_EQ)
    else:
        expr = Expr(f"{cond} ? {a.text} : {b.text}", P_TERN)
    return (fj, expr, {fall, taken})


def _simulate(cfg: CFG, sim: "StackSim", handler_seed: dict[int, str]
              ) -> tuple[dict[int, BlockCode], tuple[dict[int, int], set[int]]]:
    """Simulate every block, propagating the operand stack across edges.

    Per-block simulation with an empty starting stack loses any value that
    spans a branch -- ternaries, boolean arguments, and string concatenation
    built across a conditional. Propagating along the CFG recovers them.
    """
    code: dict[int, BlockCode] = {}
    stack_in: dict[int, list[Expr]] = {}
    folded: dict[int, int] = {}   # folded conditional head -> its join block
    arms: set[int] = set()

    for pc, typ in handler_seed.items():
        stack_in[pc] = [Expr(f"caught{simple_name(typ)}")]

    order = _reverse_postorder(cfg)
    for start in order:
        blk = cfg.blocks[start]
        if start not in stack_in:
            preds = [p for p in blk.preds if p in code]
            if len(preds) == 1:
                stack_in[start] = list(code[preds[0]].stack_out)
            elif preds:
                outs = [code[p].stack_out for p in preds]
                depth = min(len(o) for o in outs)
                merged: list[Expr] = []
                for i in range(depth):
                    vals = {o[i].text for o in outs}
                    merged.append(outs[0][i] if len(vals) == 1 else Expr(f"phi{i}"))
                stack_in[start] = merged
            else:
                stack_in[start] = []
        code[start] = sim.run(blk.insns, stack_in[start])

    # Fold value-producing conditionals, then re-simulate the join with the
    # recovered expression on its stack.
    for head in list(order):
        hit = _detect_ternary(cfg, head, code)
        if not hit:
            continue
        join, expr, arm_blocks = hit
        folded[head] = join
        arms |= arm_blocks
        code[head].condition = None
        code[head].condition_target = None
        code[head].stack_out = list(code[head].stack_out) + [expr]
        if join in cfg.blocks:
            stack_in[join] = list(code[head].stack_out)
            code[join] = sim.run(cfg.blocks[join].insns, stack_in[join])

    return code, (folded, arms)


class Structurer:
    def __init__(self, cfg: CFG, blocks: dict[int, BlockCode],
                 exceptions=(), locals_: "Locals | None" = None) -> None:
        self.cfg = cfg
        self.code = blocks
        self.loops = {l["header"]: l for l in cfg.natural_loops()}
        self.pdom = cfg.post_dominators()
        self.emitted: set[int] = set()
        self.structured = True
        self.notes: list[str] = []
        self.locals = locals_
        # Conditionals folded into ternary expressions: emitting them as
        # control flow would produce empty if/else arms.
        self.folded: dict[int, int] = {}
        self.folded_arms: set[int] = set()
        # Protected regions, keyed by the block that starts them, so a `try`
        # can be opened when emission reaches that block.
        self.try_at: dict[int, list] = {}
        for e in exceptions:
            self.try_at.setdefault(e.start_pc, []).append(e)
        self.handlers = {e.handler_pc for e in exceptions}

    def ipdom(self, s: int) -> int | None:
        cands = self.pdom.get(s, set()) - {s}
        if not cands:
            return None
        for c in sorted(cands):
            if all(c == o or c not in (self.pdom.get(o, set()) - {o}) for o in cands):
                return c
        return min(cands)

    def emit(self, start: int, stop: int | None, indent: int,
             loop_ctx: tuple[int, int | None] | None = None) -> list[str]:
        lines: list[str] = []
        cur: int | None = start
        guard = 0

        while cur is not None and cur != stop:
            guard += 1
            if guard > 4000:
                self.structured = False
                self.notes.append("structuring aborted: region did not converge")
                break
            if cur not in self.cfg.blocks:
                break
            if cur in self.emitted:
                if loop_ctx and cur == loop_ctx[0]:
                    lines.append("    " * indent + "continue;")
                else:
                    lines.append("    " * indent + f"/* -> L{cur} */")
                    self.structured = False
                break

            blk = self.cfg.blocks[cur]
            bc = self.code.get(cur)

            # A conditional that produced a value, not a branch: emit its
            # statements and continue at the join.
            if cur in self.folded:
                self.emitted.add(cur)
                if bc:
                    for st_ in bc.statements:
                        lines.append("    " * indent + st_.text)
                cur = self.folded[cur]
                continue
            if cur in self.folded_arms:
                self.emitted.add(cur)
                cur = blk.succs[0] if blk.succs else None
                continue

            # A protected region begins here: emit try/catch around it.
            if cur in self.try_at and cur not in self.emitted:
                entries = self.try_at.pop(cur)
                lines.extend(self._emit_try(cur, entries, indent, loop_ctx))
                after = max(e.end_pc for e in entries)
                cur = after if after in self.cfg.blocks else None
                continue

            # A loop header we are not already inside.
            if cur in self.loops and (loop_ctx is None or loop_ctx[0] != cur):
                lines.extend(self._emit_loop(cur, indent))
                loop = self.loops[cur]
                exits = [e for e in loop["exits"]]
                cur = exits[0] if exits else None
                continue

            self.emitted.add(cur)

            if bc:
                for s in bc.statements:
                    lines.append("    " * indent + s.text)

            term = blk.terminator
            mn = term.mnemonic if term else None

            if mn in ("ireturn", "lreturn", "freturn", "dreturn", "areturn",
                      "return", "athrow"):
                return lines

            if bc and bc.condition and mn in CONDITIONS:
                lines.extend(self._emit_if(cur, bc, indent, loop_ctx))
                join = self.ipdom(cur)
                cur = join
                continue

            if bc and bc.condition and mn in ("tableswitch", "lookupswitch"):
                lines.extend(self._emit_switch(cur, bc, indent))
                cur = self.ipdom(cur)
                continue

            succs = blk.succs
            if len(succs) == 1:
                if loop_ctx and succs[0] == loop_ctx[0]:
                    lines.append("    " * indent + "continue;")
                    return lines
                if loop_ctx and loop_ctx[1] is not None and succs[0] == loop_ctx[1]:
                    lines.append("    " * indent + "break;")
                    return lines
                cur = succs[0]
            elif not succs:
                cur = None
            else:
                self.structured = False
                self.notes.append(f"block {cur} has {len(succs)} successors and no "
                                  "recognized shape")
                cur = succs[0]

        return lines

    def _emit_if(self, start: int, bc: BlockCode, indent: int,
                 loop_ctx) -> list[str]:
        blk = self.cfg.blocks[start]
        term = blk.terminator
        taken = bc.condition_target
        succs = blk.succs
        fall = next((s for s in succs if s != taken), None)

        # A JVM conditional jumps when true, so the fall-through is the
        # `then` arm only if we invert the printed condition.
        cond = _invert_condition(bc.condition, term.mnemonic if term else "")
        join = self.ipdom(start)

        lines = ["    " * indent + f"if ({cond}) {{"]
        if fall is not None and fall != join:
            lines.extend(self.emit(fall, join, indent + 1, loop_ctx))
        elif fall is not None and fall == join:
            lines.append("    " * (indent + 1) + "// (empty)")
        if taken is not None and taken != join:
            lines.append("    " * indent + "} else {")
            lines.extend(self.emit(taken, join, indent + 1, loop_ctx))
        lines.append("    " * indent + "}")
        return lines

    def _emit_try(self, start: int, entries, indent: int, loop_ctx) -> list[str]:
        """Emit a try/catch for a protected range.

        Without this the handler blocks were never emitted at all: `safeDiv`
        decompiled to just `return a / b;` with the entire catch clause
        silently missing, which is a correctness failure rather than a
        cosmetic one.
        """
        pad = "    " * indent
        end = max(e.end_pc for e in entries)
        lines = [pad + "try {"]
        lines.extend(self.emit(start, end if end in self.cfg.blocks else None,
                               indent + 1, loop_ctx))
        for e in entries:
            typ = simple_name(e.catch_type) if e.catch_type else "Throwable"
            name = "e"
            if self.locals is not None:
                # The handler stores the caught exception into a local first.
                hb = self.cfg.blocks.get(e.handler_pc)
                if hb and hb.insns:
                    first = hb.insns[0]
                    if first.mnemonic.startswith("astore"):
                        idx = first.operands.get("index")
                        if idx is None and "_" in first.mnemonic:
                            idx = int(first.mnemonic.rsplit("_", 1)[1])
                        if idx is not None:
                            name = self.locals.name(idx, first.pc)
            lines.append(pad + f"}} catch ({typ} {name}) {{")
            if e.handler_pc in self.cfg.blocks:
                self.emitted.discard(e.handler_pc)
                body = self.emit(e.handler_pc, None, indent + 1, loop_ctx)
                # Drop the synthetic store of the caught reference.
                lines.extend(l for l in body if not l.strip().startswith(f"{name} = "))
        lines.append(pad + "}")
        return lines

    def _emit_switch(self, start: int, bc: BlockCode, indent: int) -> list[str]:
        blk = self.cfg.blocks[start]
        term = blk.terminator
        o = term.operands if term else {}
        join = self.ipdom(start)
        lines = ["    " * indent + f"{bc.condition} {{"]
        keys = o.get("keys")
        targets = o.get("targets", [])
        low = o.get("low")
        for i, t in enumerate(targets):
            label = keys[i] if keys else (low + i if low is not None else i)
            lines.append("    " * (indent + 1) + f"case {label}:")
            lines.extend(self.emit(t, join, indent + 2, None))
            lines.append("    " * (indent + 2) + "break;")
        if o.get("default") is not None and o["default"] != join:
            lines.append("    " * (indent + 1) + "default:")
            lines.extend(self.emit(o["default"], join, indent + 2, None))
        lines.append("    " * indent + "}")
        return lines

    def _emit_loop(self, header: int, indent: int) -> list[str]:
        loop = self.loops[header]
        body_set = set(loop["body_blocks"])
        exits = loop["exits"]
        exit_block = exits[0] if exits else None

        blk = self.cfg.blocks[header]
        bc = self.code.get(header)
        term = blk.terminator
        self.emitted.add(header)

        # A header whose condition leaves the loop is a `while (cond)`.
        if bc and bc.condition and term and term.mnemonic in CONDITIONS:
            taken = bc.condition_target
            fall = next((s for s in blk.succs if s != taken), None)
            in_loop = fall if fall in body_set else taken
            leaves = taken if fall in body_set else fall
            if leaves is not None and leaves not in body_set:
                cond = bc.condition if in_loop == taken else _invert_condition(
                    bc.condition, term.mnemonic)
                lines = []
                if bc.statements:
                    lines.extend("    " * indent + s.text for s in bc.statements)
                lines.append("    " * indent + f"while ({cond}) {{")
                lines.extend(self.emit(in_loop, header, indent + 1, (header, leaves)))
                lines.append("    " * indent + "}")
                return lines

        lines = ["    " * indent + "while (true) {"]
        if bc:
            lines.extend("    " * (indent + 1) + s.text for s in bc.statements)
        first = blk.succs[0] if blk.succs else None
        if first is not None:
            lines.extend(self.emit(first, header, indent + 1, (header, exit_block)))
        lines.append("    " * indent + "}")
        return lines


_TERMINAL = ("return", "throw ", "break;", "continue;")


_COMPOUND = re.compile(
    r"^(\s*)([A-Za-z_$][\w$.\[\]]*) = \2 ([-+*/%^&|]|<<|>>>?) (.+);$"
)


_TOPLEVEL_OP = re.compile(r"(?:^|\s)(?:[-+*/%^&|]|<<|>>>?|\?|:)(?:\s|$)")


def _has_toplevel_operator(expr: str) -> bool:
    """True if `expr` contains a binary operator outside any bracket.

    This guard is load-bearing. Folding `h = h * 31 + c` into `h *= 31 + c`
    changes the meaning to `h * (31 + c)` -- a silently wrong transformation
    of exactly the kind this engine exists to refuse. The fold is only
    performed when the remainder is a single operand.
    """
    depth = 0
    i = 0
    while i < len(expr):
        c = expr[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif depth == 0 and c in "-+*/%^&|<>?:":
            # Ignore an operator glued to a token (unary minus, `->`).
            before = expr[i - 1] if i else " "
            after = expr[i + 1] if i + 1 < len(expr) else " "
            if before == " " and (after == " " or after in "<>="):
                return True
        i += 1
    return False


def _fold_assignments(line: str) -> str:
    """`x = x + 1` -> `x++`, `x = x ^ m` -> `x ^= m`.

    javac emits the expanded form; the source almost never contained it.
    Only folds when the right-hand side is a single operand -- see
    `_has_toplevel_operator` for why that restriction is not optional.
    """
    mo = _COMPOUND.match(line)
    if not mo:
        return line
    pad, name, op, rhs = mo.groups()
    if _has_toplevel_operator(rhs):
        return line
    if op == "+" and rhs == "1":
        return f"{pad}{name}++;"
    if op == "-" and rhs == "1":
        return f"{pad}{name}--;"
    return f"{pad}{name} {op}= {rhs};"


def _cleanup(lines: list[str], types: dict[str, str] | None = None) -> list[str]:
    """Remove control-flow statements that the structure already implies.

    A `continue;` as the last statement of a loop body, or a `break;` after a
    `return`, is correct but is noise the source never contained.
    """
    out: list[str] = []
    declared: set[str] = set()
    types = types or {}
    for i, line in enumerate(lines):
        s = line.strip()
        nxt = lines[i + 1].strip() if i + 1 < len(lines) else ""
        prev = out[-1].strip() if out else ""

        if s == "continue;" and nxt.startswith("}"):
            continue
        if s == "break;" and (prev.startswith("return") or prev.startswith("throw ")):
            continue
        if s == "// (empty)":
            continue

        line = _fold_assignments(line)

        # Give a local its declared type at its first assignment, so the
        # output reads as Java rather than as untyped pseudocode.
        dm = re.match(r"^(\s*)([A-Za-z_$]\w*) (=|\+\+|--|[-+*/%^&|]=|<<=|>>>?=)", line)
        if dm:
            nm = dm.group(2)
            if nm in types and nm not in declared:
                declared.add(nm)
                if dm.group(3) == "=":
                    line = f"{dm.group(1)}{types[nm]} {line.lstrip()}"
        out.append(line)

    # Collapse a trailing bare `return;` in a void method.
    while out and out[-1].strip() == "return;":
        out.pop()
    return out


def _invert_condition(cond: str, mnemonic: str) -> str:
    """Flip a printed condition so the fall-through arm reads as `then`."""
    if not cond:
        return "true"
    if cond.endswith("== null"):
        return cond[:-7] + "!= null"
    if cond.endswith("!= null"):
        return cond[:-7] + "== null"
    for op in (" >= ", " <= ", " != ", " == ", " > ", " < "):
        if op in cond:
            return cond.replace(op, f" {INVERT[op.strip()]} ", 1)
    if cond.startswith("!"):
        return cond[1:]
    if re.fullmatch(r"[A-Za-z_$][\w$.]*(\([^()]*\))?", cond):
        return f"!{cond}"      # a simple name or call needs no parentheses
    return f"!({cond})"


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def decompile_method(cf, member: Member, *, fold_strings: bool = True) -> dict[str, Any]:
    """Reconstruct one method's source-level logic."""
    if member.code is None:
        body = "abstract" if "abstract" in member.access else "native"
        return {
            "signature": member.signature_text(),
            "decompiled": f"{member.signature_text()};  // {body}, no bytecode",
            "structured": True,
            "block_count": 0,
            "instruction_count": 0,
            "notes": [f"method has no Code attribute ({body})"],
        }

    insns = decode(member.code.code)
    cfg = CFG(insns, member.code.exceptions)
    locals_ = Locals(member, member.code)
    sim = StackSim(cf.pool, locals_, member)

    # Straight-line simulation per block. Stack values that cross a block
    # boundary are rare in javac output outside of ternaries; where they do
    # occur the note is recorded rather than silently dropped.
    # The JVM pushes the caught reference onto an emptied stack before a
    # handler runs, so a handler block must start with that value present or
    # its leading `astore` underflows.
    handler_seed = {e.handler_pc: (e.catch_type or "Throwable")
                    for e in member.code.exceptions}

    block_code, folded = _simulate(cfg, sim, handler_seed)

    # Declared types for locals that are not parameters; parameters are
    # already typed by the signature.
    params, _ret = parse_method_descriptor(member.descriptor)
    param_slots = descriptor_slots(params) + (0 if member.is_static else 1)
    local_types: dict[str, str] = {}
    for lv in member.code.local_vars:
        if lv.index >= param_slots and lv.name != "this":
            local_types.setdefault(lv.name, simple_name(parse_type(lv.descriptor)[0]))

    st = Structurer(cfg, block_code, member.code.exceptions, locals_)
    st.folded, st.folded_arms = folded
    body = _cleanup(st.emit(cfg.entry, None, 1), local_types)

    notes = list(st.notes)
    for bc in block_code.values():
        notes.extend(bc.notes)
    carried = [f"block {s} leaves {len(bc.stack_out)} value(s) on the stack"
               for s, bc in block_code.items() if bc.stack_out]
    notes.extend(carried[:5])

    header = member.signature_text()
    if member.code.exceptions:
        notes.append(f"{len(member.code.exceptions)} exception handler(s); "
                     "try/catch regions are reported in the CFG but not re-nested")

    text = header + " {\n" + "\n".join(body) + "\n}"
    if fold_strings:
        text = fold_string_builders(text)

    return {
        "signature": header,
        "decompiled": text,
        "structured": st.structured and not carried,
        "block_count": len(cfg.blocks),
        "instruction_count": len(insns),
        "cyclomatic_complexity": cyclomatic_complexity(cfg),
        "loops": len(cfg.natural_loops()),
        "max_stack": member.code.max_stack,
        "max_locals": member.code.max_locals,
        "has_debug_names": bool(member.code.local_vars),
        "exception_handlers": [e.to_dict() for e in member.code.exceptions],
        "notes": notes[:12],
    }
