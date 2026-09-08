"""JVM bytecode decoding.

First principle: bytecode is not machine code, and pretending otherwise
throws away everything that makes it recoverable.

JVM bytecode carries type information in the opcodes themselves (`iadd` vs
`dadd`), addresses locals by index rather than by stack offset, keeps method
and field references as symbolic constant-pool entries rather than
addresses, and has an explicitly structured exception table. That is why a
JVM method can be decompiled to readable source while an x86 function
generally cannot: the information a native compiler destroys is still here.

This module decodes; `cfg.py` structures; `decompile.py` reconstructs
expressions and control flow.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

# Operand shapes. Each name maps to a decoder in `_decode_operands`.
NONE = "none"
U1 = "u1"                 # unsigned byte (local index, ldc index)
U2 = "u2"                 # unsigned short (cp index)
S1 = "s1"                 # signed byte (bipush)
S2 = "s2"                 # signed short (sipush)
BRANCH2 = "branch2"
BRANCH4 = "branch4"
IINC = "iinc"
NEWARRAY = "newarray"
INVOKEINTERFACE = "invokeinterface"
INVOKEDYNAMIC = "invokedynamic"
MULTIANEWARRAY = "multianewarray"
TABLESWITCH = "tableswitch"
LOOKUPSWITCH = "lookupswitch"
WIDE = "wide"

# opcode -> (mnemonic, operand shape)
OPCODES: dict[int, tuple[str, str]] = {
    0x00: ("nop", NONE), 0x01: ("aconst_null", NONE),
    0x02: ("iconst_m1", NONE), 0x03: ("iconst_0", NONE), 0x04: ("iconst_1", NONE),
    0x05: ("iconst_2", NONE), 0x06: ("iconst_3", NONE), 0x07: ("iconst_4", NONE),
    0x08: ("iconst_5", NONE),
    0x09: ("lconst_0", NONE), 0x0A: ("lconst_1", NONE),
    0x0B: ("fconst_0", NONE), 0x0C: ("fconst_1", NONE), 0x0D: ("fconst_2", NONE),
    0x0E: ("dconst_0", NONE), 0x0F: ("dconst_1", NONE),
    0x10: ("bipush", S1), 0x11: ("sipush", S2),
    0x12: ("ldc", U1), 0x13: ("ldc_w", U2), 0x14: ("ldc2_w", U2),
    0x15: ("iload", U1), 0x16: ("lload", U1), 0x17: ("fload", U1),
    0x18: ("dload", U1), 0x19: ("aload", U1),
    0x1A: ("iload_0", NONE), 0x1B: ("iload_1", NONE), 0x1C: ("iload_2", NONE), 0x1D: ("iload_3", NONE),
    0x1E: ("lload_0", NONE), 0x1F: ("lload_1", NONE), 0x20: ("lload_2", NONE), 0x21: ("lload_3", NONE),
    0x22: ("fload_0", NONE), 0x23: ("fload_1", NONE), 0x24: ("fload_2", NONE), 0x25: ("fload_3", NONE),
    0x26: ("dload_0", NONE), 0x27: ("dload_1", NONE), 0x28: ("dload_2", NONE), 0x29: ("dload_3", NONE),
    0x2A: ("aload_0", NONE), 0x2B: ("aload_1", NONE), 0x2C: ("aload_2", NONE), 0x2D: ("aload_3", NONE),
    0x2E: ("iaload", NONE), 0x2F: ("laload", NONE), 0x30: ("faload", NONE),
    0x31: ("daload", NONE), 0x32: ("aaload", NONE), 0x33: ("baload", NONE),
    0x34: ("caload", NONE), 0x35: ("saload", NONE),
    0x36: ("istore", U1), 0x37: ("lstore", U1), 0x38: ("fstore", U1),
    0x39: ("dstore", U1), 0x3A: ("astore", U1),
    0x3B: ("istore_0", NONE), 0x3C: ("istore_1", NONE), 0x3D: ("istore_2", NONE), 0x3E: ("istore_3", NONE),
    0x3F: ("lstore_0", NONE), 0x40: ("lstore_1", NONE), 0x41: ("lstore_2", NONE), 0x42: ("lstore_3", NONE),
    0x43: ("fstore_0", NONE), 0x44: ("fstore_1", NONE), 0x45: ("fstore_2", NONE), 0x46: ("fstore_3", NONE),
    0x47: ("dstore_0", NONE), 0x48: ("dstore_1", NONE), 0x49: ("dstore_2", NONE), 0x4A: ("dstore_3", NONE),
    0x4B: ("astore_0", NONE), 0x4C: ("astore_1", NONE), 0x4D: ("astore_2", NONE), 0x4E: ("astore_3", NONE),
    0x4F: ("iastore", NONE), 0x50: ("lastore", NONE), 0x51: ("fastore", NONE),
    0x52: ("dastore", NONE), 0x53: ("aastore", NONE), 0x54: ("bastore", NONE),
    0x55: ("castore", NONE), 0x56: ("sastore", NONE),
    0x57: ("pop", NONE), 0x58: ("pop2", NONE),
    0x59: ("dup", NONE), 0x5A: ("dup_x1", NONE), 0x5B: ("dup_x2", NONE),
    0x5C: ("dup2", NONE), 0x5D: ("dup2_x1", NONE), 0x5E: ("dup2_x2", NONE),
    0x5F: ("swap", NONE),
    0x60: ("iadd", NONE), 0x61: ("ladd", NONE), 0x62: ("fadd", NONE), 0x63: ("dadd", NONE),
    0x64: ("isub", NONE), 0x65: ("lsub", NONE), 0x66: ("fsub", NONE), 0x67: ("dsub", NONE),
    0x68: ("imul", NONE), 0x69: ("lmul", NONE), 0x6A: ("fmul", NONE), 0x6B: ("dmul", NONE),
    0x6C: ("idiv", NONE), 0x6D: ("ldiv", NONE), 0x6E: ("fdiv", NONE), 0x6F: ("ddiv", NONE),
    0x70: ("irem", NONE), 0x71: ("lrem", NONE), 0x72: ("frem", NONE), 0x73: ("drem", NONE),
    0x74: ("ineg", NONE), 0x75: ("lneg", NONE), 0x76: ("fneg", NONE), 0x77: ("dneg", NONE),
    0x78: ("ishl", NONE), 0x79: ("lshl", NONE), 0x7A: ("ishr", NONE), 0x7B: ("lshr", NONE),
    0x7C: ("iushr", NONE), 0x7D: ("lushr", NONE),
    0x7E: ("iand", NONE), 0x7F: ("land", NONE), 0x80: ("ior", NONE), 0x81: ("lor", NONE),
    0x82: ("ixor", NONE), 0x83: ("lxor", NONE),
    0x84: ("iinc", IINC),
    0x85: ("i2l", NONE), 0x86: ("i2f", NONE), 0x87: ("i2d", NONE),
    0x88: ("l2i", NONE), 0x89: ("l2f", NONE), 0x8A: ("l2d", NONE),
    0x8B: ("f2i", NONE), 0x8C: ("f2l", NONE), 0x8D: ("f2d", NONE),
    0x8E: ("d2i", NONE), 0x8F: ("d2l", NONE), 0x90: ("d2f", NONE),
    0x91: ("i2b", NONE), 0x92: ("i2c", NONE), 0x93: ("i2s", NONE),
    0x94: ("lcmp", NONE),
    0x95: ("fcmpl", NONE), 0x96: ("fcmpg", NONE),
    0x97: ("dcmpl", NONE), 0x98: ("dcmpg", NONE),
    0x99: ("ifeq", BRANCH2), 0x9A: ("ifne", BRANCH2), 0x9B: ("iflt", BRANCH2),
    0x9C: ("ifge", BRANCH2), 0x9D: ("ifgt", BRANCH2), 0x9E: ("ifle", BRANCH2),
    0x9F: ("if_icmpeq", BRANCH2), 0xA0: ("if_icmpne", BRANCH2), 0xA1: ("if_icmplt", BRANCH2),
    0xA2: ("if_icmpge", BRANCH2), 0xA3: ("if_icmpgt", BRANCH2), 0xA4: ("if_icmple", BRANCH2),
    0xA5: ("if_acmpeq", BRANCH2), 0xA6: ("if_acmpne", BRANCH2),
    0xA7: ("goto", BRANCH2), 0xA8: ("jsr", BRANCH2), 0xA9: ("ret", U1),
    0xAA: ("tableswitch", TABLESWITCH), 0xAB: ("lookupswitch", LOOKUPSWITCH),
    0xAC: ("ireturn", NONE), 0xAD: ("lreturn", NONE), 0xAE: ("freturn", NONE),
    0xAF: ("dreturn", NONE), 0xB0: ("areturn", NONE), 0xB1: ("return", NONE),
    0xB2: ("getstatic", U2), 0xB3: ("putstatic", U2),
    0xB4: ("getfield", U2), 0xB5: ("putfield", U2),
    0xB6: ("invokevirtual", U2), 0xB7: ("invokespecial", U2), 0xB8: ("invokestatic", U2),
    0xB9: ("invokeinterface", INVOKEINTERFACE), 0xBA: ("invokedynamic", INVOKEDYNAMIC),
    0xBB: ("new", U2), 0xBC: ("newarray", NEWARRAY), 0xBD: ("anewarray", U2),
    0xBE: ("arraylength", NONE), 0xBF: ("athrow", NONE),
    0xC0: ("checkcast", U2), 0xC1: ("instanceof", U2),
    0xC2: ("monitorenter", NONE), 0xC3: ("monitorexit", NONE),
    0xC4: ("wide", WIDE),
    0xC5: ("multianewarray", MULTIANEWARRAY),
    0xC6: ("ifnull", BRANCH2), 0xC7: ("ifnonnull", BRANCH2),
    0xC8: ("goto_w", BRANCH4), 0xC9: ("jsr_w", BRANCH4),
    0xCA: ("breakpoint", NONE), 0xFE: ("impdep1", NONE), 0xFF: ("impdep2", NONE),
}

ARRAY_TYPES = {
    4: "boolean", 5: "char", 6: "float", 7: "double",
    8: "byte", 9: "short", 10: "int", 11: "long",
}

# Opcodes that end a basic block.
BRANCH_OPS = {
    "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle",
    "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple",
    "if_acmpeq", "if_acmpne", "ifnull", "ifnonnull",
}
GOTO_OPS = {"goto", "goto_w"}
RETURN_OPS = {"ireturn", "lreturn", "freturn", "dreturn", "areturn", "return"}
SWITCH_OPS = {"tableswitch", "lookupswitch"}
TERMINATORS = BRANCH_OPS | GOTO_OPS | RETURN_OPS | SWITCH_OPS | {"athrow", "ret"}

# Conditional opcode -> (java operator, operand count, compares-against-zero)
CONDITIONS = {
    "ifeq": ("==", 1, True), "ifne": ("!=", 1, True),
    "iflt": ("<", 1, True), "ifge": (">=", 1, True),
    "ifgt": (">", 1, True), "ifle": ("<=", 1, True),
    "if_icmpeq": ("==", 2, False), "if_icmpne": ("!=", 2, False),
    "if_icmplt": ("<", 2, False), "if_icmpge": (">=", 2, False),
    "if_icmpgt": (">", 2, False), "if_icmple": ("<=", 2, False),
    "if_acmpeq": ("==", 2, False), "if_acmpne": ("!=", 2, False),
    "ifnull": ("== null", 1, True), "ifnonnull": ("!= null", 1, True),
}

# Inverted conditions, for emitting `if (!cond)` as a positive test.
INVERT = {
    "==": "!=", "!=": "==", "<": ">=", ">=": "<", ">": "<=", "<=": ">",
    "== null": "!= null", "!= null": "== null",
}


@dataclass
class Insn:
    pc: int
    opcode: int
    mnemonic: str
    size: int
    operands: dict[str, Any] = field(default_factory=dict)
    wide: bool = False

    @property
    def targets(self) -> list[int]:
        """Branch targets, in the order the JVM spec lists them."""
        out: list[int] = []
        if "target" in self.operands:
            out.append(int(self.operands["target"]))
        for k in ("default", "targets"):
            v = self.operands.get(k)
            if isinstance(v, int):
                out.append(v)
            elif isinstance(v, list):
                out.extend(int(t) for t in v)
        return out

    def to_dict(self, pool=None) -> dict:
        d: dict[str, Any] = {
            "pc": self.pc,
            "opcode": f"0x{self.opcode:02x}",
            "mnemonic": self.mnemonic,
            "size": self.size,
        }
        if self.wide:
            d["wide"] = True
        if self.operands:
            d["operands"] = dict(self.operands)
        if pool is not None:
            ref = describe_ref(self, pool)
            if ref:
                d["ref"] = ref
        return d


def _s1(b: bytes, i: int) -> int:
    return struct.unpack_from(">b", b, i)[0]


def _u1(b: bytes, i: int) -> int:
    return b[i]


def _s2(b: bytes, i: int) -> int:
    return struct.unpack_from(">h", b, i)[0]


def _u2(b: bytes, i: int) -> int:
    return struct.unpack_from(">H", b, i)[0]


def _s4(b: bytes, i: int) -> int:
    return struct.unpack_from(">i", b, i)[0]


def decode(code: bytes) -> list[Insn]:
    """Decode a Code attribute's bytes into instructions.

    Undecodable bytes stop the sweep rather than resyncing: unlike a native
    linear sweep over data-interleaved sections, a JVM Code array contains
    only instructions, so a bad opcode means the input is malformed and
    guessing past it would fabricate a method body.
    """
    out: list[Insn] = []
    pc = 0
    n = len(code)
    while pc < n:
        op = code[pc]
        entry = OPCODES.get(op)
        if entry is None:
            out.append(Insn(pc=pc, opcode=op, mnemonic=f".byte 0x{op:02x}", size=1,
                            operands={"undecodable": True}))
            break
        name, shape = entry
        try:
            insn = _decode_one(code, pc, op, name, shape)
        except (struct.error, IndexError):
            out.append(Insn(pc=pc, opcode=op, mnemonic=name, size=n - pc,
                            operands={"truncated": True}))
            break
        out.append(insn)
        pc += insn.size
    return out


def _decode_one(code: bytes, pc: int, op: int, name: str, shape: str) -> Insn:
    o: dict[str, Any] = {}

    if shape == NONE:
        return Insn(pc, op, name, 1)
    if shape == U1:
        o["index"] = _u1(code, pc + 1)
        return Insn(pc, op, name, 2, o)
    if shape == S1:
        o["value"] = _s1(code, pc + 1)
        return Insn(pc, op, name, 2, o)
    if shape == U2:
        o["index"] = _u2(code, pc + 1)
        return Insn(pc, op, name, 3, o)
    if shape == S2:
        o["value"] = _s2(code, pc + 1)
        return Insn(pc, op, name, 3, o)
    if shape == BRANCH2:
        o["target"] = pc + _s2(code, pc + 1)
        return Insn(pc, op, name, 3, o)
    if shape == BRANCH4:
        o["target"] = pc + _s4(code, pc + 1)
        return Insn(pc, op, name, 5, o)
    if shape == IINC:
        o["index"] = _u1(code, pc + 1)
        o["const"] = _s1(code, pc + 2)
        return Insn(pc, op, name, 3, o)
    if shape == NEWARRAY:
        t = _u1(code, pc + 1)
        o["atype"] = t
        o["type"] = ARRAY_TYPES.get(t, f"?{t}")
        return Insn(pc, op, name, 2, o)
    if shape == INVOKEINTERFACE:
        o["index"] = _u2(code, pc + 1)
        o["count"] = _u1(code, pc + 3)
        return Insn(pc, op, name, 5, o)
    if shape == INVOKEDYNAMIC:
        o["index"] = _u2(code, pc + 1)
        return Insn(pc, op, name, 5, o)
    if shape == MULTIANEWARRAY:
        o["index"] = _u2(code, pc + 1)
        o["dimensions"] = _u1(code, pc + 3)
        return Insn(pc, op, name, 4, o)
    if shape == WIDE:
        sub = _u1(code, pc + 1)
        sub_name = OPCODES.get(sub, ("?", NONE))[0]
        if sub_name == "iinc":
            o["index"] = _u2(code, pc + 2)
            o["const"] = _s2(code, pc + 4)
            return Insn(pc, sub, sub_name, 6, o, wide=True)
        o["index"] = _u2(code, pc + 2)
        return Insn(pc, sub, sub_name, 4, o, wide=True)
    if shape == TABLESWITCH:
        base = pc + 1
        pad = (4 - (base % 4)) % 4
        i = base + pad
        default = pc + _s4(code, i)
        low = _s4(code, i + 4)
        high = _s4(code, i + 8)
        count = high - low + 1
        targets = [pc + _s4(code, i + 12 + k * 4) for k in range(max(count, 0))]
        o.update({"default": default, "low": low, "high": high, "targets": targets})
        return Insn(pc, op, name, (i + 12 + max(count, 0) * 4) - pc, o)
    if shape == LOOKUPSWITCH:
        base = pc + 1
        pad = (4 - (base % 4)) % 4
        i = base + pad
        default = pc + _s4(code, i)
        npairs = _s4(code, i + 4)
        keys: list[int] = []
        targets: list[int] = []
        for k in range(max(npairs, 0)):
            keys.append(_s4(code, i + 8 + k * 8))
            targets.append(pc + _s4(code, i + 12 + k * 8))
        o.update({"default": default, "keys": keys, "targets": targets})
        return Insn(pc, op, name, (i + 8 + max(npairs, 0) * 8) - pc, o)

    return Insn(pc, op, name, 1, o)


def describe_ref(insn: Insn, pool) -> str | None:
    """Resolve a constant-pool operand into a human-readable reference."""
    idx = insn.operands.get("index")
    if not idx:
        return None
    m = insn.mnemonic
    if m in ("getstatic", "putstatic", "getfield", "putfield"):
        return pool.fieldref_at(idx)
    if m in ("invokevirtual", "invokespecial", "invokestatic", "invokeinterface"):
        return pool.methodref_at(idx)
    if m == "invokedynamic":
        return pool.invokedynamic_at(idx)
    if m in ("new", "anewarray", "checkcast", "instanceof", "multianewarray"):
        return pool.class_at(idx)
    if m in ("ldc", "ldc_w", "ldc2_w"):
        return pool.constant_at(idx)
    return None
