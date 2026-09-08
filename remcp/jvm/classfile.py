"""Full class-file parser: constant values, attribute bodies, method code.

The inventory parser in `remcp/formats/classfile.py` reads attribute *names*
and skips their bodies -- enough to answer "what classes and methods exist",
which is where JVM support stopped. Decompilation needs the bodies: the
Code attribute holding the bytecode, the exception table, and the optional
LocalVariableTable that carries real parameter names when a jar was not
compiled with `-g:none`.

This parser is a superset and is kept separate so the fast inventory path
stays cheap.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from ..errors import FormatError

TAGS = {
    1: "Utf8", 3: "Integer", 4: "Float", 5: "Long", 6: "Double", 7: "Class",
    8: "String", 9: "Fieldref", 10: "Methodref", 11: "InterfaceMethodref",
    12: "NameAndType", 15: "MethodHandle", 16: "MethodType", 17: "Dynamic",
    18: "InvokeDynamic", 19: "Module", 20: "Package",
}

ACC = [
    (0x0001, "public"), (0x0002, "private"), (0x0004, "protected"),
    (0x0008, "static"), (0x0010, "final"), (0x0020, "synchronized"),
    (0x0040, "volatile"), (0x0080, "transient"), (0x0100, "native"),
    (0x0200, "interface"), (0x0400, "abstract"), (0x0800, "strictfp"),
    (0x1000, "synthetic"), (0x2000, "annotation"), (0x4000, "enum"),
]

PRIMITIVES = {
    "B": "byte", "C": "char", "D": "double", "F": "float",
    "I": "int", "J": "long", "S": "short", "Z": "boolean", "V": "void",
}


def flags_to_names(flags: int, *, is_method: bool = False) -> list[str]:
    out = []
    for bit, name in ACC:
        if flags & bit:
            if name == "synchronized" and not is_method:
                name = "super"
            if name == "volatile" and is_method:
                name = "bridge"
            if name == "transient" and is_method:
                name = "varargs"
            out.append(name)
    return out


class Reader:
    def __init__(self, data: bytes) -> None:
        self.d = data
        self.i = 0

    def need(self, n: int) -> None:
        if self.i + n > len(self.d):
            raise FormatError(
                f"class file truncated: wanted {n} bytes at offset {self.i}, "
                f"only {len(self.d) - self.i} remain"
            )

    def u1(self) -> int:
        self.need(1); v = self.d[self.i]; self.i += 1; return v

    def u2(self) -> int:
        self.need(2); v = struct.unpack_from(">H", self.d, self.i)[0]; self.i += 2; return v

    def u4(self) -> int:
        self.need(4); v = struct.unpack_from(">I", self.d, self.i)[0]; self.i += 4; return v

    def s4(self) -> int:
        self.need(4); v = struct.unpack_from(">i", self.d, self.i)[0]; self.i += 4; return v

    def raw(self, n: int) -> bytes:
        self.need(n); v = self.d[self.i:self.i + n]; self.i += n; return v

    def skip(self, n: int) -> None:
        self.need(n); self.i += n


class Pool:
    """Constant pool with resolved values, not just tags.

    `ldc` pushing a String must yield the string's text for decompiled
    output to be readable; the inventory parser skipped those bytes.
    """

    def __init__(self, count: int) -> None:
        self.count = count
        self.entries: dict[int, dict] = {}
        self.utf8: dict[int, str] = {}

    # --- primitive accessors ----------------------------------------------

    def utf8_at(self, idx: int) -> str | None:
        return self.utf8.get(idx)

    def class_at(self, idx: int) -> str | None:
        e = self.entries.get(idx)
        if not e or e["tag"] != "Class":
            return None
        raw = self.utf8_at(e["name_index"])
        return raw.replace("/", ".") if raw else None

    def nat_at(self, idx: int) -> tuple[str, str] | None:
        e = self.entries.get(idx)
        if not e or e["tag"] != "NameAndType":
            return None
        return (self.utf8_at(e["name_index"]) or "?", self.utf8_at(e["desc_index"]) or "?")

    # --- composite accessors used by the disassembler ---------------------

    def _ref(self, idx: int, want: tuple[str, ...]) -> tuple[str, str, str] | None:
        e = self.entries.get(idx)
        if not e or e["tag"] not in want:
            return None
        cls = self.class_at(e["class_index"]) or "?"
        nat = self.nat_at(e["nat_index"]) or ("?", "?")
        return (cls, nat[0], nat[1])

    def fieldref(self, idx: int):
        return self._ref(idx, ("Fieldref",))

    def methodref(self, idx: int):
        return self._ref(idx, ("Methodref", "InterfaceMethodref"))

    def fieldref_at(self, idx: int) -> str | None:
        r = self.fieldref(idx)
        return f"{r[0]}.{r[1]}:{r[2]}" if r else None

    def methodref_at(self, idx: int) -> str | None:
        r = self.methodref(idx)
        return f"{r[0]}.{r[1]}{r[2]}" if r else None

    def invokedynamic_at(self, idx: int) -> str | None:
        e = self.entries.get(idx)
        if not e or e["tag"] not in ("InvokeDynamic", "Dynamic"):
            return None
        nat = self.nat_at(e["nat_index"]) or ("?", "?")
        return f"<dynamic>.{nat[0]}{nat[1]} (bsm #{e['bootstrap_index']})"

    def constant_at(self, idx: int) -> Any:
        """The literal value an `ldc` family opcode pushes."""
        e = self.entries.get(idx)
        if not e:
            return None
        tag = e["tag"]
        if tag == "String":
            return self.utf8_at(e["string_index"])
        if tag in ("Integer", "Long", "Float", "Double"):
            return e.get("value")
        if tag == "Class":
            return f"{self.class_at(idx)}.class"
        if tag == "MethodType":
            return f"MethodType({self.utf8_at(e['desc_index'])})"
        if tag == "MethodHandle":
            return f"MethodHandle(kind={e['kind']}, #{e['ref_index']})"
        return None

    def constant_kind(self, idx: int) -> str | None:
        e = self.entries.get(idx)
        return e["tag"] if e else None


def parse_pool(r: Reader) -> Pool:
    count = r.u2()
    pool = Pool(count)
    idx = 1
    while idx < count:
        tag = r.u1()
        name = TAGS.get(tag)
        if name is None:
            raise FormatError(
                f"unknown constant pool tag {tag} at index {idx}; refusing to guess "
                "the layout of the remaining pool"
            )
        if name == "Utf8":
            text = r.raw(r.u2()).decode("utf-8", errors="replace")
            pool.utf8[idx] = text
            pool.entries[idx] = {"tag": name}
        elif name == "Integer":
            pool.entries[idx] = {"tag": name, "value": struct.unpack(">i", r.raw(4))[0]}
        elif name == "Float":
            pool.entries[idx] = {"tag": name, "value": struct.unpack(">f", r.raw(4))[0]}
        elif name == "Long":
            pool.entries[idx] = {"tag": name, "value": struct.unpack(">q", r.raw(8))[0]}
            idx += 1
        elif name == "Double":
            pool.entries[idx] = {"tag": name, "value": struct.unpack(">d", r.raw(8))[0]}
            idx += 1
        elif name == "Class":
            pool.entries[idx] = {"tag": name, "name_index": r.u2()}
        elif name == "String":
            pool.entries[idx] = {"tag": name, "string_index": r.u2()}
        elif name in ("Fieldref", "Methodref", "InterfaceMethodref"):
            pool.entries[idx] = {"tag": name, "class_index": r.u2(), "nat_index": r.u2()}
        elif name == "NameAndType":
            pool.entries[idx] = {"tag": name, "name_index": r.u2(), "desc_index": r.u2()}
        elif name == "MethodHandle":
            pool.entries[idx] = {"tag": name, "kind": r.u1(), "ref_index": r.u2()}
        elif name == "MethodType":
            pool.entries[idx] = {"tag": name, "desc_index": r.u2()}
        elif name in ("Dynamic", "InvokeDynamic"):
            pool.entries[idx] = {"tag": name, "bootstrap_index": r.u2(), "nat_index": r.u2()}
        else:  # Module / Package
            pool.entries[idx] = {"tag": name, "name_index": r.u2()}
        idx += 1
    return pool


# --------------------------------------------------------------------------
# Descriptors
# --------------------------------------------------------------------------


def parse_type(desc: str, i: int = 0) -> tuple[str, int]:
    """Decode one field descriptor, returning (java type, next index)."""
    if i >= len(desc):
        return ("?", i)
    c = desc[i]
    if c in PRIMITIVES:
        return (PRIMITIVES[c], i + 1)
    if c == "[":
        inner, j = parse_type(desc, i + 1)
        return (inner + "[]", j)
    if c == "L":
        end = desc.find(";", i)
        if end == -1:
            return ("?", len(desc))
        return (desc[i + 1:end].replace("/", "."), end + 1)
    return ("?", i + 1)


def parse_method_descriptor(desc: str) -> tuple[list[str], str]:
    """`(Ljava/lang/String;I)V` -> (['java.lang.String', 'int'], 'void')."""
    if not desc.startswith("("):
        return ([], "?")
    params: list[str] = []
    i = 1
    while i < len(desc) and desc[i] != ")":
        t, i = parse_type(desc, i)
        params.append(t)
    ret, _ = parse_type(desc, i + 1) if i < len(desc) else ("?", i)
    return (params, ret)


def simple_name(qualified: str) -> str:
    return qualified.rsplit(".", 1)[-1]


def descriptor_slots(params: list[str]) -> int:
    """Local-variable slots a parameter list occupies (long/double take two)."""
    return sum(2 if p in ("long", "double") else 1 for p in params)


# --------------------------------------------------------------------------
# Attributes and members
# --------------------------------------------------------------------------


@dataclass
class ExceptionEntry:
    start_pc: int
    end_pc: int
    handler_pc: int
    catch_type: str | None

    def to_dict(self) -> dict:
        return {
            "start_pc": self.start_pc, "end_pc": self.end_pc,
            "handler_pc": self.handler_pc,
            "catch_type": self.catch_type or "any",
        }


@dataclass
class LocalVar:
    start_pc: int
    length: int
    name: str
    descriptor: str
    index: int


@dataclass
class Code:
    max_stack: int
    max_locals: int
    code: bytes
    exceptions: list[ExceptionEntry] = field(default_factory=list)
    line_numbers: list[tuple[int, int]] = field(default_factory=list)
    local_vars: list[LocalVar] = field(default_factory=list)

    def line_for(self, pc: int) -> int | None:
        best = None
        for start, line in sorted(self.line_numbers):
            if start <= pc:
                best = line
            else:
                break
        return best

    def local_name(self, index: int, pc: int) -> str | None:
        """Debug name for a local slot.

        A LocalVariableTable entry's scope begins *after* the store that
        initialises it, so an exact pc match misses the very statement that
        creates the variable -- `total = 0` was rendering as `v2 = 0`.
        Falling back to the slot's unique name outside its live range fixes
        that; the fallback is skipped when a slot is reused for two
        different variables, where only the live range disambiguates.
        """
        for lv in self.local_vars:
            if lv.index == index and lv.start_pc <= pc < lv.start_pc + lv.length:
                return lv.name
        names = {lv.name for lv in self.local_vars if lv.index == index}
        return names.pop() if len(names) == 1 else None

    def name_for_slot(self, slot: int) -> str | None:
        """Declared name for a local slot, ignoring live range."""
        cands = [lv.name for lv in self.local_vars if lv.index == slot]
        return cands[0] if cands else None

    def param_names(self, params: list[str], first_slot: int) -> list[str | None]:
        """Declared parameter names, respecting that long/double take two slots."""
        out: list[str | None] = []
        slot = first_slot
        for p in params:
            out.append(self.name_for_slot(slot))
            slot += 2 if p in ("long", "double") else 1
        return out


@dataclass
class Member:
    kind: str
    name: str
    descriptor: str
    flags: int
    access: list[str]
    code: Code | None = None
    exceptions_thrown: list[str] = field(default_factory=list)
    constant_value: Any = None
    signature: str | None = None
    attribute_names: list[str] = field(default_factory=list)

    @property
    def params(self) -> list[str]:
        return parse_method_descriptor(self.descriptor)[0] if self.kind == "method" else []

    @property
    def return_type(self) -> str:
        return parse_method_descriptor(self.descriptor)[1] if self.kind == "method" else \
            parse_type(self.descriptor)[0]

    @property
    def is_static(self) -> bool:
        return "static" in self.access

    def signature_text(self) -> str:
        if self.kind == "field":
            return f"{' '.join(self.access)} {self.return_type} {self.name}".strip()
        params, ret = parse_method_descriptor(self.descriptor)

        # Prefer real parameter names from the LocalVariableTable over
        # positional placeholders; `sumEven(int[] xs)` beats `sumEven(int[] a0)`.
        names: list[str | None] = [None] * len(params)
        if self.code is not None:
            slot = 0 if self.is_static else 1
            declared = self.code.param_names(params, slot)
            for i, nm in enumerate(declared):
                if nm and nm != "this":
                    names[i] = nm

        args = ", ".join(
            f"{simple_name(p)} {names[i] or f'a{i}'}" for i, p in enumerate(params)
        )
        mods = " ".join(self.access)
        throws = f" throws {', '.join(simple_name(e) for e in self.exceptions_thrown)}" \
            if self.exceptions_thrown else ""
        return f"{mods} {simple_name(ret)} {self.name}({args}){throws}".strip()


def _parse_code(r: Reader, pool: Pool, length: int) -> Code:
    end = r.i + length
    max_stack = r.u2()
    max_locals = r.u2()
    code = r.raw(r.u4())

    exceptions: list[ExceptionEntry] = []
    for _ in range(r.u2()):
        s, e, h, t = r.u2(), r.u2(), r.u2(), r.u2()
        exceptions.append(ExceptionEntry(s, e, h, pool.class_at(t) if t else None))

    lines: list[tuple[int, int]] = []
    locals_: list[LocalVar] = []
    for _ in range(r.u2()):
        an = pool.utf8_at(r.u2()) or "?"
        alen = r.u4()
        stop = r.i + alen
        if an == "LineNumberTable":
            for _ in range(r.u2()):
                lines.append((r.u2(), r.u2()))
        elif an in ("LocalVariableTable", "LocalVariableTypeTable"):
            for _ in range(r.u2()):
                sp, ln, ni, di, ix = r.u2(), r.u2(), r.u2(), r.u2(), r.u2()
                locals_.append(LocalVar(sp, ln, pool.utf8_at(ni) or f"v{ix}",
                                        pool.utf8_at(di) or "?", ix))
        r.i = min(stop, end)

    r.i = end
    return Code(max_stack, max_locals, code, exceptions, lines, locals_)


def parse_members(r: Reader, pool: Pool, kind: str) -> list[Member]:
    out: list[Member] = []
    for _ in range(r.u2()):
        flags = r.u2()
        name = pool.utf8_at(r.u2()) or "?"
        desc = pool.utf8_at(r.u2()) or "?"
        m = Member(kind=kind, name=name, descriptor=desc, flags=flags,
                   access=flags_to_names(flags, is_method=(kind == "method")))
        for _ in range(r.u2()):
            an = pool.utf8_at(r.u2()) or "?"
            alen = r.u4()
            stop = r.i + alen
            m.attribute_names.append(an)
            if an == "Code" and kind == "method":
                m.code = _parse_code(r, pool, alen)
            elif an == "Exceptions":
                for _ in range(r.u2()):
                    c = pool.class_at(r.u2())
                    if c:
                        m.exceptions_thrown.append(c)
            elif an == "ConstantValue":
                m.constant_value = pool.constant_at(r.u2())
            elif an == "Signature":
                m.signature = pool.utf8_at(r.u2())
            r.i = stop
        out.append(m)
    return out


@dataclass
class ClassFile:
    major: int
    minor: int
    access: list[str]
    name: str
    superclass: str | None
    interfaces: list[str]
    fields: list[Member]
    methods: list[Member]
    pool: Pool
    source_file: str | None = None

    def method(self, name: str, descriptor: str = "") -> Member | None:
        for m in self.methods:
            if m.name == name and (not descriptor or m.descriptor == descriptor):
                return m
        return None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "superclass": self.superclass,
            "interfaces": self.interfaces,
            "access": self.access,
            "class_file_version": f"{self.major}.{self.minor}",
            "source_file": self.source_file,
            "field_count": len(self.fields),
            "method_count": len(self.methods),
            "constant_pool_size": self.pool.count,
        }


def parse(data: bytes) -> ClassFile:
    r = Reader(data)
    if r.u4() != 0xCAFEBABE:
        raise FormatError("not a class file: missing 0xCAFEBABE magic")
    minor, major = r.u2(), r.u2()
    pool = parse_pool(r)
    flags = r.u2()
    this_class = pool.class_at(r.u2()) or "?"
    super_idx = r.u2()
    superclass = pool.class_at(super_idx) if super_idx else None
    interfaces = [pool.class_at(r.u2()) or "?" for _ in range(r.u2())]
    fields = parse_members(r, pool, "field")
    methods = parse_members(r, pool, "method")

    source_file = None
    try:
        for _ in range(r.u2()):
            an = pool.utf8_at(r.u2()) or "?"
            alen = r.u4()
            stop = r.i + alen
            if an == "SourceFile":
                source_file = pool.utf8_at(r.u2())
            r.i = stop
    except FormatError:
        pass  # trailing class attributes are optional for our purposes

    return ClassFile(
        major=major, minor=minor, access=flags_to_names(flags),
        name=this_class, superclass=superclass, interfaces=interfaces,
        fields=fields, methods=methods, pool=pool, source_file=source_file,
    )
