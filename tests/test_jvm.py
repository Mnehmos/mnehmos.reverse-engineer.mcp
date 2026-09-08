"""JVM bytecode, CFG and decompiler tests.

`fixtures/Algo.class` is compiled from `fixtures/Algo.java`, which is checked
in beside it. That makes these ground-truth tests rather than eyeball tests:
the expected logic is known exactly, so a decompiler regression that still
produces plausible-looking Java will fail.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from remcp.errors import FormatError
from remcp.jvm import cfg as jcfg
from remcp.jvm import classfile, decompile
from remcp.jvm.bytecode import OPCODES, decode

FIXTURE = Path(__file__).parent / "fixtures" / "Algo.class"
needs_fixture = pytest.mark.skipif(not FIXTURE.exists(), reason="Algo.class missing")


@pytest.fixture(scope="module")
def cf():
    return classfile.parse(FIXTURE.read_bytes())


def src(cf, name: str) -> str:
    m = cf.method(name)
    assert m is not None, name
    return decompile.decompile_method(cf, m)["decompiled"]


# --------------------------------------------------------------------------
# Bytecode decoding
# --------------------------------------------------------------------------


def test_opcode_table_is_complete_and_unique():
    # The JVM defines opcodes 0x00-0xC9 contiguously, plus three reserved.
    for op in range(0x00, 0xCA):
        assert op in OPCODES, f"opcode 0x{op:02x} missing from the table"
    names = [n for n, _ in OPCODES.values()]
    assert len(names) == len(set(names)), "duplicate mnemonic in the opcode table"


def test_decode_computes_absolute_branch_targets():
    # iconst_0; ifeq +5 (-> pc 7); nop; return
    code = bytes([0x03, 0x99, 0x00, 0x05, 0x00, 0x00, 0x00, 0xB1])
    insns = decode(code)
    br = [i for i in insns if i.mnemonic == "ifeq"][0]
    assert br.pc == 1
    assert br.operands["target"] == 6, "branch offset must be relative to the branch pc"
    assert br.targets == [6]


def test_decode_stops_on_an_undecodable_opcode():
    """A Code array contains only instructions, so a bad opcode means the
    input is malformed; resyncing past it would fabricate a method body."""
    insns = decode(bytes([0x00, 0xCB, 0x00]))
    assert insns[-1].operands.get("undecodable") is True


def test_tableswitch_padding_is_honoured():
    """Padding aligns the default offset to a 4-byte boundary measured from
    the start of the code array, not from the opcode."""
    # nop@0, tableswitch@1 -> pad@2,3 -> default@4. Two pad bytes, not three.
    code = (bytes([0x00, 0xAA, 0x00, 0x00])
            + (20).to_bytes(4, "big") + (0).to_bytes(4, "big")
            + (1).to_bytes(4, "big") + (30).to_bytes(4, "big")
            + (40).to_bytes(4, "big"))
    ts = [i for i in decode(code) if i.mnemonic == "tableswitch"][0]
    assert ts.operands["low"] == 0 and ts.operands["high"] == 1
    assert ts.operands["default"] == 21          # pc 1 + 20
    assert ts.operands["targets"] == [31, 41]


def test_rejects_non_class_input():
    with pytest.raises(FormatError):
        classfile.parse(b"not a class file at all")


# --------------------------------------------------------------------------
# Class parsing
# --------------------------------------------------------------------------


@needs_fixture
def test_constant_pool_resolves_values_not_just_tags(cf):
    """The inventory parser skipped constant bodies; `ldc "x"` needs the text."""
    strings = [cf.pool.constant_at(i) for i in cf.pool.entries]
    assert "one" in strings and "seven" in strings


@needs_fixture
def test_code_attribute_bodies_are_parsed(cf):
    m = cf.method("sumEven")
    assert m.code is not None
    assert m.code.max_stack > 0 and m.code.max_locals >= 3
    assert len(m.code.code) > 0
    assert m.code.local_vars, "compiled with -g, LocalVariableTable expected"


@needs_fixture
def test_descriptors_decode_to_java_types(cf):
    params, ret = classfile.parse_method_descriptor("(Ljava/lang/String;I)V")
    assert params == ["java.lang.String", "int"] and ret == "void"
    assert classfile.parse_type("[[I")[0] == "int[][]"


def test_long_and_double_parameters_consume_two_slots():
    assert classfile.descriptor_slots(["long", "int"]) == 3
    assert classfile.descriptor_slots(["double", "double"]) == 4


# --------------------------------------------------------------------------
# Decompilation against known source
# --------------------------------------------------------------------------


@needs_fixture
def test_loop_and_array_indexing_recovered(cf):
    out = src(cf, "sumEven")
    assert "while (i < xs.length)" in out
    assert "if (xs[i] % 2 == 0)" in out
    assert "total += xs[i];" in out
    assert "return total;" in out


@needs_fixture
def test_parameter_names_come_from_the_debug_table(cf):
    """`sumEven(int[] xs)`, not `sumEven(int[] a0)`."""
    assert "sumEven(int[] xs)" in src(cf, "sumEven")
    assert "hashOf(String s)" in src(cf, "hashOf")


@needs_fixture
def test_locals_are_declared_with_their_types(cf):
    out = src(cf, "sumEven")
    assert "int total = 0;" in out
    assert "int i = 0;" in out


@needs_fixture
def test_precedence_is_preserved_across_compound_folding(cf):
    """`h = h * 31 + c` must NOT become `h *= 31 + c`.

    That fold changes the meaning to `h * (31 + c)`. It shipped briefly and
    is exactly the plausible-but-wrong output this engine exists to refuse.
    """
    out = src(cf, "hashOf")
    assert "h = h * 31 + s.charAt(i);" in out
    assert "h *=" not in out
    assert "h ^= 1542469173;" in out       # a single operand folds safely


@pytest.mark.parametrize("expr,expected", [
    ("31 + s.charAt(i)", True),
    ("a + b", True),
    ("xs[i]", False),
    ("1542469173", False),
    ("f(a, b)", False),
    ("-1", False),
    ("obj.method(x)", False),
])
def test_toplevel_operator_detection(expr, expected):
    assert decompile._has_toplevel_operator(expr) is expected


@needs_fixture
def test_switch_recovered_with_case_labels(cf):
    out = src(cf, "classify")
    for label in ("case 1:", "case 2:", "case 7:", "default:"):
        assert label in out
    assert '"seven"' in out


@needs_fixture
def test_try_catch_is_emitted_with_its_handler(cf):
    """The handler block was previously dropped entirely, leaving only the
    try body -- a silent loss of the whole catch clause."""
    out = src(cf, "safeDiv")
    assert "try {" in out
    assert "catch (ArithmeticException" in out
    assert "return -1;" in out


@needs_fixture
def test_field_increment_folds(cf):
    assert "this.counter++;" in src(cf, "bump")


@needs_fixture
def test_string_concat_indy_is_folded(cf):
    """Java 9+ compiles `+` on strings to invokedynamic; the raw call would
    make every formatted string unreadable."""
    out = src(cf, "describe")
    assert "name + n" in out
    assert "makeConcat" not in out


def test_string_builder_chain_folds():
    text = 'return new StringBuilder().append(a).append("x").append(b).toString();'
    assert decompile.fold_string_builders(text) == 'return a + "x" + b;'


# --------------------------------------------------------------------------
# Control flow
# --------------------------------------------------------------------------


@needs_fixture
def test_cfg_finds_the_loop(cf):
    m = cf.method("sumEven")
    g = jcfg.CFG(decode(m.code.code), m.code.exceptions)
    loops = g.natural_loops()
    assert len(loops) == 1
    assert loops[0]["size"] >= 2
    assert jcfg.cyclomatic_complexity(g) >= 3


@needs_fixture
def test_self_loop_body_does_not_escape_backwards(cf):
    """Seeding the worklist with the header walks its external predecessors,
    which reported a one-block self-loop as a four-block loop."""
    insns = decode(bytes([0xA7, 0x00, 0x00]))     # goto 0 -- a bare self-loop
    g = jcfg.CFG(insns)
    loops = g.natural_loops()
    assert loops and loops[0]["size"] == 1


@needs_fixture
def test_exception_table_is_exposed(cf):
    m = cf.method("safeDiv")
    assert m.code.exceptions
    e = m.code.exceptions[0]
    assert e.catch_type == "java.lang.ArithmeticException"
    assert e.start_pc < e.end_pc <= e.handler_pc


# --------------------------------------------------------------------------
# Honesty of the structured flag
# --------------------------------------------------------------------------


@needs_fixture
def test_every_fixture_method_is_fully_structured(cf):
    for m in cf.methods:
        if m.code is None:
            continue
        r = decompile.decompile_method(cf, m)
        assert r["structured"], f"{m.name} regressed to approximate output"


@needs_fixture
def test_abstract_and_native_methods_report_no_bytecode(cf):
    m = classfile.Member(kind="method", name="x", descriptor="()V", flags=0x0400,
                         access=["abstract"])
    r = decompile.decompile_method(cf, m)
    assert r["instruction_count"] == 0
    assert "abstract" in r["decompiled"]


def test_string_builder_fold_keeps_argument_parentheses():
    """`sb.append(size + 1)` must not fold to `"pop_" + size + 1`.

    That reads as `("pop_" + size) + 1` and produces "pop_31" instead of
    "pop_4". Caught against Starsector's own `increaseMarketSize`, whose
    bytecode computes `getSize() + 1` before appending.
    """
    text = 'addCondition(new StringBuilder("population_").append(size + 1).toString());'
    out = decompile.fold_string_builders(text)
    assert out == 'addCondition("population_" + (size + 1));'


def test_string_builder_fold_leaves_simple_arguments_bare():
    text = 'x(new StringBuilder("a").append(b).append(f(c)).toString());'
    assert decompile.fold_string_builders(text) == 'x("a" + b + f(c));'
