"""Regression tests, one per defect class found in the audited predecessor.

Each test names the specific failure it prevents, so a future change that
reintroduces it fails loudly instead of silently returning plausible garbage.
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from remcp import cache, codeindex, disasm, fingerprint, strings, xrefs
from remcp.errors import AddressError, TargetError, UnsupportedError
from remcp.evidence import image_warnings
from remcp.formats import load, sniff
from remcp.formats.raw import RawImage

PE64 = Path(r"C:\Windows\System32\notepad.exe")
PE32 = Path(r"C:\Windows\SysWOW64\notepad.exe")

pe64 = pytest.mark.skipif(not PE64.exists(), reason="no 64-bit PE available")
pe32 = pytest.mark.skipif(not PE32.exists(), reason="no 32-bit PE available")


# --------------------------------------------------------------------------
# Address spaces -- the bug class that killed the predecessor's string signal
# --------------------------------------------------------------------------


@pe64
@pe32
@pytest.mark.parametrize("path", [PE64, PE32])
def test_offset_va_roundtrip_is_exact(path):
    img = load(str(path))
    checked = 0
    for sec in img.sections:
        if sec.filesize == 0:
            continue
        for off in (sec.fileoff, sec.fileoff + sec.filesize // 2, sec.file_end - 1):
            va = img.off_to_va(off)
            assert va is not None
            assert img.va_to_off(va) == off
            checked += 1
    assert checked > 0


@pe64
def test_naive_base_plus_offset_is_wrong():
    """The predecessor computed string VAs as image_base + file_offset.

    This test asserts the shortcut is *not* equivalent, so nobody
    reintroduces it believing it is harmless.
    """
    img = load(str(PE64))
    disagreements = 0
    for sec in img.sections:
        if sec.filesize == 0:
            continue
        off = sec.fileoff
        if img.off_to_va(off) != img.image_base + off:
            disagreements += 1
    assert disagreements > 0, "expected the naive shortcut to disagree with the section table"


@pe64
def test_va_in_virtual_tail_has_no_file_bytes():
    """A VA past a section's raw size must not silently read the next section."""
    img = load(str(PE64))
    for sec in img.sections:
        if sec.vsize > sec.filesize and sec.filesize > 0:
            va = sec.va + sec.filesize + 1
            if sec.va <= va < sec.va_end:
                assert img.va_to_off(va) is None
                assert img.read_va(va, 4) is None
                return
    pytest.skip("no section with a virtual tail in this image")


def test_unmapped_address_raises_not_returns_garbage():
    img = RawImage(Path("blob"), b"\x90" * 64, arch="x86", bits=32, base_va=0x1000)
    assert img.section_for_va(0xDEAD0000) is None
    with pytest.raises(AddressError):
        img.require_va(0xDEAD0000)


# --------------------------------------------------------------------------
# Architecture derivation -- silent 64-bit-as-32-bit decoding
# --------------------------------------------------------------------------


@pe64
@pe32
def test_decoder_matches_declared_architecture():
    assert disasm.decoder_for(load(str(PE64)))[1] == "x86-64"
    assert disasm.decoder_for(load(str(PE32)))[1] == "x86-32"


def test_unsupported_architecture_refuses_rather_than_guessing():
    img = RawImage(Path("blob"), b"\x00" * 32, arch="unknown", bits=0)
    with pytest.raises(UnsupportedError) as exc:
        disasm.decoder_for(img)
    assert "refusing" in str(exc.value).lower()


# --------------------------------------------------------------------------
# Signature masking -- the no-op that made signatures layout-coupled
# --------------------------------------------------------------------------


def _mask_fixture():
    code = bytes.fromhex(
        "558bec"        # push ebp; mov ebp, esp
        "b834121f01"    # mov eax, 0x011F1234    in-image absolute
        "6834121f01"    # push 0x011F1234        in-image absolute
        "a134121f01"    # mov eax, [0x011F1234]  in-image displacement
        "b93412ff7f"    # mov ecx, 0x7FFF1234    NOT in image
        "83f810"        # cmp eax, 0x10          small constant
        "e800000000"    # call rel32
        "c3"
    )
    img = RawImage(Path("blob"), code + b"\x00" * 0x2000, arch="x86", bits=32, base_va=0x11F0000)
    md, _ = disasm.decoder_for(img)
    return img, list(disasm.sweep(md, code, 0x11F0000))


def test_in_image_addresses_are_masked():
    img, insns = _mask_fixture()
    sig = disasm.signature(insns, img)
    # 3 absolute references x 4 bytes + 1 rel32 x 4 bytes = 16 wildcards.
    assert sig.count("??") == 16, sig


def test_out_of_image_and_small_constants_survive_masking():
    """These are the durable signal. Masking them destroys the fingerprint."""
    img, insns = _mask_fixture()
    sig = disasm.signature(insns, img)
    assert "FF 7F" in sig, "out-of-image constant 0x7FFF1234 was wrongly masked"
    assert "83 F8 10" in sig, "small constant 0x10 was wrongly masked"


# --------------------------------------------------------------------------
# Code index -- edges the predecessor never recorded
# --------------------------------------------------------------------------


@pe64
def test_index_records_indirect_calls_and_jumps():
    """`call rax` and `jmp` thunks were both invisible in the predecessor."""
    img = load(str(PE64))
    idx = codeindex.build(img)
    assert idx["jump_edges"], "no jump edges recorded"
    assert idx["indirect_calls"], "no indirect call sites recorded"
    assert idx["import_calls"], "no import calls resolved"


@pe64
def test_index_resolves_rip_relative_imports():
    img = load(str(PE64))
    idx = codeindex.build(img)
    quals = {q for _s, _slot, q in idx["import_calls"]}
    assert any("!" in q for q in quals)


# --------------------------------------------------------------------------
# Cross-references -- data sections were never scanned
# --------------------------------------------------------------------------


@pe64
def test_xrefs_scan_data_sections_not_only_executable():
    """Vtables and pointer tables live in data. The predecessor scanned
    executable sections only, hiding every vtable reference."""
    img = load(str(PE64))
    idx = codeindex.build(img)
    entry = img.entry_va
    assert entry is not None
    found_data_ref = False
    # An address referenced from a non-executable section must be findable.
    for va_s in list(idx["refs_by_target"])[:400]:
        res = xrefs.xrefs_to(img, idx, int(va_s, 16), limit=50)
        if any(not r["executable_section"] for r in res["data_refs"]):
            found_data_ref = True
            break
    assert found_data_ref, "no data-section reference found in 400 targets"


@pe64
def test_string_xrefs_cover_utf16_not_only_ascii():
    """`find_string_va` was ASCII-only while the extractor reported UTF-16,
    so a UTF-16 string the tool had just shown you was untargetable."""
    img = load(str(PE64))
    rows = strings.extract(img, min_len=6, encodings=("utf16",))
    assert rows, "no UTF-16 strings in fixture"
    hits = strings.find_string_vas(img, rows[0]["text"])
    assert any(h["encoding"].startswith("utf-16") for h in hits)


# --------------------------------------------------------------------------
# Fingerprint features -- layout invariance
# --------------------------------------------------------------------------


@pe64
def test_fingerprint_features_are_content_not_addresses():
    img = load(str(PE64))
    idx = codeindex.build(img)
    db = fingerprint.build_database(img, idx, build_id="t", limit=250)
    assert db["function_count"] > 0
    for f in db["functions"]:
        for s in f["referenced_strings"]:
            assert not s.startswith("0x"), "strings must be content, not addresses"
        for imp in f["referenced_imports"]:
            assert "!" in imp, "imports must be qualified names, not slot addresses"


def test_jaccard_abstains_when_neither_side_has_evidence():
    """Returning 0.0 for two empty sets penalized small functions and capped
    every achievable score at 0.75 in the predecessor."""
    assert fingerprint._jaccard(set(), set()) is None
    assert fingerprint._jaccard({"a"}, set()) == 0.0
    assert fingerprint._jaccard({"a"}, {"a"}) == 1.0


def test_compare_renormalizes_over_signals_with_evidence():
    a = {"referenced_strings": ["cfg.ini"], "referenced_imports": ["k!F"], "ngram5": ["g1"],
         "constants": [], "masked_sig": "AA", "insn_count": 10, "direct_calls": 1,
         "branches": 1, "returns": 1}
    b = dict(a)
    r = fingerprint.compare(a, b)
    assert r["components"]["constants"] is None
    assert "constants" in r["abstained"]
    # With every present signal in full agreement the score must reach 1.0,
    # not be dragged down by an abstaining signal.
    assert r["score"] == pytest.approx(1.0)
    assert r["agreeing_signals"] >= 3


def test_signature_and_ngram_are_not_collinear():
    """sig_eq == 1 implied ngram == 1 in 559/559 predecessor matches because
    both were computed from the same 64-byte window."""
    assert fingerprint.SIG_BYTES != 0
    a = {"masked_sig": "AA BB", "ngram5": ["g1", "g2", "g3"], "referenced_strings": [],
         "referenced_imports": [], "constants": [], "insn_count": 5, "direct_calls": 0,
         "branches": 0, "returns": 1}
    b = dict(a, ngram5=["g1", "zz", "yy"])
    r = fingerprint.compare(a, b)
    assert r["components"]["masked_sig"] == 1.0
    assert r["components"]["ngram5"] < 1.0, "signals must be able to disagree"


# --------------------------------------------------------------------------
# Evidence in band -- the stderr warning nobody saw
# --------------------------------------------------------------------------


def test_packed_section_produces_an_unreliable_warning():
    import os

    high_entropy = os.urandom(4096)
    img = RawImage(Path("packed"), high_entropy, arch="x86", bits=32, base_va=0x400000)
    warns = image_warnings(img)
    codes = {w.code for w in warns}
    assert "packed_exec_section" in codes
    assert any(w.impact == "unreliable" for w in warns)


def test_low_entropy_code_produces_no_packing_warning():
    img = RawImage(Path("plain"), b"\x55\x8b\xec\xc3" * 512, arch="x86", bits=32, base_va=0x400000)
    assert "packed_exec_section" not in {w.code for w in image_warnings(img)}


# --------------------------------------------------------------------------
# Target handling -- the one-argument server kill
# --------------------------------------------------------------------------


def test_non_binary_input_raises_ordinary_exception(tmp_path):
    """The predecessor raised SystemExit here, which escaped FastMCP's
    `except Exception` and killed the stdio loop."""
    p = tmp_path / "notes.md"
    p.write_text("# not a binary\n", encoding="utf-8")
    with pytest.raises(UnsupportedError) as exc:
        load(str(p))
    assert isinstance(exc.value, Exception)
    assert not isinstance(exc.value, BaseException) or isinstance(exc.value, Exception)


def test_directory_and_missing_paths_are_rejected(tmp_path):
    with pytest.raises(TargetError):
        load(str(tmp_path))
    with pytest.raises(TargetError):
        load(str(tmp_path / "nope.bin"))


def test_empty_file_is_rejected(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    with pytest.raises(TargetError):
        load(str(p))


def test_fat_macho_is_refused_with_guidance(tmp_path):
    p = tmp_path / "fat"
    p.write_bytes(struct.pack(">II", 0xCAFEBABE, 2) + b"\x00" * 64)
    with pytest.raises(UnsupportedError) as exc:
        load(str(p))
    assert "lipo" in str(exc.value)


def test_raw_requires_explicit_architecture(tmp_path):
    p = tmp_path / "fw.bin"
    p.write_bytes(b"\x00" * 128)
    with pytest.raises(TargetError):
        load(str(p), raw_arch="x86")  # bits missing


def test_sniff_identifies_containers():
    assert sniff(b"MZ" + b"\x00" * 0x3E) == "dos_mz"
    assert sniff(b"\x7fELF\x02\x01\x01\x00") == "elf"
    assert sniff(struct.pack("<I", 0xFEEDFACF) + b"\x00" * 16) == "macho"
    assert sniff(b"PK\x03\x04....") == "zip"


# --------------------------------------------------------------------------
# Minimal synthetic ELF -- exercises the non-PE path end to end
# --------------------------------------------------------------------------


def _minimal_elf64() -> bytes:
    """An ELF64 with one PT_LOAD segment and no section headers."""
    code = b"\x55\x48\x89\xe5\xb8\x2a\x00\x00\x00\x5d\xc3"
    ehsize, phentsize = 64, 56
    load_off = 0x1000
    vaddr = 0x400000 + load_off
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    ehdr = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,          # e_type = ET_EXEC
        0x3E,       # e_machine = EM_X86_64
        1,          # e_version
        vaddr,      # e_entry
        ehsize,     # e_phoff
        0,          # e_shoff (no section headers)
        0,          # e_flags
        ehsize,
        phentsize,
        1,          # e_phnum
        0, 0, 0,    # shentsize, shnum, shstrndx
    )
    phdr = struct.pack(
        "<IIQQQQQQ",
        1,              # p_type = PT_LOAD
        5,              # p_flags = R+X
        load_off,       # p_offset
        vaddr,          # p_vaddr
        vaddr,          # p_paddr
        len(code),      # p_filesz
        len(code),      # p_memsz
        0x1000,         # p_align
    )
    blob = bytearray(ehdr + phdr)
    blob.extend(b"\x00" * (load_off - len(blob)))
    blob.extend(code)
    return bytes(blob)


def test_synthetic_elf64_parses_and_translates(tmp_path):
    p = tmp_path / "tiny.elf"
    p.write_bytes(_minimal_elf64())
    img = load(str(p))
    assert img.fmt == "elf"
    assert (img.arch, img.bits, img.endian) == ("x86", 64, "little")
    va = 0x401000
    assert img.off_to_va(0x1000) == va
    assert img.va_to_off(va) == 0x1000
    assert img.entry_va == va
    md, label = disasm.decoder_for(img)
    assert label == "x86-64"
    insns = list(disasm.sweep(md, img.read_va(va, 11), va))
    assert insns[0].mnemonic == "push"
    assert any(i.mnemonic == "ret" for i in insns)


def test_synthetic_elf_code_index_and_fingerprint(tmp_path):
    p = tmp_path / "tiny.elf"
    p.write_bytes(_minimal_elf64())
    img = load(str(p))
    idx = codeindex.build(img)
    assert idx["insn_count"] >= 4
    fp = fingerprint.fingerprint_function(img, idx, 0x401000)
    assert fp["returns"] >= 1
    assert fp["masked_sig"]


# --------------------------------------------------------------------------
# String detection quality
# --------------------------------------------------------------------------


def test_string_reader_requires_a_string_start(tmp_path):
    """A pointer into the middle of a name table decoded
    `GetFileInformationByHandle` as `tFileInformationByHandle`."""
    blob = b"\x00GetFileInformationByHandle\x00" + b"\x00" * 64
    img = RawImage(Path("b"), blob, arch="x86", bits=32, base_va=0x1000, executable=False)
    start = 0x1000 + 1
    assert fingerprint._string_at(img, start) == "GetFileInformationByHandle"
    assert fingerprint._string_at(img, start + 2) is None


def test_string_reader_rejects_control_characters(tmp_path):
    blob = b"\x00ETW0\x10\x00" + b"\x00" * 32
    img = RawImage(Path("b"), blob, arch="x86", bits=32, base_va=0x1000, executable=False)
    assert fingerprint._string_at(img, 0x1001) is None


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


def test_cache_hit_on_second_call(tmp_path, monkeypatch):
    monkeypatch.setenv("REMCP_CACHE_DIR", str(tmp_path / "c"))
    calls = {"n": 0}

    def build():
        calls["n"] += 1
        return {"value": 42}

    v1, hit1 = cache.get_or_build("a" * 64, "unit", {"p": 1}, build)
    v2, hit2 = cache.get_or_build("a" * 64, "unit", {"p": 1}, build)
    assert v1 == v2 == {"value": 42}
    assert hit1 is False and hit2 is True
    assert calls["n"] == 1


def test_cache_key_includes_params(tmp_path, monkeypatch):
    monkeypatch.setenv("REMCP_CACHE_DIR", str(tmp_path / "c"))
    cache.get_or_build("b" * 64, "unit", {"p": 1}, lambda: 1)
    _v, hit = cache.get_or_build("b" * 64, "unit", {"p": 2}, lambda: 2)
    assert hit is False


def test_corrupt_cache_entry_degrades_to_recompute(tmp_path, monkeypatch):
    monkeypatch.setenv("REMCP_CACHE_DIR", str(tmp_path / "c"))
    cache.get_or_build("c" * 64, "unit", {}, lambda: {"v": 1})
    for f in (tmp_path / "c").glob("*.json.gz"):
        f.write_bytes(b"not gzip")
    v, hit = cache.get_or_build("c" * 64, "unit", {}, lambda: {"v": 2})
    assert v == {"v": 2} and hit is False


# --------------------------------------------------------------------------
# Packed sections -- elimination rather than 394 seconds of noise
# --------------------------------------------------------------------------


def test_packed_exec_sections_are_skipped_by_default():
    """Sweeping an encrypted .text produced 5,080,489 fabricated instructions
    in 394 seconds on a real image. The default must be to refuse."""
    import os

    img = RawImage(Path("packed"), os.urandom(65536), arch="x86", bits=32, base_va=0x400000)
    assert img.packed_exec_sections(), "fixture is not high-entropy"
    assert img.analyzable_exec_sections() == []
    idx = codeindex.build(img)
    assert idx["insn_count"] == 0
    assert idx["skipped_packed_sections"] == ["blob"]
    assert idx["include_packed"] is False


def test_include_packed_is_an_available_override():
    import os

    img = RawImage(Path("packed"), os.urandom(4096), arch="x86", bits=32, base_va=0x400000)
    idx = codeindex.build(img, include_packed=True)
    assert idx["insn_count"] > 0
    assert idx["skipped_packed_sections"] == []
    assert idx["include_packed"] is True


def test_unpacked_code_is_not_skipped():
    img = RawImage(Path("plain"), b"\x55\x8b\xec\x5d\xc3" * 800, arch="x86", bits=32, base_va=0x400000)
    assert img.packed_exec_sections() == []
    idx = codeindex.build(img)
    assert idx["insn_count"] > 0
    assert idx["skipped_packed_sections"] == []


def test_packed_and_unpacked_indexes_have_separate_cache_keys(tmp_path, monkeypatch):
    """Otherwise an override would be served a cached refusal, or worse."""
    import os

    monkeypatch.setenv("REMCP_CACHE_DIR", str(tmp_path / "c"))
    img = RawImage(Path("packed"), os.urandom(2048), arch="x86", bits=32, base_va=0x400000)
    a, _ = codeindex.load(img, include_packed=False)
    b, _ = codeindex.load(img, include_packed=True)
    assert a["insn_count"] == 0
    assert b["insn_count"] > 0


def test_section_lookup_does_not_reallocate_per_call():
    """The bisect key lists are precomputed; rebuilding them per lookup made
    the index build 4x slower on a 23 MB image."""
    img = RawImage(Path("b"), b"\x90" * 4096, arch="x86", bits=32, base_va=0x1000)
    assert img._va_keys == [0x1000]
    assert img._off_keys == [0]
    before = img._va_keys
    img.contains_va(0x1500)
    img.contains_va(0x9999)
    assert img._va_keys is before, "lookup must not rebuild the key list"
