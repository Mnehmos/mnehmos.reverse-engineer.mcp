"""Algorithm identification and native control-flow tests.

The catalog's value depends entirely on not crying wolf, so most of these
tests are about the guards: small constants must not be scanned, shared
markers must not carry an identification, and a single weak hit must stay a
lead.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from remcp import codeindex
from remcp.algo import constants as algo
from remcp.algo import nativecfg
from remcp.formats import load
from remcp.formats.raw import RawImage

CRYPTO = Path(r"C:\Windows\System32\bcryptprimitives.dll")
NTDLL = Path(r"C:\Windows\System32\ntdll.dll")
needs_crypto = pytest.mark.skipif(not CRYPTO.exists(), reason="no crypto DLL available")
needs_ntdll = pytest.mark.skipif(not NTDLL.exists(), reason="no ntdll available")


# --------------------------------------------------------------------------
# Catalog hygiene
# --------------------------------------------------------------------------


def test_no_scannable_marker_is_small_enough_to_be_noise():
    """`0x1B` (AES Rcon) occurs thousands of times in any binary. Scanning
    for values that small produces noise, not evidence."""
    scanned = [
        (a.name, label, value)
        for a in algo.CATALOG
        for label, value, _w in a.constants
        if abs(value) >= algo.MIN_SCANNABLE
    ]
    assert scanned, "catalog has no scannable markers at all"
    for name, label, value in scanned:
        assert abs(value) >= 0x10000, f"{name}/{label} is too small to scan for"


def test_every_algorithm_declares_a_corroboration_threshold():
    for a in algo.CATALOG:
        assert a.min_distinct >= 1
        assert a.min_distinct <= max(a.total, 1)


def test_discriminators_are_declared_markers():
    for a in algo.CATALOG:
        labels = {label for label, _v, _w in a.constants} | set(a.strings)
        for d in a.discriminators:
            assert d in labels, f"{a.name}: discriminator {d!r} is not one of its markers"


def test_md5_and_sha1_share_init_words_and_both_declare_discriminators():
    md5 = next(a for a in algo.CATALOG if a.name == "MD5")
    sha1 = next(a for a in algo.CATALOG if a.name == "SHA-1")
    md5_vals = {v for _l, v, _w in md5.constants}
    sha1_vals = {v for _l, v, _w in sha1.constants}
    assert md5_vals & sha1_vals, "fixture assumption: these families share init words"
    assert md5.discriminators and sha1.discriminators


# --------------------------------------------------------------------------
# Scanning behaviour
# --------------------------------------------------------------------------


def test_planted_sha256_constants_are_identified():
    """A synthetic image containing SHA-256's initial state must be identified,
    and nothing else should be."""
    import struct

    iv = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
          0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    blob = b"".join(struct.pack("<I", v) for v in iv) + b"\x00" * 4096
    img = RawImage(Path("synthetic"), blob, arch="x86", bits=32,
                   base_va=0x400000, executable=False)
    res = algo.scan_image(img)
    ids = {r["algorithm"] for r in res if r["confident"]}
    assert "SHA-224/256" in ids
    assert "MD5" not in ids and "SHA-1" not in ids


def test_shared_markers_alone_do_not_identify():
    """Only MD5/SHA-1's four *shared* init words are present. Neither may be
    reported as identified, because no discriminating marker matched."""
    import struct

    shared = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    blob = b"".join(struct.pack("<I", v) for v in shared) + b"\x00" * 2048
    img = RawImage(Path("shared"), blob, arch="x86", bits=32,
                   base_va=0x400000, executable=False)
    res = {r["algorithm"]: r for r in algo.scan_image(img)}
    for name in ("MD5", "SHA-1"):
        assert name in res, f"{name} should still appear as a lead"
        assert res[name]["confident"] is False
        assert "unique" in (res[name]["why_not_confident"] or "")


def test_empty_image_yields_no_algorithms():
    img = RawImage(Path("empty"), b"\x00" * 8192, arch="x86", bits=32,
                   base_va=0x1000, executable=False)
    assert algo.scan_image(img) == []


@needs_crypto
def test_real_crypto_library_is_identified():
    img = load(str(CRYPTO))
    idx = codeindex.build(img)
    res = algo.scan_image(img, index=idx)
    ids = {r["algorithm"] for r in res if r["confident"]}
    assert "SHA-224/256" in ids
    assert "SHA-1" in ids
    # An algorithm that *declares* discriminators must have matched one to be
    # confident. SHA-384/512 declares none because all its markers are 64-bit
    # values unique to it, so it is correctly exempt.
    declared = {a.name: a.discriminators for a in algo.CATALOG if a.discriminators}
    for r in res:
        if r["confident"] and r["algorithm"] in declared:
            assert r["discriminating_markers"],                 f"{r['algorithm']} identified on shared markers alone"


@needs_crypto
def test_identified_algorithms_are_attributed_to_functions():
    img = load(str(CRYPTO))
    idx = codeindex.build(img)
    res = algo.attribute_to_functions(img, idx, algo.scan_image(img, index=idx))
    hashes = [r for r in res if r["confident"] and r["family"] == "hash"]
    assert hashes
    assert any(r.get("used_by_functions") for r in hashes), \
        "no constant was traced back to a referencing function"


@needs_ntdll
def test_a_lone_weak_marker_stays_a_lead():
    """secp256k1's field-prime low word alone appeared in ntdll and was being
    reported as an identification of Bitcoin code."""
    img = load(str(NTDLL))
    idx = codeindex.build(img)
    res = {r["algorithm"]: r for r in algo.scan_image(img, index=idx)}
    sec = res.get("secp256k1 / Bitcoin")
    if sec is not None:
        assert sec["confident"] is False, "a single 32-bit word is not an identification"


# --------------------------------------------------------------------------
# Immediates in the code index
# --------------------------------------------------------------------------


def test_index_records_non_address_immediates_only():
    code = bytes.fromhex(
        "b867e6096a"   # mov eax, 0x6A09E667   <- SHA-256 H0, not an address
        "b800100000"   # mov eax, 0x1000       <- small, must be ignored
        "c3"
    )
    img = RawImage(Path("blob"), code + b"\x00" * 4096, arch="x86", bits=32,
                   base_va=0x400000)
    idx = codeindex.build(img)
    imms = {int(k, 16) for k in idx["immediates"]}
    assert 0x6A09E667 in imms
    assert 0x1000 not in imms, "values under the noise floor must not be indexed"


def test_inline_constant_is_attributed_without_a_data_table():
    """An optimiser can materialise round constants inline, leaving no table
    to scan. The code index is the second evidence source for exactly that."""
    code = bytes.fromhex("b867e6096a" "b885ae67bb" "b872f36e3c" "c3")
    img = RawImage(Path("inline"), code + b"\x00" * 2048, arch="x86", bits=32,
                   base_va=0x400000)
    idx = codeindex.build(img)
    res = {r["algorithm"]: r for r in algo.scan_image(img, index=idx)}
    assert "SHA-224/256" in res
    assert res["SHA-224/256"]["distinct_markers"] >= 3


# --------------------------------------------------------------------------
# Native control flow
# --------------------------------------------------------------------------


def test_native_cfg_recovers_blocks_and_a_loop():
    # loop: dec eax; jnz loop; ret
    code = bytes.fromhex("48" "75fd" "c3")
    img = RawImage(Path("loop"), code + b"\x00" * 512, arch="x86", bits=32,
                   base_va=0x401000)
    idx = codeindex.build(img)
    r = nativecfg.build_function_cfg(img, idx, 0x401000)
    assert r["resolved"]
    assert r["block_count"] >= 1
    assert r["loop_count"] >= 1
    assert r["loops"][0]["blocks"] == 1, "a self-loop body is one block"


def test_native_cfg_reports_single_exit_and_complexity():
    # cmp eax,1; je +2; xor eax,eax; ret
    code = bytes.fromhex("83f801" "7402" "31c0" "c3")
    img = RawImage(Path("branch"), code + b"\x00" * 512, arch="x86", bits=32,
                   base_va=0x401000)
    idx = codeindex.build(img)
    r = nativecfg.build_function_cfg(img, idx, 0x401000)
    assert r["resolved"]
    assert r["cyclomatic_complexity"] >= 1
    assert isinstance(r["single_exit"], bool)


def test_native_cfg_on_unmapped_address_raises():
    from remcp.errors import AddressError

    img = RawImage(Path("x"), b"\xc3" * 64, arch="x86", bits=32, base_va=0x1000)
    idx = codeindex.build(img)
    with pytest.raises(AddressError):
        nativecfg.build_function_cfg(img, idx, 0xDEAD0000)
