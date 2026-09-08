"""Knowledge-base policy tests.

The predecessor documented a six-tier, per-class confidence policy and
implemented one rule. These tests pin each documented rule to an executable
check, and -- for the classes a static engine can actually confirm -- verify
that a false claim is rejected rather than recorded.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from remcp import codeindex, fingerprint, kb
from remcp.errors import PolicyError
from remcp.formats import load

PE64 = Path(r"C:\Windows\System32\notepad.exe")
pe64 = pytest.mark.skipif(not PE64.exists(), reason="no 64-bit PE available")


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("REMCP_KB", str(tmp_path / "kb" / "symbols.json"))
    monkeypatch.setenv("REMCP_CACHE_DIR", str(tmp_path / "cache"))
    return kb.load_kb()


@pytest.fixture()
def img_idx():
    img = load(str(PE64))
    return img, codeindex.build(img)


def _save(store, img, idx, **kw):
    defaults = dict(
        name="Test_Function",
        build_id="b1",
        rva=0x1000,
        provenance=["structural_guess"],
        confidence=0.2,
        evidence=[],
    )
    defaults.update(kw)
    return kb.save_symbol(store, img, idx, **defaults)


# --------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------


@pe64
def test_unknown_provenance_class_is_rejected(store, img_idx):
    """`structural-analysis` -- a typo of a policy term -- was the most common
    class in the predecessor's database because nothing validated it."""
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    with pytest.raises(PolicyError) as exc:
        _save(store, img, idx, provenance=["structural-analysis"])
    assert "unknown provenance class" in str(exc.value)
    assert "structural_guess" in json.dumps(exc.value.context)


@pe64
def test_empty_provenance_is_rejected(store, img_idx):
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    with pytest.raises(PolicyError):
        _save(store, img, idx, provenance=[])


# --------------------------------------------------------------------------
# Per-class caps -- unenforced in the predecessor
# --------------------------------------------------------------------------


@pe64
def test_class_cap_is_enforced(store, img_idx):
    """Five stored entries sat at 0.60 under a class the written policy
    caps at 0.40, because no cap was ever checked."""
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    with pytest.raises(PolicyError) as exc:
        _save(store, img, idx, provenance=["structural_guess"], confidence=0.6)
    assert "exceeds the cap" in str(exc.value)
    assert exc.value.context["cap"] == 0.20


@pe64
def test_cap_is_the_highest_among_supplied_classes(store, img_idx):
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    # structural_guess caps at 0.20, community_source at 0.60 -> cap is 0.60.
    entry = _save(
        store, img, idx,
        provenance=["structural_guess", "community_source"],
        confidence=0.6,
        evidence=[{"kind": "community_source", "note": "public header"}],
    )
    assert entry["verification"]["cap_applied"] == 0.60


@pe64
def test_confidence_out_of_range_is_rejected(store, img_idx):
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    for bad in (-0.1, 1.5):
        with pytest.raises(PolicyError):
            _save(store, img, idx, provenance=["authoritative_source"], confidence=bad)


# --------------------------------------------------------------------------
# Corroboration -- documented for tier 0.60, never implemented
# --------------------------------------------------------------------------


@pe64
def test_single_class_cannot_exceed_the_corroboration_threshold(store, img_idx):
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    with pytest.raises(PolicyError) as exc:
        _save(
            store, img, idx,
            provenance=["community_source"],
            confidence=0.6,
            evidence=[{"kind": "community_source"}],
        )
    assert "corroboration threshold" in str(exc.value)


@pe64
def test_two_classes_satisfy_corroboration(store, img_idx):
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    entry = _save(
        store, img, idx,
        provenance=["community_source", "structural_guess"],
        confidence=0.6,
        evidence=[{"kind": "community_source", "note": "SDK header"}],
    )
    assert entry["confidence"] == 0.6


# --------------------------------------------------------------------------
# Verifiable classes are actually verified against the binary
# --------------------------------------------------------------------------


def _find_string_referencing_function(img, idx):
    """Locate a real (function_va, string) pair in the image."""
    db = fingerprint.build_database(img, idx, build_id="probe", limit=800)
    for f in db["functions"]:
        if f["referenced_strings"]:
            return int(f["va"], 16), f["referenced_strings"][0]
    pytest.skip("no function with a recoverable string reference in fixture")


@pe64
def test_true_string_xref_claim_is_verified_and_recorded(store, img_idx):
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    fn_va, text = _find_string_referencing_function(img, idx)

    entry = kb.save_symbol(
        store, img, idx,
        name="StringUser",
        build_id="b1",
        rva=img.va_to_rva(fn_va),
        provenance=["string_xref"],
        confidence=0.4,
        evidence=[{"kind": "string_xref", "string": text}],
    )
    verified = entry["verification"]["verified"]
    assert [v["class"] for v in verified] == ["string_xref"]
    assert text[:12] in verified[0]["detail"]
    assert entry["verification"]["asserted"] == []


@pe64
def test_false_string_xref_claim_is_rejected(store, img_idx):
    """This is the difference between a policy and policy theater: a claim
    the engine can check, and does."""
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    fn_va, _text = _find_string_referencing_function(img, idx)

    with pytest.raises(PolicyError) as exc:
        kb.save_symbol(
            store, img, idx,
            name="Liar",
            build_id="b1",
            rva=img.va_to_rva(fn_va),
            provenance=["string_xref"],
            confidence=0.4,
            evidence=[{"kind": "string_xref", "string": "definitely-not-in-this-binary-zzz"}],
        )
    assert "failed verification" in str(exc.value)
    assert exc.value.context["provenance_class"] == "string_xref"


@pe64
def test_string_present_but_not_referenced_here_is_rejected(store, img_idx):
    """A string that exists in the image but is referenced from a different
    function must not validate a claim about this one."""
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    fn_va, text = _find_string_referencing_function(img, idx)

    # Pick a different function that does not reference `text`.
    other = None
    for va_s in idx["func_starts"]:
        va = int(va_s, 16)
        if va == fn_va:
            continue
        fp = fingerprint.fingerprint_function(img, idx, va)
        if text not in fp["referenced_strings"]:
            other = va
            break
    if other is None:
        pytest.skip("no unrelated function available")

    with pytest.raises(PolicyError) as exc:
        kb.save_symbol(
            store, img, idx,
            name="WrongFunction",
            build_id="b1",
            rva=img.va_to_rva(other),
            provenance=["string_xref"],
            confidence=0.4,
            evidence=[{"kind": "string_xref", "string": text}],
        )
    assert "no reference to it lies within" in str(exc.value)


@pe64
def test_export_table_claim_is_verified(store, img_idx):
    img, idx = img_idx
    if not img.exports:
        pytest.skip("fixture has no exports")
    kb.register_build(store, img, "b1")
    exp = img.exports[0]
    entry = kb.save_symbol(
        store, img, idx,
        name=exp.name,
        build_id="b1",
        rva=img.va_to_rva(exp.va),
        provenance=["export_table"],
        confidence=0.4,
        evidence=[{"kind": "export_table"}],
    )
    assert entry["verification"]["verified"][0]["class"] == "export_table"


@pe64
def test_false_export_table_claim_is_rejected(store, img_idx):
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    with pytest.raises(PolicyError):
        _save(store, img, idx, provenance=["export_table"], confidence=0.4,
              evidence=[{"kind": "export_table"}], rva=0x1234)


@pe64
def test_verifiable_class_without_its_evidence_field_is_rejected(store, img_idx):
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    with pytest.raises(PolicyError) as exc:
        _save(store, img, idx, provenance=["string_xref"], confidence=0.4, evidence=[])
    assert "requires evidence" in str(exc.value)


@pe64
def test_cross_build_match_requires_a_real_match_result(store, img_idx):
    """'equivalences may only cite a match result, not an assertion that two
    functions look the same' -- documented by the predecessor, never coded."""
    img, idx = img_idx
    kb.register_build(store, img, "b1")

    with pytest.raises(PolicyError) as exc:
        _save(store, img, idx, provenance=["cross_build_match"], confidence=0.4,
              evidence=[{"kind": "cross_build_match"}])
    assert "requires evidence" in str(exc.value)

    with pytest.raises(PolicyError) as exc:
        _save(store, img, idx, provenance=["cross_build_match"], confidence=0.4,
              evidence=[{"kind": "cross_build_match", "matched_build": "x",
                         "score": 0.9, "agreeing_signals": 1}])
    assert "agreeing signal" in str(exc.value)


# --------------------------------------------------------------------------
# Asserted classes: artifact required, and marked as unverified
# --------------------------------------------------------------------------


@pe64
def test_runtime_class_requires_a_named_artifact(store, img_idx):
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    with pytest.raises(PolicyError) as exc:
        _save(store, img, idx, provenance=["dynamic_trace", "structural_guess"],
              confidence=0.8, evidence=[{"kind": "dynamic_trace"}])
    assert "artifact" in str(exc.value)


@pe64
def test_asserted_class_is_recorded_as_unverified(store, img_idx):
    """The honest boundary: the engine cannot confirm a debugger trace, so
    the record says so instead of implying it was checked."""
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    entry = _save(
        store, img, idx,
        provenance=["dynamic_trace", "structural_guess"],
        confidence=0.8,
        evidence=[{"kind": "dynamic_trace", "artifact": "traces/bp-0x401000.log"}],
    )
    asserted = {a["class"]: a for a in entry["verification"]["asserted"]}
    assert asserted["dynamic_trace"]["verified"] is False
    assert asserted["dynamic_trace"]["artifact"] == "traces/bp-0x401000.log"
    # The stored record must state plainly that these were not checked, so a
    # later reader can tell a verified class from a trusted one.
    note = entry["verification"]["note"]
    assert "not" in note and "claims" in note
    assert "All supplied provenance classes were machine-verified" not in note


# --------------------------------------------------------------------------
# Build identity and storage integrity
# --------------------------------------------------------------------------


@pe64
def test_unregistered_build_is_rejected(store, img_idx):
    img, idx = img_idx
    with pytest.raises(PolicyError) as exc:
        _save(store, img, idx)
    assert "unknown build_id" in str(exc.value)


@pe64
def test_build_id_cannot_be_reused_for_a_different_binary(store, img_idx, tmp_path):
    img, _idx = img_idx
    kb.register_build(store, img, "b1")

    other = tmp_path / "other.bin"
    other.write_bytes(Path(r"C:\Windows\SysWOW64\notepad.exe").read_bytes())
    img2 = load(str(other))
    with pytest.raises(PolicyError) as exc:
        kb.register_build(store, img2, "b1")
    assert "already registered to a different binary" in str(exc.value)


@pe64
def test_va_is_derived_from_rva_never_supplied(store, img_idx):
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    entry = _save(store, img, idx, rva=0x1000)
    assert entry["rva"] == "0x1000"
    assert entry["va"] == f"0x{img.image_base + 0x1000:x}"


@pe64
def test_revision_preserves_prior_evidence_as_history(store, img_idx):
    """The predecessor removed the old record and appended a new one,
    discarding the earlier evidence list entirely."""
    img, idx = img_idx
    kb.register_build(store, img, "b1")

    _save(store, img, idx, provenance=["structural_guess"], confidence=0.2,
          evidence=[{"kind": "structural_guess", "note": "first guess"}])
    entry = _save(store, img, idx, provenance=["structural_guess"], confidence=0.1,
                  evidence=[{"kind": "structural_guess", "note": "revised down"}])

    assert len(entry["history"]) == 1
    assert entry["history"][0]["confidence"] == 0.2
    assert entry["history"][0]["evidence"][0]["note"] == "first guess"
    assert entry["previous_confidence"] == 0.2
    assert "downgraded" in entry["note"]
    assert len(store["symbols"]) == 1


@pe64
def test_save_is_atomic_and_keeps_a_backup(store, img_idx):
    img, idx = img_idx
    kb.register_build(store, img, "b1")
    _save(store, img, idx)
    p1 = kb.save_kb(store)
    assert p1.exists()
    _save(store, img, idx, name="Second")
    p2 = kb.save_kb(store)
    assert p2.with_suffix(p2.suffix + ".bak").exists()
    reloaded = kb.load_kb()
    assert {s["name"] for s in reloaded["symbols"]} == {"Test_Function", "Second"}


def test_policy_document_is_self_describing():
    doc = kb.policy_document()
    assert doc["min_classes_above_threshold"] == 2
    for name, spec in doc["classes"].items():
        assert 0.0 < spec["cap"] <= 1.0
        assert isinstance(spec["verifiable"], bool)
        # Every verifiable class must have a verifier wired up.
        if spec["verifiable"]:
            assert name in kb.VERIFIERS
    # And every wired verifier must be a declared class.
    assert set(kb.VERIFIERS) <= set(doc["classes"])
