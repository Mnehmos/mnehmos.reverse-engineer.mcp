"""Function fingerprints and cross-build matching.

First principle: a cross-build signal must not depend on the layout, because
differing layout is the entire problem it exists to solve.

The predecessor's matcher combined four signals with weights (masked
signature 0.35, mnemonic 3-grams 0.30, references 0.25, call degree 0.10)
and described them as independent triangulation. Measured over its own
shipped databases (2,973 x 1,142 functions), the result was:

    min=0.55:  559 matches | without byte-identical sig:    0 | refs>0:   0
    min=0.40: 2325 matches | without byte-identical sig: 1764 | refs>0:   0
    min=0.30: 3363 matches | without byte-identical sig: 2802 | refs>0:   0
    distinct scores: [0.70, 0.75]        (theoretical max 1.00)

Three independent defects produced that:

1. The "masked" signature masked nothing but relative branch displacements,
   so any function referencing a global stayed layout-coupled.
2. The 3-gram set was computed from the same 64-byte window as the
   signature, making the two signals perfectly collinear -- `sig_eq == 1`
   implied `ngram == 1` in 559 of 559 matches, and no match was ever found
   without a byte-identical signature.
3. The reference signal compared *RVAs* across builds. The same global sits
   at a different RVA in each build, so the intersection was empty by
   construction -- 82% of functions carried reference data and the signal
   contributed to zero matches at any threshold.

The features below are content-addressed instead. A function that calls
`kernel32!CreateFileW` and loads the string "config.ini" has those facts in
common across every build, at every base address, under any compiler that
keeps the call.
"""
from __future__ import annotations

import hashlib
from typing import Any, Iterable

from . import disasm
from .graph import FunctionMap

MAX_FN_BYTES = 8192
SIG_BYTES = 128


def _sha(s: str, n: int = 16) -> str:
    return hashlib.sha256(s.encode()).hexdigest()[:n]


def _printable(b: int) -> bool:
    # Tab plus the printable ASCII range. Control characters are not text;
    # allowing them let `ETW0\x10` through as a "string" during testing.
    return b == 0x09 or 0x20 <= b < 0x7F


def _at_string_start(image, va: int) -> bool:
    """True if `va` plausibly begins a string rather than sitting inside one.

    A reference to a string literal points at its first byte, so the
    preceding byte should be a terminator or padding. Without this check a
    pointer into an import-name table produced truncated fragments -- a real
    observed case decoded `GetFileInformationByHandle` as
    `tFileInformationByHandle`, which would then be compared as if it were a
    distinct string constant.
    """
    sec = image.section_for_va(va)
    if sec is None:
        return False
    if va == sec.va:
        return True
    prev = image.read_va(va - 1, 1)
    if not prev:
        return True
    return prev[0] in (0x00, 0x0A, 0x0D)


def _string_at(image, va: int, *, max_len: int = 96, min_len: int = 4) -> str | None:
    """Read a printable, NUL-terminated string starting exactly at `va`."""
    if not _at_string_start(image, va):
        return None
    blob = image.read_va(va, max_len)
    if not blob:
        return None

    end = blob.find(b"\x00")
    cand = blob[: end if end != -1 else len(blob)]
    if len(cand) >= min_len and all(_printable(b) for b in cand):
        return cand.decode("ascii", "replace")

    # UTF-16LE: printable ASCII interleaved with NUL high bytes.
    if len(blob) >= min_len * 2 and blob[1] == 0 and blob[3] == 0:
        chunk = blob[: (len(blob) // 2) * 2]
        try:
            text = chunk.decode("utf-16-le")
        except UnicodeDecodeError:
            return None
        text = text.split("\x00", 1)[0]
        if len(text) >= min_len and all(_printable(ord(c)) for c in text):
            return text
    return None


def fingerprint_function(
    image,
    index: dict,
    va: int,
    *,
    size: int | None = None,
    sig_bytes: int = SIG_BYTES,
) -> dict[str, Any]:
    """Layout-invariant feature vector for one function."""
    image.require_va(va)
    md, decoder = disasm.decoder_for(image)

    starts = [int(s, 16) for s in index.get("func_starts", [])]
    fmap = FunctionMap(starts)
    if size is None:
        start, end = fmap.extent(va, hard_cap=MAX_FN_BYTES)
        if start != va:  # asked about a mid-function address
            start, end = va, min(va + MAX_FN_BYTES, end if end > va else va + MAX_FN_BYTES)
    else:
        start, end = va, va + min(size, MAX_FN_BYTES)

    blob = image.read_va(start, end - start) or b""
    insns = list(disasm.sweep(md, blob, start))

    # Trim at the first terminator followed by padding or a new prologue --
    # a better boundary estimate than "distance to the next known start".
    insns, real_end = _trim_at_terminator(insns, start)

    mnemonics = [i.mnemonic for i in insns]
    imports_slot = image.import_by_slot()

    strings_ref: set[str] = set()
    imports_ref: set[str] = set()
    consts: set[int] = set()
    direct_calls = 0
    indirect_calls = 0

    for insn in insns:
        if disasm.is_call(insn):
            tgt = disasm.branch_target(insn)
            if tgt is not None and image.contains_va(tgt):
                direct_calls += 1
            else:
                indirect_calls += 1

        for tgt, _kind in _refs(insn, image):
            if tgt in imports_slot:
                imports_ref.add(imports_slot[tgt].qualified)
                continue
            sec = image.section_for_va(tgt)
            if sec is not None and not sec.x:
                text = _string_at(image, tgt)
                if text:
                    strings_ref.add(text)

        for c in _plain_constants(insn, image):
            consts.add(c)

    grams = {" ".join(mnemonics[i : i + 3]) for i in range(max(len(mnemonics) - 2, 0))}

    return {
        "va": f"0x{va:x}",
        "rva": f"0x{image.va_to_rva(va):x}",
        "size": real_end - start,
        "decoder": decoder,
        "insn_count": len(insns),
        # --- layout-coupled, useful only within one build -----------------
        "head_bytes": blob[:16].hex(" "),
        # --- layout-invariant ---------------------------------------------
        "masked_sig": disasm.signature(insns, image, max_bytes=sig_bytes),
        "mnemonic_hash": _sha(" ".join(mnemonics)),
        # 5-grams over the *whole* function, deliberately a different window
        # and a different order than masked_sig, so the two signals can
        # disagree instead of being collinear.
        "ngram5": sorted(_sha(g, 8) for g in _ngrams(mnemonics, 5)),
        "referenced_strings": sorted(strings_ref),
        "referenced_imports": sorted(imports_ref),
        "constants": sorted(consts),
        "direct_calls": direct_calls,
        "indirect_calls": indirect_calls,
        "returns": sum(1 for i in insns if disasm.is_ret(i)),
        "branches": sum(1 for i in insns if disasm.is_jump(i)),
    }


def _ngrams(seq: list[str], n: int) -> set[str]:
    return {" ".join(seq[i : i + n]) for i in range(max(len(seq) - n + 1, 0))}


def _trim_at_terminator(insns: list, start: int) -> tuple[list, int]:
    """Cut the instruction list at a plausible function end."""
    for i, insn in enumerate(insns):
        if not disasm.is_ret(insn):
            continue
        nxt = insns[i + 1] if i + 1 < len(insns) else None
        if nxt is None:
            return insns[: i + 1], insn.address + insn.size
        raw = bytes(nxt.bytes)
        # Padding or an obvious new frame setup means the function ended.
        if raw[:1] in (b"\xcc", b"\x90") or nxt.mnemonic in ("int3", "nop"):
            return insns[: i + 1], insn.address + insn.size
    return insns, (insns[-1].address + insns[-1].size) if insns else start


def _refs(insn, image):
    from .codeindex import _operand_refs

    yield from _operand_refs(insn, image)


def _plain_constants(insn, image) -> Iterable[int]:
    """Immediates that are NOT in-image addresses.

    These are the magic numbers, table sizes, flag masks and hash seeds that
    survive relinking unchanged -- the most durable cross-build signal there
    is, and one the predecessor discarded by keeping only values > 0x10000
    and then comparing them as RVAs.
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
        if image.contains_va(v) or image.contains_va(v & 0xFFFFFFFF):
            continue
        # Very small values are too common to carry information.
        if -16 <= v <= 16:
            continue
        yield v


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

# Weights are renormalized over whichever signals have evidence on both
# sides, so a signal with no data on either side abstains instead of voting
# zero. The predecessor's jaccard returned 0.0 for two empty sets, which
# actively penalized small functions and capped every achievable score.
WEIGHTS = {
    "strings": 0.30,
    "imports": 0.25,
    "constants": 0.15,
    "ngram5": 0.20,
    "masked_sig": 0.05,
    "shape": 0.05,
}


def _jaccard(a: set, b: set) -> float | None:
    """None means "neither side has evidence" -- abstain, do not score 0."""
    if not a and not b:
        return None
    return len(a & b) / len(a | b)


def _shape_sim(fa: dict, fb: dict) -> float:
    """Structural similarity: instruction count, call degree, branches."""
    def close(x: int, y: int) -> float:
        m = max(x, y, 1)
        return max(0.0, 1.0 - abs(x - y) / m)

    return (
        0.4 * close(fa.get("insn_count", 0), fb.get("insn_count", 0))
        + 0.3 * close(fa.get("direct_calls", 0), fb.get("direct_calls", 0))
        + 0.2 * close(fa.get("branches", 0), fb.get("branches", 0))
        + 0.1 * close(fa.get("returns", 0), fb.get("returns", 0))
    )


def compare(fa: dict, fb: dict) -> dict[str, Any]:
    """Score one candidate pair, reporting every signal separately."""
    comps: dict[str, float | None] = {
        "strings": _jaccard(set(fa.get("referenced_strings", [])), set(fb.get("referenced_strings", []))),
        "imports": _jaccard(set(fa.get("referenced_imports", [])), set(fb.get("referenced_imports", []))),
        "constants": _jaccard(set(fa.get("constants", [])), set(fb.get("constants", []))),
        "ngram5": _jaccard(set(fa.get("ngram5", [])), set(fb.get("ngram5", []))),
        "masked_sig": 1.0 if fa.get("masked_sig") and fa["masked_sig"] == fb.get("masked_sig") else 0.0,
        "shape": _shape_sim(fa, fb),
    }

    total_w = sum(WEIGHTS[k] for k, v in comps.items() if v is not None)
    if total_w == 0:
        score = 0.0
    else:
        score = sum(WEIGHTS[k] * v for k, v in comps.items() if v is not None) / total_w

    # Corroboration: how many *independent* content signals actually agree.
    # Reported separately from the score so a single strong signal cannot
    # masquerade as triangulation.
    independent = [
        comps["strings"],
        comps["imports"],
        comps["constants"],
        comps["ngram5"],
    ]
    agreeing = sum(1 for v in independent if v is not None and v >= 0.5)
    abstained = [k for k, v in comps.items() if v is None]

    return {
        "score": round(score, 4),
        "components": {k: (None if v is None else round(v, 4)) for k, v in comps.items()},
        "agreeing_signals": agreeing,
        "abstained": abstained,
        "exact_signature": comps["masked_sig"] == 1.0,
    }


def match_databases(
    db_a: dict,
    db_b: dict,
    *,
    min_score: float = 0.55,
    min_agreeing: int = 2,
    top: int = 3,
    max_matches: int = 5000,
) -> dict[str, Any]:
    """Match two fingerprint databases using content-addressed features.

    Candidates are generated from shared content (a referenced string, an
    import name, a constant, an n-gram) rather than from a byte-identical
    signature, so a function whose layout changed can still be found.

    `min_agreeing` requires corroboration from at least that many
    independent content signals. Setting it to 0 reproduces the
    single-signal behaviour and is not recommended.
    """
    fns_a: list[dict] = db_a["functions"]
    fns_b: list[dict] = db_b["functions"]

    # Inverted indexes over content features.
    by_string: dict[str, list[int]] = {}
    by_import: dict[str, list[int]] = {}
    by_const: dict[int, list[int]] = {}
    by_gram: dict[str, list[int]] = {}

    for j, f in enumerate(fns_b):
        for s in f.get("referenced_strings", []):
            by_string.setdefault(s, []).append(j)
        for s in f.get("referenced_imports", []):
            by_import.setdefault(s, []).append(j)
        for c in f.get("constants", []):
            by_const.setdefault(c, []).append(j)
        for g in f.get("ngram5", []):
            by_gram.setdefault(g, []).append(j)

    matches: list[dict] = []
    unmatched = 0

    for fa in fns_a:
        cand: dict[int, int] = {}

        def bump(js: list[int], w: int = 1) -> None:
            for j in js:
                cand[j] = cand.get(j, 0) + w

        for s in fa.get("referenced_strings", []):
            bump(by_string.get(s, []), 4)
        for s in fa.get("referenced_imports", []):
            bump(by_import.get(s, []), 3)
        for c in fa.get("constants", []):
            bump(by_const.get(c, []), 2)
        for g in fa.get("ngram5", []):
            bump(by_gram.get(g, []), 1)

        if not cand:
            unmatched += 1
            continue

        # Score the strongest candidates only; the inverted index already
        # ranked them by how much content they share.
        ranked = sorted(cand.items(), key=lambda kv: -kv[1])[:64]
        scored = []
        for j, _hits in ranked:
            r = compare(fa, fns_b[j])
            if r["score"] >= min_score and r["agreeing_signals"] >= min_agreeing:
                scored.append((r, j))

        if not scored:
            unmatched += 1
            continue

        scored.sort(key=lambda t: (-t[0]["score"], -t[0]["agreeing_signals"]))
        for r, j in scored[:top]:
            matches.append(
                {
                    "a": fa["va"],
                    "a_rva": fa.get("rva"),
                    "b": fns_b[j]["va"],
                    "b_rva": fns_b[j].get("rva"),
                    "a_name": fa.get("name"),
                    "b_name": fns_b[j].get("name"),
                    "a_size": fa.get("size"),
                    "b_size": fns_b[j].get("size"),
                    **r,
                }
            )
            if len(matches) >= max_matches:
                break
        if len(matches) >= max_matches:
            break

    matches.sort(key=lambda m: (-m["score"], -m["agreeing_signals"]))

    # Ambiguity is a property worth surfacing: one A mapping to several B
    # candidates at the same score is not a match, it is a family.
    from collections import Counter

    per_a = Counter(m["a"] for m in matches)
    return {
        "a_build": db_a.get("build_id"),
        "b_build": db_b.get("build_id"),
        "functions_a": len(fns_a),
        "functions_b": len(fns_b),
        "min_score": min_score,
        "min_agreeing_signals": min_agreeing,
        "matched_a_functions": len(per_a),
        "match_count": len(matches),
        "ambiguous_a_functions": sum(1 for v in per_a.values() if v > 1),
        "unmatched_a_functions": unmatched,
        "matches": matches,
    }


def build_database(
    image,
    index: dict,
    *,
    build_id: str,
    limit: int | None = None,
    sig_bytes: int = SIG_BYTES,
) -> dict[str, Any]:
    """Fingerprint every discovered function in an image."""
    starts = [int(s, 16) for s in index.get("func_starts", [])]
    if limit is not None:
        starts = starts[:limit]

    names = {s.va: s.name for s in image.symbols + image.exports}
    fns: list[dict] = []
    failed = 0
    for va in starts:
        try:
            fp = fingerprint_function(image, index, va, sig_bytes=sig_bytes)
        except Exception:
            failed += 1
            continue
        if fp["insn_count"] < 2:
            continue
        if va in names:
            fp["name"] = names[va]
        fns.append(fp)

    return {
        "schema": 2,
        "build_id": build_id,
        "identity": image.identity(),
        "function_count": len(fns),
        "skipped": failed,
        "functions": fns,
    }
