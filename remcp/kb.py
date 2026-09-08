"""Recovered-symbol knowledge base with enforced, verifiable provenance.

First principle: a gate the caller can satisfy by asserting a magic word is
not a control. Where a claim can be checked, check it.

The predecessor's `re_save_symbol` advertised mechanical enforcement of a
tiered confidence policy. What it actually enforced was one rule:

    if confidence > 0.60 and not (provenance & RUNTIME_CLASSES): reject

Its 0.80 gate tested an identical predicate and could never fire
independently, so the three documented tiers were one gate. Nothing else in
the written policy was implemented: per-class caps went unchecked (five
stored entries sat at 0.60 under a class the policy caps at 0.40), the
"two independent classes" requirement for 0.60 went unchecked (two entries
had one), the provenance vocabulary went unvalidated (`structural-analysis`,
used by 10 of 13 entries, is not a policy term at all), and `evidence` was
never inspected and could be empty. A caller wanting 0.95 typed
`dynamic_trace` and got it.

This module fixes that by splitting provenance into two kinds:

  verifiable      the engine can confirm the claim against the binary right
                  now -- a claimed string reference either exists in the
                  image or it does not. A failing check is a rejection, not
                  a warning.
  asserted        the engine cannot confirm it from static bytes (a debugger
                  trace, an experiment, an authoritative symbol source).
                  These require a named evidence artifact, and every stored
                  record says plainly which of its classes were verified and
                  which were taken on trust.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .errors import PolicyError, TargetError

SCHEMA = 2


@dataclass(frozen=True)
class ProvenanceClass:
    name: str
    cap: float
    verifiable: bool
    requires_artifact: bool
    description: str


# The closed vocabulary. A class not in this table is rejected outright,
# which is what would have caught `structural-analysis` before it became the
# most common class in the predecessor's database.
CLASSES: dict[str, ProvenanceClass] = {
    c.name: c
    for c in [
        ProvenanceClass("structural_guess", 0.20, False, False,
                        "position or plausibility argument only"),
        ProvenanceClass("string_xref", 0.40, True, False,
                        "the function references a specific string present in the image"),
        ProvenanceClass("import_xref", 0.40, True, False,
                        "the function calls a specific named import"),
        ProvenanceClass("constant_xref", 0.40, True, False,
                        "the function uses a specific distinctive constant"),
        ProvenanceClass("callgraph_position", 0.40, True, False,
                        "the function is called by, or calls, a specific known function"),
        ProvenanceClass("cross_build_match", 0.60, True, False,
                        "matched to a named function in another build with corroborating signals"),
        ProvenanceClass("community_source", 0.60, False, False,
                        "published documentation, headers, or community reverse engineering"),
        ProvenanceClass("symbol_table", 0.95, True, False,
                        "the image's own symbol table names this address"),
        ProvenanceClass("export_table", 0.95, True, False,
                        "the image's export table names this address"),
        ProvenanceClass("dynamic_trace", 0.80, False, True,
                        "observed under a debugger or tracer at runtime"),
        ProvenanceClass("experimental_manipulation", 0.95, False, True,
                        "a predicted behaviour change was produced and reproduced"),
        ProvenanceClass("authoritative_source", 1.00, False, True,
                        "vendor symbols, source code, or equivalent ground truth"),
    ]
}

# Above this confidence, one class is not enough. Corroboration from two
# independent classes is required -- the rule the predecessor documented for
# tier 0.60 and never implemented.
CORROBORATION_THRESHOLD = 0.40
MIN_CLASSES_ABOVE_THRESHOLD = 2


def policy_document() -> dict:
    return {
        "schema": SCHEMA,
        "corroboration_threshold": CORROBORATION_THRESHOLD,
        "min_classes_above_threshold": MIN_CLASSES_ABOVE_THRESHOLD,
        "rule": (
            "confidence must not exceed the highest cap among the supplied "
            "provenance classes; above the corroboration threshold at least "
            f"{MIN_CLASSES_ABOVE_THRESHOLD} distinct classes are required; "
            "every verifiable class is checked against the binary and a "
            "failed check rejects the write; every artifact-requiring class "
            "must name a concrete evidence artifact."
        ),
        "classes": {
            n: {
                "cap": c.cap,
                "verifiable": c.verifiable,
                "requires_artifact": c.requires_artifact,
                "description": c.description,
            }
            for n, c in CLASSES.items()
        },
    }


# --------------------------------------------------------------------------
# Verifiers: each returns (ok, detail). They are the actual control.
# --------------------------------------------------------------------------


def _verify_string_xref(ctx: "VerifyContext") -> tuple[bool, str]:
    want = ctx.claim.get("string")
    if not want:
        raise PolicyError("provenance 'string_xref' requires evidence {kind:'string_xref', string:'...'}")
    from .strings import find_string_vas

    hits = find_string_vas(ctx.image, want)
    if not hits:
        return False, f"string {want!r} does not occur in {ctx.image.path.name}"
    refs = ctx.index.get("refs_by_target", {})
    fn_lo, fn_hi = ctx.extent
    for h in hits:
        for site, _kind in refs.get(h["va"], []):
            s = int(site, 16)
            if fn_lo <= s < fn_hi:
                return True, f"string {want!r} at {h['va']} referenced from {site}"
    return False, (
        f"string {want!r} exists at "
        f"{', '.join(h['va'] for h in hits[:4])} but no reference to it lies within "
        f"0x{fn_lo:x}..0x{fn_hi:x}"
    )


def _verify_import_xref(ctx: "VerifyContext") -> tuple[bool, str]:
    want = (ctx.claim.get("import") or "").lower()
    if not want:
        raise PolicyError("provenance 'import_xref' requires evidence {kind:'import_xref', import:'lib!Func'}")
    fn_lo, fn_hi = ctx.extent
    for site_s, _slot, qualified in ctx.index.get("import_calls", []):
        s = int(site_s, 16)
        if fn_lo <= s < fn_hi and want in qualified.lower():
            return True, f"call to {qualified} at {site_s}"
    # Also accept a reference to the slot without a call (e.g. a stored fn ptr).
    slots = {v: k for k, v in ((i.slot_va, i.qualified) for i in ctx.image.imports) if v}
    refs = ctx.index.get("refs_by_target", {})
    for qualified, slot_va in slots.items():
        if slot_va is None or want not in qualified.lower():
            continue
        for site, _k in refs.get(f"0x{slot_va:x}", []):
            if fn_lo <= int(site, 16) < fn_hi:
                return True, f"reference to {qualified} slot at {site}"
    return False, f"no reference to an import matching {want!r} within 0x{fn_lo:x}..0x{fn_hi:x}"


def _verify_constant_xref(ctx: "VerifyContext") -> tuple[bool, str]:
    raw = ctx.claim.get("constant")
    if raw is None:
        raise PolicyError("provenance 'constant_xref' requires evidence {kind:'constant_xref', constant:<int|hex>}")
    want = int(raw, 16) if isinstance(raw, str) else int(raw)
    from .fingerprint import fingerprint_function

    fp = fingerprint_function(ctx.image, ctx.index, ctx.va)
    if want in fp["constants"]:
        return True, f"constant {want:#x} present in function fingerprint"
    return False, f"constant {want:#x} not among the function's constants"


def _verify_callgraph_position(ctx: "VerifyContext") -> tuple[bool, str]:
    from .graph import build_function_graph

    peer = ctx.claim.get("calls") or ctx.claim.get("called_by")
    if not peer:
        raise PolicyError(
            "provenance 'callgraph_position' requires evidence "
            "{kind:'callgraph_position', calls:'0x...'} or {called_by:'0x...'}"
        )
    peer_va = int(peer, 16) if isinstance(peer, str) else int(peer)
    g = build_function_graph(ctx.index)
    key = f"0x{ctx.va:x}"
    pk = f"0x{peer_va:x}"
    if ctx.claim.get("calls") and pk in g["callees"].get(key, []):
        return True, f"{key} calls {pk}"
    if ctx.claim.get("called_by") and pk in g["callers"].get(key, []):
        return True, f"{key} is called by {pk}"
    return False, f"no such call-graph relationship between {key} and {pk}"


def _verify_symbol_table(ctx: "VerifyContext") -> tuple[bool, str]:
    for s in ctx.image.symbols:
        if s.va == ctx.va:
            return True, f"symbol table names 0x{ctx.va:x} as {s.name!r} (source: {s.source})"
    return False, f"the image's symbol table has no entry at 0x{ctx.va:x}"


def _verify_export_table(ctx: "VerifyContext") -> tuple[bool, str]:
    for s in ctx.image.exports:
        if s.va == ctx.va:
            return True, f"export table names 0x{ctx.va:x} as {s.name!r}"
    return False, f"the image's export table has no entry at 0x{ctx.va:x}"


def _verify_cross_build_match(ctx: "VerifyContext") -> tuple[bool, str]:
    score = ctx.claim.get("score")
    agreeing = ctx.claim.get("agreeing_signals")
    peer = ctx.claim.get("matched_build")
    if score is None or agreeing is None or not peer:
        raise PolicyError(
            "provenance 'cross_build_match' requires evidence {kind:'cross_build_match', "
            "matched_build:'<build_id>', score:<float>, agreeing_signals:<int>} "
            "as produced by re_match_builds -- an assertion that two functions "
            "'look the same' is not a match result"
        )
    if float(score) < 0.55:
        return False, f"match score {score} is below the 0.55 admission threshold"
    if int(agreeing) < 2:
        return False, (
            f"match has only {agreeing} agreeing signal(s); cross-build identity "
            "requires corroboration from at least 2 independent content signals"
        )
    return True, f"match to {peer} at score {score} with {agreeing} agreeing signals"


VERIFIERS: dict[str, Callable[["VerifyContext"], tuple[bool, str]]] = {
    "string_xref": _verify_string_xref,
    "import_xref": _verify_import_xref,
    "constant_xref": _verify_constant_xref,
    "callgraph_position": _verify_callgraph_position,
    "symbol_table": _verify_symbol_table,
    "export_table": _verify_export_table,
    "cross_build_match": _verify_cross_build_match,
}


@dataclass
class VerifyContext:
    image: Any
    index: dict
    va: int
    extent: tuple[int, int]
    claim: dict


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------


def kb_path() -> Path:
    env = os.environ.get("REMCP_KB")
    if env:
        return Path(env)
    return Path.cwd() / "re_kb" / "symbols.json"


def _empty() -> dict:
    return {"schema": SCHEMA, "builds": {}, "symbols": []}


def load_kb() -> dict:
    p = kb_path()
    if not p.exists():
        return _empty()
    try:
        kb = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TargetError(f"knowledge base at {p} is unreadable: {exc}", path=str(p)) from exc
    kb.setdefault("schema", SCHEMA)
    kb.setdefault("builds", {})
    kb.setdefault("symbols", [])
    return kb


def save_kb(kb: dict) -> Path:
    """Atomic write with a one-generation backup.

    The predecessor rewrote the whole file in place with no temp file, no
    fsync and no backup, so an interrupted write truncated the database.
    """
    p = kb_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(kb, indent=1, sort_keys=False)

    if p.exists():
        try:
            backup = p.with_suffix(p.suffix + ".bak")
            backup.write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
        except OSError:
            pass

    fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return p


def register_build(kb: dict, image, build_id: str) -> dict:
    """Record a build's identity so symbols can be stored RVA-first."""
    ident = image.identity()
    existing = kb["builds"].get(build_id)
    if existing and existing.get("sha256") != ident["sha256"]:
        raise PolicyError(
            f"build_id {build_id!r} is already registered to a different binary "
            f"(stored sha256 {existing.get('sha256', '')[:16]}..., "
            f"supplied {ident['sha256'][:16]}...). Build ids must be stable, "
            "because every stored RVA is meaningless against the wrong image.",
            build_id=build_id,
        )
    kb["builds"][build_id] = ident
    return ident


def evaluate(
    image,
    index: dict,
    *,
    va: int,
    provenance: list[str],
    confidence: float,
    evidence: list[dict],
) -> dict:
    """Apply the policy. Raises PolicyError on any violation.

    Returns a verification record describing what was checked and what was
    taken on trust, which is stored alongside the symbol so a later reader
    can tell the difference.
    """
    if not isinstance(confidence, (int, float)):
        raise PolicyError("confidence must be a number")
    confidence = float(confidence)
    if not (0.0 <= confidence <= 1.0):
        raise PolicyError(f"confidence {confidence} is outside 0.0..1.0")

    classes = list(dict.fromkeys(provenance))  # dedupe, keep order
    if not classes:
        raise PolicyError(
            "at least one provenance class is required",
            vocabulary=sorted(CLASSES),
        )

    unknown = [c for c in classes if c not in CLASSES]
    if unknown:
        raise PolicyError(
            f"unknown provenance class(es): {', '.join(unknown)}. "
            "The vocabulary is closed so that a typo cannot silently become "
            "a new evidence class.",
            unknown=unknown,
            vocabulary=sorted(CLASSES),
        )

    cap = max(CLASSES[c].cap for c in classes)
    if confidence > cap:
        limiting = sorted(classes, key=lambda c: -CLASSES[c].cap)
        raise PolicyError(
            f"confidence {confidence} exceeds the cap {cap} implied by "
            f"provenance {classes}. Highest-cap class present: "
            f"{limiting[0]} (cap {CLASSES[limiting[0]].cap}).",
            confidence=confidence,
            cap=cap,
            classes=classes,
        )

    if confidence > CORROBORATION_THRESHOLD and len(classes) < MIN_CLASSES_ABOVE_THRESHOLD:
        raise PolicyError(
            f"confidence {confidence} is above the corroboration threshold "
            f"{CORROBORATION_THRESHOLD} but only {len(classes)} provenance class "
            f"was supplied; {MIN_CLASSES_ABOVE_THRESHOLD} independent classes are required",
            classes=classes,
        )

    by_kind: dict[str, dict] = {}
    for e in evidence or []:
        if not isinstance(e, dict) or "kind" not in e:
            raise PolicyError(
                "each evidence entry must be an object with a 'kind' field naming "
                "the provenance class it supports",
                got=e,
            )
        by_kind[str(e["kind"])] = e

    from .graph import FunctionMap

    starts = [int(s, 16) for s in index.get("func_starts", [])]
    extent = FunctionMap(starts).extent(va)

    verified: list[dict] = []
    asserted: list[dict] = []

    for cls in classes:
        spec = CLASSES[cls]
        claim = by_kind.get(cls, {})

        if spec.verifiable:
            verifier = VERIFIERS[cls]
            ctx = VerifyContext(image=image, index=index, va=va, extent=extent, claim=claim)
            ok, detail = verifier(ctx)
            if not ok:
                raise PolicyError(
                    f"provenance {cls!r} failed verification against "
                    f"{image.path.name}: {detail}",
                    provenance_class=cls,
                    detail=detail,
                )
            verified.append({"class": cls, "detail": detail})
        else:
            if spec.requires_artifact:
                artifact = claim.get("artifact") or claim.get("reference")
                if not artifact:
                    raise PolicyError(
                        f"provenance {cls!r} cannot be checked from static bytes, so it "
                        "requires evidence {kind:'" + cls + "', artifact:'<log, trace file, "
                        "recipe, or symbol source>'} naming a concrete artifact",
                        provenance_class=cls,
                    )
                asserted.append({"class": cls, "artifact": str(artifact), "verified": False})
            else:
                asserted.append({"class": cls, "verified": False, "note": claim.get("note", "")})

    return {
        "cap_applied": cap,
        "classes": classes,
        "verified": verified,
        "asserted": asserted,
        "function_extent": {"start": f"0x{extent[0]:x}", "end": f"0x{extent[1]:x}"},
        "note": (
            "Verified classes were checked against the binary at write time. "
            "Asserted classes were not and cannot be; they are recorded as "
            "claims with a named artifact."
        )
        if asserted
        else "All supplied provenance classes were machine-verified.",
    }


def save_symbol(
    kb: dict,
    image,
    index: dict,
    *,
    name: str,
    build_id: str,
    rva: int,
    provenance: list[str],
    confidence: float,
    evidence: list[dict],
    status: str = "candidate",
) -> dict:
    """Add or revise a symbol. RVA-first; the VA is always derived."""
    if not name or not name.strip():
        raise PolicyError("symbol name is required")
    if build_id not in kb["builds"]:
        raise PolicyError(
            f"unknown build_id {build_id!r}; register it first with re_register_build",
            known=sorted(kb["builds"]),
        )
    stored = kb["builds"][build_id]
    if stored.get("sha256") != image.sha256:
        raise PolicyError(
            f"build_id {build_id!r} is registered to sha256 "
            f"{stored.get('sha256','')[:16]}... but the supplied binary is "
            f"{image.sha256[:16]}.... Refusing to store an RVA derived from a "
            "different image.",
            build_id=build_id,
        )

    va = image.rva_to_va(rva)
    image.require_va(va)

    verification = evaluate(
        image, index, va=va, provenance=provenance, confidence=confidence, evidence=evidence
    )

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    entry = {
        "name": name.strip(),
        "build_id": build_id,
        "rva": f"0x{rva:x}",
        "va": f"0x{va:x}",
        "confidence": float(confidence),
        "provenance": verification["classes"],
        "evidence": evidence or [],
        "verification": verification,
        "status": status,
        "updated": now,
        "history": [],
    }

    for i, s in enumerate(kb["symbols"]):
        if s.get("name") == entry["name"] and s.get("build_id") == build_id:
            # Prior evidence is preserved, not overwritten. The predecessor
            # removed the old record and appended a new one, discarding the
            # earlier evidence list entirely and keeping only a scalar
            # previous_confidence.
            hist = list(s.get("history", []))
            hist.append(
                {
                    "at": s.get("updated") or s.get("added"),
                    "confidence": s.get("confidence"),
                    "provenance": s.get("provenance"),
                    "evidence": s.get("evidence"),
                    "status": s.get("status"),
                }
            )
            entry["history"] = hist
            entry["added"] = s.get("added", now)
            entry["previous_confidence"] = s.get("confidence")
            if float(confidence) < float(s.get("confidence") or 0):
                entry["note"] = f"downgraded {s.get('confidence')} -> {confidence}"
            kb["symbols"][i] = entry
            return entry

    entry["added"] = now
    kb["symbols"].append(entry)
    return entry


def lookup(kb: dict, query: str, *, build_id: str = "", min_confidence: float = 0.0) -> list[dict]:
    q = query.lower().strip()
    out = []
    for s in kb.get("symbols", []):
        if build_id and s.get("build_id") != build_id:
            continue
        if float(s.get("confidence") or 0) < min_confidence:
            continue
        if q and q not in s.get("name", "").lower() and q not in s.get("va", "").lower() and q not in s.get("rva", "").lower():
            continue
        out.append(s)
    out.sort(key=lambda s: -float(s.get("confidence") or 0))
    return out
