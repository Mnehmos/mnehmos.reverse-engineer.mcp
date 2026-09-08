"""remcp -- a general, robust reverse-engineering MCP server.

Design principles, each of which exists because its absence was measured as
a defect in the predecessor this replaces:

1. **Nothing escapes a tool.** Every handler is wrapped by `@tool`, which
   catches BaseException. The predecessor's library code raised SystemExit
   on a non-PE file; SystemExit is a BaseException, so it slipped past
   FastMCP's `except Exception` and killed the stdio loop. One bad path
   argument ended the session.

2. **Warnings travel with the answer.** Packed sections, wrong-architecture
   refusals and truncated analyses are reported in the response payload,
   not on stderr where no client shows them to a model.

3. **Architecture comes from the header.** A 64-bit image is decoded as
   64-bit or refused. It is never decoded as 32-bit "by default".

4. **Expensive analysis is cached by content hash.** The predecessor spent
   355 seconds rebuilding a full call graph on every query about the same
   file, then discarded all but one function.

5. **Read-only.** There is no patch, write, inject or execute tool. Runtime
   work belongs in a debugger a human is driving.

Run: python server.py   (stdio)
"""
from __future__ import annotations

import functools
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from remcp import __version__, cache, codeindex, disasm, fingerprint, graph, kb, strings, xrefs  # noqa: E402
from remcp.errors import ReError  # noqa: E402
from remcp.evidence import Envelope, image_warnings  # noqa: E402
from remcp.formats import classfile, dotnet  # noqa: E402
from remcp.formats import load as load_image  # noqa: E402
from remcp.formats import sniff  # noqa: E402

mcp = FastMCP("remcp")

MAX_RESPONSE_CHARS = int(os.environ.get("REMCP_MAX_RESPONSE_CHARS", "120000"))


# --------------------------------------------------------------------------
# Tool plumbing
# --------------------------------------------------------------------------


def _dump(payload: dict) -> str:
    """Serialize a response, clipping anything that would flood the context."""
    text = json.dumps(payload, indent=1, default=str)
    if len(text) <= MAX_RESPONSE_CHARS:
        return text
    clipped = {
        "ok": payload.get("ok", True),
        "target": payload.get("target"),
        "method": payload.get("method"),
        "reliability": payload.get("reliability"),
        "warnings": (payload.get("warnings") or [])
        + [
            {
                "code": "response_clipped",
                "detail": (
                    f"the full response was {len(text):,} characters, over the "
                    f"{MAX_RESPONSE_CHARS:,} limit. Narrow the query (add a filter, "
                    "lower the limit, or ask about one address) rather than "
                    "consuming the whole context window."
                ),
                "impact": "degraded",
            }
        ],
        "result": None,
    }
    return json.dumps(clipped, indent=1, default=str)


def tool(fn: Callable[..., dict]) -> Callable[..., str]:
    """Wrap a handler so no failure can propagate out of the tool layer."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> str:
        try:
            return _dump(fn(*args, **kwargs))
        except ReError as exc:
            return json.dumps(exc.to_dict(), indent=1, default=str)
        except (KeyboardInterrupt, SystemExit) as exc:
            # A library that calls sys.exit() must not be able to take the
            # server down. Convert it into an ordinary error response.
            return json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "aborted",
                        "message": f"the analysis aborted ({type(exc).__name__}): {exc}",
                        "hint": "this is a bug in the engine, not in your request",
                    },
                },
                indent=1,
            )
        except MemoryError:
            return json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "out_of_memory",
                        "message": "the analysis exhausted memory; narrow the request "
                        "or raise REMCP_MAX_FILE_BYTES only if the machine can take it",
                    },
                },
                indent=1,
            )
        except BaseException as exc:  # noqa: BLE001 - deliberate backstop
            return json.dumps(
                {
                    "ok": False,
                    "error": {
                        "code": "internal_error",
                        "message": f"{type(exc).__name__}: {exc}",
                        "traceback": traceback.format_exc(limit=8).splitlines()[-6:],
                    },
                },
                indent=1,
            )

    return wrapper


_image_cache: dict[tuple[str, int, int], Any] = {}


def _open(binary: str, **raw: Any):
    """Load an image, memoized on (path, mtime, size) within this process."""
    p = Path(binary).expanduser()
    try:
        st = p.stat()
        key = (str(p.resolve()), int(st.st_mtime), st.st_size)
    except OSError:
        key = None
    if key and not raw and key in _image_cache:
        return _image_cache[key]
    img = load_image(binary, **raw)
    if key and not raw:
        if len(_image_cache) > 8:
            _image_cache.clear()
        _image_cache[key] = img
    return img


def _envelope(image, method: str, *, code_analysis: bool = False) -> Envelope:
    env = Envelope(method=method, target=image.identity())
    if image.format_notes:
        env.extra["format_notes"] = image.format_notes
    if code_analysis:
        for w in image_warnings(image):
            env.warnings.append(w)
    return env


def _index(image, env: Envelope, *, use_cache: bool = True, include_packed: bool = False) -> dict:
    idx, hit = codeindex.load(image, use_cache=use_cache, include_packed=include_packed)
    env.extra["code_index"] = {
        "cached": hit,
        "instructions": idx.get("insn_count"),
        "decoder": idx.get("decoder"),
        "skipped_packed_sections": idx.get("skipped_packed_sections", []),
    }
    if idx.get("skipped_packed_sections"):
        env.warn(
            "packed_sections_skipped",
            "skipped high-entropy executable section(s) "
            + ", ".join(idx["skipped_packed_sections"])
            + ". Decoding encrypted bytes costs minutes and yields only noise "
            "-- on a real 16.5 MB image it produced 5,080,489 fabricated "
            "instructions in 394 seconds. Obtain an unpacked image or a process "
            "dump; pass include_packed=true only if the entropy estimate is wrong.",
            impact="degraded",
        )
    if include_packed and image.packed_exec_sections():
        env.warn(
            "packed_sections_included",
            "include_packed was set, so encrypted or compressed sections were "
            "decoded. Instructions, edges and signatures from those sections are "
            "not trustworthy.",
            impact="unreliable",
        )
    if idx.get("truncated"):
        env.warn(
            "index_truncated",
            "the instruction limit was reached; results cover only the "
            "portion of the image that was swept.",
            impact="degraded",
        )
    if idx.get("refs_truncated"):
        env.warn(
            "refs_clipped",
            f"reference sites per target were clipped at "
            f"{codeindex.MAX_SITES_PER_TARGET}; counts remain exact but site "
            "lists are partial.",
            impact="degraded",
        )
    return idx


# --------------------------------------------------------------------------
# Identity and structure
# --------------------------------------------------------------------------


@mcp.tool()
@tool
def re_identify(binary: str) -> dict:
    """Identify a binary: format, architecture, sections, imports/exports, and
    whether this engine can analyze its code. Start here."""
    image = _open(binary)
    env = _envelope(image, "header parse", code_analysis=True)

    try:
        _md, label = disasm.decoder_for(image)
        decodable, decoder = True, label
    except ReError as exc:
        decodable, decoder = False, None
        env.warn("no_decoder", exc.message, impact="degraded")

    env.result = {
        "sections": [s.to_dict() for s in image.sections],
        "section_count": len(image.sections),
        "import_count": len(image.imports),
        "imported_libraries": sorted({i.library for i in image.imports if i.library}),
        "export_count": len(image.exports),
        "symbol_count": len(image.symbols),
        "code_analysis_available": decodable,
        "decoder": decoder,
        "supported_architectures": disasm.supported(),
    }
    return env.to_dict()


@mcp.tool()
@tool
def re_sniff(path: str) -> dict:
    """Report the container format detected from a file's leading bytes,
    without fully parsing it. Useful on unknown or corrupt files."""
    from remcp.formats import resolve_target

    p = resolve_target(path)
    head = p.open("rb").read(64)
    return {
        "ok": True,
        "target": {"path": str(p), "size": p.stat().st_size},
        "method": "magic-byte inspection",
        "reliability": "sound",
        "warnings": [],
        "result": {"detected": sniff(head), "leading_bytes": head[:16].hex(" ")},
    }


@mcp.tool()
@tool
def re_translate(binary: str, address: str, space: str = "auto") -> dict:
    """Translate an address between file offset, RVA and VA through the
    section table. `space` is one of auto | file | rva | va."""
    image = _open(binary)
    env = _envelope(image, "section-table translation")
    val = xrefs.parse_va(address)

    def describe(va: int | None, off: int | None, rva: int | None) -> dict:
        sec = image.section_for_va(va) if va is not None else None
        return {
            "va": None if va is None else f"0x{va:x}",
            "rva": None if rva is None else f"0x{rva:x}",
            "file_offset": off,
            "section": sec.name if sec else None,
            "section_perms": sec.perms() if sec else None,
            "mapped": sec is not None,
            "has_file_bytes": off is not None,
        }

    out: dict[str, Any] = {}
    if space in ("auto", "va"):
        off = image.va_to_off(val)
        out["as_va"] = describe(val, off, image.va_to_rva(val))
    if space in ("auto", "rva"):
        va = image.rva_to_va(val)
        out["as_rva"] = describe(va, image.va_to_off(va), val)
    if space in ("auto", "file"):
        va = image.off_to_va(val)
        out["as_file_offset"] = describe(va, val, None if va is None else image.va_to_rva(va))
    if space not in ("auto", "va", "rva", "file"):
        env.warn("bad_space", f"unknown space {space!r}; interpreted as 'auto'")

    env.result = {"input": address, "interpretations": out}
    env.extra["note"] = (
        "A file offset is not an RVA. Adding the image base to a file offset "
        "is only correct when a section's file and virtual offsets coincide."
    )
    return env.to_dict()


# --------------------------------------------------------------------------
# Strings
# --------------------------------------------------------------------------


@mcp.tool()
@tool
def re_strings(
    binary: str,
    pattern: str = "",
    min_len: int = 5,
    limit: int = 200,
    encodings: str = "ascii,utf16",
    referenced_only: bool = False,
) -> dict:
    """Extract strings with correct VAs. `pattern` is a regex filter.
    `referenced_only` keeps only strings that code actually references."""
    import re as _re

    image = _open(binary)
    env = _envelope(image, "regex scan with section-table address mapping")
    encs = tuple(e.strip() for e in encodings.split(",") if e.strip())

    rows, hit = cache.get_or_build(
        image.sha256,
        "strings",
        {"min_len": min_len, "encodings": encs},
        lambda: strings.extract(image, min_len=min_len, encodings=encs),
    )
    env.extra["cached"] = hit
    total_extracted = len(rows)

    if referenced_only:
        idx = _index(image, env)
        rows = strings.annotate_referenced(list(rows), idx)
        rows = [r for r in rows if r.get("xrefs", 0) > 0]

    if pattern:
        try:
            rx = _re.compile(pattern, _re.IGNORECASE)
        except _re.error as exc:
            env.warn("bad_pattern", f"invalid regex {pattern!r}: {exc}", impact="degraded")
            rx = None
        if rx is not None:
            rows = [r for r in rows if rx.search(r["text"])]

    env.result = {
        "total_in_image": total_extracted,
        "matched": len(rows),
        "returned": min(len(rows), limit),
        "strings": rows[:limit],
    }
    if len(rows) > limit:
        env.warn(
            "result_limited",
            f"{len(rows)} strings matched; {limit} returned. Narrow with `pattern` "
            "or raise `limit`.",
            impact="degraded",
        )
    return env.to_dict()


# --------------------------------------------------------------------------
# Code
# --------------------------------------------------------------------------


@mcp.tool()
@tool
def re_disasm(binary: str, address: str, count: int = 40, raw_arch: str = "", raw_bits: int = 0) -> dict:
    """Disassemble instructions at an address. The predecessor had no
    disassembly tool at all, so an agent could never actually read code."""
    raw: dict[str, Any] = {}
    if raw_arch or raw_bits:
        raw = {"raw_arch": raw_arch or None, "raw_bits": raw_bits or None}
    image = _open(binary, **raw)
    env = _envelope(image, "capstone linear decode", code_analysis=True)

    va = xrefs.parse_va(address)
    sec = image.require_va(va)
    if not sec.x:
        env.warn(
            "non_executable_section",
            f"0x{va:x} is in section {sec.name!r} ({sec.perms()}), which is not "
            "executable. Decoding data as instructions produces plausible "
            "nonsense.",
            impact="unreliable",
        )

    md, label = disasm.decoder_for(image)
    env.extra["decoder"] = label
    count = max(1, min(count, 512))
    blob = image.read_va(va, count * 16) or b""

    rows = []
    for insn in disasm.sweep(md, blob, va):
        if len(rows) >= count:
            break
        rows.append(
            {
                "va": f"0x{insn.address:x}",
                "bytes": bytes(insn.bytes).hex(" "),
                "mnemonic": insn.mnemonic,
                "operands": insn.op_str,
                "size": insn.size,
                "is_call": disasm.is_call(insn),
                "is_jump": disasm.is_jump(insn),
                "is_ret": disasm.is_ret(insn),
                "target": (
                    f"0x{t:x}"
                    if (disasm.is_call(insn) or disasm.is_jump(insn))
                    and (t := disasm.branch_target(insn)) is not None
                    else None
                ),
            }
        )

    if not rows:
        env.warn("no_instructions", f"nothing decoded at 0x{va:x}", impact="unreliable")

    env.result = {"start_va": f"0x{va:x}", "section": sec.name, "count": len(rows), "instructions": rows}
    return env.to_dict()


@mcp.tool()
@tool
def re_xrefs(binary: str, target: str, is_string: bool = False, limit: int = 200,
             include_packed: bool = False) -> dict:
    """Cross-references to an address, or to a string's address.
    Scans decoded code operands AND data-section pointers -- vtables and
    pointer tables live in data, which the predecessor never scanned."""
    image = _open(binary)
    env = _envelope(image, "decoded-operand index + pointer-width data scan", code_analysis=True)
    idx = _index(image, env, include_packed=include_packed)

    if is_string:
        env.result = xrefs.xrefs_to_string(image, idx, target, limit=limit)
        if not env.result.get("found"):
            env.warn("string_not_found", f"{target!r} does not occur in the image", impact="degraded")
    else:
        env.result = xrefs.xrefs_to(image, idx, xrefs.parse_va(target), limit=limit)
    return env.to_dict()


@mcp.tool()
@tool
def re_functions(binary: str, limit: int = 200, named_only: bool = False,
                 include_packed: bool = False) -> dict:
    """List discovered function entry points with their evidence source."""
    image = _open(binary)
    env = _envelope(image, "symbols + exports + call targets, prologue fallback", code_analysis=True)
    idx = _index(image, env, include_packed=include_packed)

    names = {f"0x{s.va:x}": (s.name, s.source) for s in image.symbols + image.exports}
    g = graph.build_function_graph(idx)
    rows = []
    for va in idx.get("func_starts", []):
        nm = names.get(va)
        if named_only and nm is None:
            continue
        rows.append(
            {
                "va": va,
                "name": nm[0] if nm else None,
                "name_source": nm[1] if nm else None,
                "callers": len(g["callers"].get(va, [])),
                "callees": len(g["callees"].get(va, [])),
                "imports_used": len(g["imports_used"].get(va, [])),
            }
        )
    rows.sort(key=lambda r: -(r["callers"] + r["callees"]))

    env.result = {
        "function_count": len(idx.get("func_starts", [])),
        "named": sum(1 for v in idx.get("func_starts", []) if v in names),
        "returned": min(len(rows), limit),
        "functions": rows[:limit],
    }
    if not image.symbols and not image.exports:
        env.warn(
            "no_symbol_evidence",
            "this image has no symbol or export table, so function starts rest on "
            "call targets and prologue patterns. Treat boundaries as estimates.",
            impact="degraded",
        )
    return env.to_dict()


@mcp.tool()
@tool
def re_callgraph(binary: str, focus: str = "", depth: int = 1,
                 include_packed: bool = False) -> dict:
    """Call graph. With `focus`, returns one function's neighbourhood;
    without it, a summary. Built once and cached by content hash."""
    image = _open(binary)
    env = _envelope(image, "function-attributed call graph over cached code index", code_analysis=True)
    idx = _index(image, env, include_packed=include_packed)

    if focus:
        env.result = graph.neighborhood(image, idx, xrefs.parse_va(focus), depth=depth)
    else:
        g = graph.build_function_graph(idx)
        ranked = sorted(g["callees"].items(), key=lambda kv: -len(kv[1]))[:25]
        env.result = {
            "function_count": g["function_count"],
            "edge_count": g["edge_count"],
            "unattributed_call_sites": g["unattributed_call_sites"],
            "indirect_call_sites": sum(g["indirect_calls"].values()),
            "import_call_sites": len(idx.get("import_calls", [])),
            "highest_out_degree": [{"va": k, "callees": len(v)} for k, v in ranked],
        }
    if idx.get("indirect_calls"):
        env.warn(
            "indirect_calls_unresolved",
            f"{len(idx['indirect_calls'])} indirect call sites are recorded but not "
            "resolved to targets. Virtual dispatch and function-pointer calls are "
            "visible as sites, not as edges.",
            impact="degraded",
        )
    return env.to_dict()


# --------------------------------------------------------------------------
# Fingerprints and cross-build matching
# --------------------------------------------------------------------------


@mcp.tool()
@tool
def re_fingerprint(binary: str, address: str, sig_bytes: int = 128,
                   include_packed: bool = False) -> dict:
    """Layout-invariant fingerprint of one function: masked signature plus
    referenced strings, imports and constants (content, not addresses)."""
    image = _open(binary)
    env = _envelope(image, "masked signature + content-addressed features", code_analysis=True)
    idx = _index(image, env, include_packed=include_packed)
    env.result = fingerprint.fingerprint_function(
        image, idx, xrefs.parse_va(address), sig_bytes=max(16, min(sig_bytes, 512))
    )
    env.extra["note"] = (
        "referenced_strings / referenced_imports / constants are layout-invariant "
        "and comparable across builds. head_bytes and va are not."
    )
    return env.to_dict()


@mcp.tool()
@tool
def re_build_fingerprints(binary: str, build_id: str, out_path: str = "", limit: int = 0,
                          include_packed: bool = False) -> dict:
    """Fingerprint every discovered function and save a database for
    cross-build matching."""
    image = _open(binary)
    env = _envelope(image, "whole-image fingerprint database", code_analysis=True)
    idx = _index(image, env, include_packed=include_packed)

    db = fingerprint.build_database(image, idx, build_id=build_id, limit=limit or None)
    dest = Path(out_path) if out_path else Path.cwd() / "re_kb" / "signatures" / f"{build_id}.fnprints.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(db, separators=(",", ":")), encoding="utf-8")

    have = lambda k: sum(1 for f in db["functions"] if f.get(k))  # noqa: E731
    env.result = {
        "build_id": build_id,
        "path": str(dest),
        "function_count": db["function_count"],
        "skipped": db["skipped"],
        "feature_coverage": {
            "referenced_strings": have("referenced_strings"),
            "referenced_imports": have("referenced_imports"),
            "constants": have("constants"),
            "ngram5": have("ngram5"),
        },
    }
    if db["function_count"] and have("referenced_strings") + have("referenced_imports") == 0:
        env.warn(
            "no_content_features",
            "no function references a recoverable string or named import, so "
            "cross-build matching will fall back to structural signals only and "
            "will be much weaker.",
            impact="degraded",
        )
    return env.to_dict()


@mcp.tool()
@tool
def re_match_builds(
    db_a: str,
    db_b: str,
    min_score: float = 0.55,
    min_agreeing: int = 2,
    top: int = 3,
    limit: int = 100,
) -> dict:
    """Match two fingerprint databases by shared content. `min_agreeing`
    requires corroboration from that many independent signals."""
    a = json.loads(Path(db_a).read_text(encoding="utf-8"))
    b = json.loads(Path(db_b).read_text(encoding="utf-8"))
    for name, db in (("db_a", a), ("db_b", b)):
        if "functions" not in db:
            raise ReError(f"{name} is not a fingerprint database (missing 'functions')")

    res = fingerprint.match_databases(
        a, b, min_score=min_score, min_agreeing=min_agreeing, top=top
    )
    shown = res["matches"][:limit]
    env = Envelope(
        method="content-addressed candidate generation + multi-signal scoring",
        target={"a": a.get("identity", {}), "b": b.get("identity", {})},
    )
    env.result = {**res, "matches": shown, "matches_returned": len(shown)}
    if res["ambiguous_a_functions"]:
        env.warn(
            "ambiguous_matches",
            f"{res['ambiguous_a_functions']} source functions matched more than one "
            "candidate. Those are families of similar code, not identifications.",
            impact="degraded",
        )
    if min_agreeing < 2:
        env.warn(
            "corroboration_disabled",
            "min_agreeing < 2 accepts matches supported by a single signal, which is "
            "how a byte-identical stub becomes a false identification.",
            impact="degraded",
        )
    return env.to_dict()


# --------------------------------------------------------------------------
# Knowledge base
# --------------------------------------------------------------------------


@mcp.tool()
@tool
def re_kb_policy() -> dict:
    """The confidence policy: provenance vocabulary, per-class caps, and
    which classes this engine verifies against the binary itself."""
    doc = kb.policy_document()
    return {
        "ok": True,
        "target": {"kb_path": str(kb.kb_path())},
        "method": "declarative policy table",
        "reliability": "sound",
        "warnings": [],
        "result": doc,
    }


@mcp.tool()
@tool
def re_register_build(binary: str, build_id: str) -> dict:
    """Register a binary under a stable build id. Symbols are stored RVA-first
    against a registered build, and the VA is always derived."""
    image = _open(binary)
    store = kb.load_kb()
    ident = kb.register_build(store, image, build_id)
    path = kb.save_kb(store)
    env = _envelope(image, "build registration")
    env.result = {"build_id": build_id, "identity": ident, "kb_path": str(path)}
    return env.to_dict()


@mcp.tool()
@tool
def re_save_symbol(
    binary: str,
    build_id: str,
    name: str,
    rva: str,
    provenance: list[str],
    confidence: float,
    evidence: list[dict] | None = None,
    status: str = "candidate",
) -> dict:
    """Record a recovered symbol. Verifiable provenance classes are checked
    against the binary; a failed check rejects the write. See re_kb_policy."""
    image = _open(binary)
    env = _envelope(image, "policy evaluation with binary-backed verification", code_analysis=True)
    idx = _index(image, env)

    store = kb.load_kb()
    entry = kb.save_symbol(
        store,
        image,
        idx,
        name=name,
        build_id=build_id,
        rva=xrefs.parse_va(rva),
        provenance=list(provenance or []),
        confidence=confidence,
        evidence=list(evidence or []),
        status=status,
    )
    path = kb.save_kb(store)
    env.result = {"saved": entry, "kb_path": str(path)}
    if entry["verification"]["asserted"]:
        env.warn(
            "unverified_provenance",
            "some provenance classes could not be checked from static bytes and are "
            "stored as claims: "
            + ", ".join(a["class"] for a in entry["verification"]["asserted"]),
            impact="degraded",
        )
    return env.to_dict()


@mcp.tool()
@tool
def re_lookup_symbol(query: str = "", build_id: str = "", min_confidence: float = 0.0, limit: int = 50) -> dict:
    """Query the recovered-symbol knowledge base by name, VA or RVA."""
    store = kb.load_kb()
    hits = kb.lookup(store, query, build_id=build_id, min_confidence=min_confidence)
    return {
        "ok": True,
        "target": {"kb_path": str(kb.kb_path()), "builds": sorted(store.get("builds", {}))},
        "method": "knowledge-base query",
        "reliability": "sound",
        "warnings": [],
        "result": {
            "total_symbols": len(store.get("symbols", [])),
            "matched": len(hits),
            "symbols": hits[:limit],
        },
    }


# --------------------------------------------------------------------------
# Managed-runtime metadata: JVM and .NET
# --------------------------------------------------------------------------


@mcp.tool()
@tool
def re_java(
    binary: str,
    pattern: str = "",
    class_name: str = "",
    limit: int = 200,
) -> dict:
    """JVM introspection for .class files and .jar archives: class inventory,
    package tree, manifest, and constant-pool strings with their source entry
    and pool index. `class_name` switches to per-class detail (fields, methods,
    super, interfaces). Without `pattern`, a jar returns a frequency profile
    of its most common constant-pool strings instead of a full dump."""
    import hashlib
    import re as _re
    from collections import Counter

    path = classfile.resolve(binary)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    env = Envelope(method="JVM constant-pool extraction (inflated class entries)",
                   target={"path": str(path), "sha256": sha})

    head = path.open("rb").read(4)
    if classfile.is_class_file(head):
        info = classfile.parse_class(path.read_bytes())
        strings = info.pop("strings")
        if pattern:
            rx = _re.compile(pattern, _re.IGNORECASE)
            strings = [s for s in strings if rx.search(s["text"])]
        env.result = {"kind": "class", **info, "strings": strings[:limit]}
        return env.to_dict()

    if head[:2] == b"PK":
        scan, hit = cache.get_or_build(sha, "java", {}, lambda: classfile.scan_jar(path, want_strings=True))
        env.extra["cached"] = hit
        if scan["unparsed"]:
            env.warn(
                "unparsed_entries",
                f"{len(scan['unparsed'])} entries failed to parse and are excluded; "
                "first: " + "; ".join(f"{u['entry']}: {u['reason']}" for u in scan["unparsed"][:3]),
                impact="degraded",
            )
        if scan["truncated"]:
            env.warn("scan_truncated", f"{scan['truncated']} items skipped at analysis bounds", impact="degraded")

        if class_name:
            needle = class_name.lower()
            matched = [
                c for c in scan["classes"]
                if needle in c["class"].lower() or needle in c["entry"].lower()
            ][:limit]
            env.result = {
                "kind": "jar",
                "class_count": scan["class_count"],
                "entry_count": scan["entry_count"],
                "matched": len(matched),
                "classes": matched,
            }
            return env.to_dict()

        result = {
            "kind": "jar",
            "entry_count": scan["entry_count"],
            "class_count": scan["class_count"],
            "resource_count": scan["resource_count"],
            "manifest": scan["manifest"],
            "packages": scan["packages"][:25],
        }
        if pattern:
            rx = _re.compile(pattern, _re.IGNORECASE)
            matched = [s for s in scan["strings"] if rx.search(s["text"])][:limit]
            result["strings"] = matched
            result["matched"] = len(matched)
        else:
            freq = Counter(s["text"] for s in scan["strings"])
            result["top_strings"] = [{"count": c, "text": t} for t, c in freq.most_common(100)]
            result["total_strings"] = len(scan["strings"])
        env.result = result
        return env.to_dict()

    raise ReError(
        f"{path.name} is neither a Java class file (0xCAFEBABE) nor a zip/jar "
        "container (PK); re_java only accepts JVM targets"
    )


@mcp.tool()
@tool
def re_dotnet(binary: str, pattern: str = "", heap: str = "both", limit: int = 300) -> dict:
    """.NET assembly metadata: CLR runtime target, metadata streams, exact
    table row counts (TypeDef/MethodDef/Field/...), #Strings identifiers and
    #US user strings. `heap` is identifiers | user_strings | both."""
    import hashlib
    import re as _re

    path = classfile.resolve(binary)
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    info, hit = cache.get_or_build(sha, "dotnet", {}, lambda: dotnet.parse_cli(path))
    env = Envelope(
        method="ECMA-335 CLI metadata walk (BSJB root, #Strings/#US heaps, #~ header)",
        target={"path": str(path), "sha256": sha},
    )
    env.extra["cached"] = hit
    if heap not in ("identifiers", "user_strings", "both"):
        env.warn("bad_heap", f"unknown heap {heap!r}; interpreted as 'both'")

    rx = None
    if pattern:
        try:
            rx = _re.compile(pattern, _re.IGNORECASE)
        except _re.error as exc:
            env.warn("bad_pattern", f"invalid regex {pattern!r}: {exc}", impact="degraded")

    def pick(names: list[str]) -> list[str]:
        out = [s for s in names if rx is None or rx.search(s)]
        return out[:limit]

    identifiers = pick(info["identifiers"]) if heap in ("identifiers", "both") else None
    user_strings = pick(info["user_strings"]) if heap in ("user_strings", "both") else None
    env.result = {
        "machine": info["machine"],
        "clr_runtime_target": info["clr_runtime_target"],
        "metadata_version": info["metadata_version"],
        "entry_point": info["entry_point"],
        "streams": info["streams"],
        "table_rows": info["table_rows"],
        "identifier_count": info["identifier_count"],
        "user_string_count": info["user_string_count"],
        "identifiers": identifiers,
        "user_strings": user_strings,
    }
    total_id = info["identifier_count"] if identifiers is not None else 0
    total_us = info["user_string_count"] if user_strings is not None else 0
    if (identifiers is not None and len(identifiers) >= limit and total_id > limit) or (
        user_strings is not None and len(user_strings) >= limit and total_us > limit
    ):
        env.warn(
            "result_limited",
            f"heaps hold {total_id} identifiers and {total_us} user strings; "
            f"{limit} returned per list. Narrow with `pattern` or raise `limit`.",
            impact="degraded",
        )
    return env.to_dict()


# --------------------------------------------------------------------------
# Raw bytes
# --------------------------------------------------------------------------


@mcp.tool()
@tool
def re_read(binary: str, address: str, length: int = 64, space: str = "file") -> dict:
    """Read raw bytes at a file offset, RVA or VA and return a bounded hex +
    ASCII dump. `space` is one of file | rva | va. Use it to look at the exact
    bytes behind any address another tool reported."""
    from remcp.formats import resolve_target

    length = max(1, min(length, 4096))
    off = xrefs.parse_va(address)

    if space == "file":
        path = resolve_target(binary)
        data = path.read_bytes()
        if off >= len(data):
            raise ReError(
                f"file offset 0x{off:x} is past end of file ({len(data):,} bytes)",
            )
        chunk = data[off : off + length]
        section = None
        va = None
        env = Envelope(method="raw file read", target={"path": str(path), "size": len(data)})
    elif space in ("va", "rva"):
        image = _open(binary)
        if space == "rva":
            off = off + image.image_base
        if not image.contains_va(off):
            raise ReError(
                f"VA 0x{off:x} is not inside any mapped section of {image.path.name}",
            )
        sec = image.section_for_va(off)
        file_off = image.va_to_off(off)
        if file_off is None:
            raise ReError(f"VA 0x{off:x} maps into {sec.name!r} but has no bytes on disk (BSS tail)")
        chunk = image.data[file_off : file_off + length]
        section = sec.name
        va = off
        env = _envelope(image, "section-table translate + raw read")
    else:
        raise ReError(f"unknown space {space!r}; expected file | rva | va")

    if len(chunk) < length:
        env.warn("short_read", f"requested {length} bytes, got {len(chunk)} (end of data)", impact="degraded")

    rows = []
    for i in range(0, len(chunk), 16):
        piece = chunk[i : i + 16]
        gutter = f"{(va + i) if va is not None else (off + i):08x}"
        hexpart = " ".join(f"{b:02x}" for b in piece)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in piece)
        rows.append(f"{gutter}  {hexpart:<47}  |{asciipart}|")

    env.result = {
        "space": space,
        "address": address,
        "section": section,
        "file_offset": off if space == "file" else file_off,
        "va": None if va is None else f"0x{va:x}",
        "length": len(chunk),
        "hex": chunk.hex(),
        "dump": rows,
    }
    return env.to_dict()


# --------------------------------------------------------------------------
# Cache management
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Deep JVM analysis: bytecode, control flow, decompilation
# --------------------------------------------------------------------------


def _load_class_bytes(binary: str, class_name: str = "") -> tuple[bytes, str]:
    """Read one class, from a .class file or a named entry inside a .jar."""
    import zipfile

    path = classfile.resolve(binary)
    data = path.read_bytes()
    if data[:4] == b"\xca\xfe\xba\xbe":
        return data, path.name
    if not zipfile.is_zipfile(path):
        raise ReError(
            f"{path.name} is neither a class file nor a jar",
            hint="pass a .class file, or a .jar plus class_name",
        )
    with zipfile.ZipFile(path) as z:
        entries = [n for n in z.namelist() if n.endswith(".class")]
        if not class_name:
            raise ReError(
                f"{path.name} is a jar containing {len(entries)} classes; name one "
                "with class_name",
                examples=entries[:10],
            )
        want = class_name.replace(".", "/")
        cands = [
            n for n in entries
            if n == want + ".class" or n == class_name or n[:-6].endswith(want)
        ]
        if not cands:
            near = [n for n in entries if want.lower() in n.lower()][:10]
            raise ReError(
                f"class {class_name!r} not found in {path.name}",
                near_matches=near,
                class_count=len(entries),
            )
        return z.read(cands[0]), cands[0]


def _jvm_envelope(cf, source: str, path: str) -> Envelope:
    env = Envelope(
        method="class-file parse with Code attribute bodies",
        target={
            "path": path,
            "entry": source,
            "class": cf.name,
            "superclass": cf.superclass,
            "class_file_version": f"{cf.major}.{cf.minor}",
            "source_file": cf.source_file,
        },
    )
    if not any(m.code and m.code.local_vars for m in cf.methods):
        env.warn(
            "no_debug_names",
            "no LocalVariableTable in this class: it was compiled without -g or has "
            "been stripped, so locals appear as v0, v1 rather than their source names.",
            impact="degraded",
        )
    return env


@mcp.tool()
@tool
def re_jvm_methods(
    binary: str, class_name: str = "", pattern: str = "", limit: int = 200
) -> dict:
    """List a class's methods with signatures, bytecode size, cyclomatic
    complexity and loop count. Use this to choose a method to decompile."""
    import re as _re

    from remcp.jvm import cfg as jcfg
    from remcp.jvm import classfile as jcf
    from remcp.jvm.bytecode import decode

    data, entry = _load_class_bytes(binary, class_name)
    cf = jcf.parse(data)
    env = _jvm_envelope(cf, entry, binary)

    rx = _re.compile(pattern, _re.IGNORECASE) if pattern else None
    rows = []
    for m in cf.methods:
        if rx and not rx.search(m.name):
            continue
        row = {
            "name": m.name,
            "descriptor": m.descriptor,
            "signature": m.signature_text(),
            "access": m.access,
            "code_bytes": len(m.code.code) if m.code else 0,
        }
        if m.code:
            insns = decode(m.code.code)
            g = jcfg.CFG(insns, m.code.exceptions)
            row.update(
                {
                    "instructions": len(insns),
                    "blocks": len(g.blocks),
                    "cyclomatic_complexity": jcfg.cyclomatic_complexity(g),
                    "loops": len(g.natural_loops()),
                    "exception_handlers": len(m.code.exceptions),
                    "has_debug_names": bool(m.code.local_vars),
                }
            )
        rows.append(row)

    rows.sort(key=lambda r: -r.get("cyclomatic_complexity", 0))
    env.result = {
        "class": cf.to_dict(),
        "fields": [f.signature_text() for f in cf.fields],
        "method_count": len(cf.methods),
        "returned": min(len(rows), limit),
        "methods": rows[:limit],
    }
    return env.to_dict()


@mcp.tool()
@tool
def re_jvm_disasm(
    binary: str, method: str, class_name: str = "", descriptor: str = ""
) -> dict:
    """Disassemble one method's bytecode, with constant-pool references
    resolved to names and branch targets computed."""
    from remcp.jvm import classfile as jcf
    from remcp.jvm.bytecode import decode

    data, entry = _load_class_bytes(binary, class_name)
    cf = jcf.parse(data)
    env = _jvm_envelope(cf, entry, binary)

    m = cf.method(method, descriptor)
    if m is None:
        raise ReError(
            f"no method {method!r} in {cf.name}",
            available=[x.name for x in cf.methods][:40],
        )
    if m.code is None:
        env.warn(
            "no_code",
            f"{method} is abstract or native and carries no bytecode",
            impact="degraded",
        )
        env.result = {"signature": m.signature_text(), "instructions": []}
        return env.to_dict()

    insns = decode(m.code.code)
    env.result = {
        "signature": m.signature_text(),
        "max_stack": m.code.max_stack,
        "max_locals": m.code.max_locals,
        "instruction_count": len(insns),
        "exception_table": [e.to_dict() for e in m.code.exceptions],
        "instructions": [i.to_dict(cf.pool) for i in insns],
    }
    return env.to_dict()


@mcp.tool()
@tool
def re_jvm_decompile(
    binary: str,
    method: str = "",
    class_name: str = "",
    descriptor: str = "",
    limit: int = 40,
) -> dict:
    """Decompile bytecode back to readable Java. Without `method`, decompiles
    every method in the class. A result with `structured: false` did not fit a
    recognized control-flow shape and is approximate -- believe that flag
    rather than how clean the output looks."""
    from remcp.jvm import classfile as jcf
    from remcp.jvm import decompile as jdec

    data, entry = _load_class_bytes(binary, class_name)
    cf = jcf.parse(data)
    env = _jvm_envelope(cf, entry, binary)

    if method:
        m = cf.method(method, descriptor)
        if m is None:
            raise ReError(
                f"no method {method!r} in {cf.name}",
                available=[x.name for x in cf.methods][:40],
            )
        targets = [m]
    else:
        targets = cf.methods[:limit]

    results = [jdec.decompile_method(cf, m) for m in targets]
    approximate = [r["signature"] for r in results if not r["structured"]]
    if approximate:
        env.warn(
            "approximate_structure",
            f"{len(approximate)} method(s) did not fit a recognized control-flow "
            "shape; their output is a best-effort listing, not recovered source: "
            + ", ".join(approximate[:3]),
            impact="degraded",
        )

    env.result = {
        "class": cf.to_dict(),
        "method_count": len(results),
        "fully_structured": sum(1 for r in results if r["structured"]),
        "methods": results,
    }
    return env.to_dict()


@mcp.tool()
@tool
def re_jvm_cfg(
    binary: str, method: str, class_name: str = "", descriptor: str = ""
) -> dict:
    """Control-flow graph for one method: basic blocks, edges, natural loops,
    nesting depth and cyclomatic complexity."""
    from remcp.jvm import cfg as jcfg
    from remcp.jvm import classfile as jcf
    from remcp.jvm.bytecode import decode

    data, entry = _load_class_bytes(binary, class_name)
    cf = jcf.parse(data)
    env = _jvm_envelope(cf, entry, binary)

    m = cf.method(method, descriptor)
    if m is None or m.code is None:
        raise ReError(
            f"no method {method!r} with bytecode in {cf.name}",
            available=[x.name for x in cf.methods][:40],
        )

    insns = decode(m.code.code)
    g = jcfg.CFG(insns, m.code.exceptions)
    d = g.to_dict()
    d["signature"] = m.signature_text()
    d["cyclomatic_complexity"] = jcfg.cyclomatic_complexity(g)
    d["exception_table"] = [e.to_dict() for e in m.code.exceptions]
    env.result = d
    return env.to_dict()


# --------------------------------------------------------------------------
# Native algorithm recovery
# --------------------------------------------------------------------------


@mcp.tool()
@tool
def re_algorithms(binary: str, include_leads: bool = True,
                  include_packed: bool = False) -> dict:
    """Identify cryptographic, hashing, checksum and PRNG algorithms by their
    characteristic constants, and attribute each to the functions that use it.

    A result is `identified` only when enough distinct markers matched *and*
    at least one of them is unique to that algorithm; otherwise it is a
    `lead`. MD5 and SHA-1 share their four init words, so shared markers
    alone never carry an identification."""
    from remcp.algo import constants as algo

    image = _open(binary)
    env = _envelope(image, "constant-marker scan with discriminator requirement",
                    code_analysis=True)
    idx = _index(image, env, include_packed=include_packed)

    results = algo.scan_image(image, index=idx)
    algo.attribute_to_functions(image, idx, results)
    if not include_leads:
        results = [r for r in results if r["confident"]]

    identified = [r for r in results if r["confident"]]
    env.result = {
        "catalog_size": len(algo.CATALOG),
        "identified": len(identified),
        "leads": len(results) - len(identified),
        "algorithms": results,
    }
    if not results:
        env.warn(
            "no_algorithms_found",
            "no catalogued marker matched. The binary may use algorithms outside "
            "the catalog, a bitsliced or table-free implementation, or its code "
            "may be packed.",
            impact="degraded",
        )
    return env.to_dict()


@mcp.tool()
@tool
def re_function_cfg(binary: str, address: str, include_packed: bool = False) -> dict:
    """Control-flow graph of one native function: basic blocks, edges, natural
    loops, cyclomatic complexity and exit points. Function extent is an
    estimate and is reported as such."""
    from remcp.algo import nativecfg

    image = _open(binary)
    env = _envelope(image, "basic-block recovery with dominator-based loop detection",
                    code_analysis=True)
    idx = _index(image, env, include_packed=include_packed)

    env.result = nativecfg.build_function_cfg(image, idx, xrefs.parse_va(address))
    if env.result.get("resolved") and not image.symbols and not image.exports:
        env.warn(
            "estimated_boundaries",
            "this image has no symbol table, so the function's end is inferred "
            "from the next known entry point and a terminator scan. Blocks past "
            "the real end may belong to the following function.",
            impact="degraded",
        )
    return env.to_dict()


# --------------------------------------------------------------------------
# JVM plugin verification: will it load, and will it actually run?
# --------------------------------------------------------------------------


@mcp.tool()
@tool
def re_jvm_linkage(
    subject: str,
    classpath: list[str],
    entrypoints: list[str] | None = None,
    limit: int = 40,
) -> dict:
    """Verify a JVM plugin links against a host application.

    Every external call a class makes is a symbolic reference resolved lazily
    at first execution, so a host API change surfaces as `NoSuchMethodError`
    mid-session rather than at load. This resolves all of them statically
    against `classpath` and reports what would fail.

    `entrypoints` additionally checks that reflectively-loaded classes exist,
    are concrete, and have a no-argument constructor."""
    from remcp.jvm import linkage

    r = linkage.verify(subject, classpath)
    env = Envelope(
        method="constant-pool symbol resolution against the supplied classpath",
        target={
            "subject": r["subject"],
            "subject_classes": r["subject_classes"],
            "provided_classes": r["provided_classes"],
        },
    )

    if entrypoints:
        r["entrypoints"] = linkage.check_entrypoints(subject, entrypoints, classpath)
        broken = [e for e in r["entrypoints"] if e["verdict"] != "ok"]
        if broken:
            env.warn(
                "entrypoint_will_not_load",
                "; ".join(f"{e['declared']}: {e['verdict']}" for e in broken),
                impact="unreliable",
            )

    missing = r["missing_classes"] + r["missing_members"]
    r["missing_classes"] = r["missing_classes"][:limit]
    r["missing_members"] = r["missing_members"][:limit]

    if missing:
        env.warn(
            "unresolved_references",
            f"{len(missing)} reference(s) cannot be resolved. Each is a "
            "NoClassDefFoundError or NoSuchMethodError waiting at the call site.",
            impact="unreliable",
        )
    if r["unchecked_members"]:
        env.warn(
            "incomplete_classpath",
            f"{r['unchecked_members']} member(s) could not be checked because a "
            "supertype is not on the supplied classpath. An absent answer is not "
            "a negative one -- add the missing jar for a complete result.",
            impact="degraded",
        )
    for s in r["classpath"]:
        if s["status"] != "ok":
            env.warn("classpath_entry_unusable", f"{s['path']}: {s['status']}")

    env.result = r
    return env.to_dict()


@mcp.tool()
@tool
def re_jvm_health(
    subject: str,
    classpath: list[str],
    data_dir: str = "",
    limit: int = 40,
) -> dict:
    """Find plugin code that loads cleanly and still does nothing.

    Three failures that survive loading:
    unimplemented inherited abstract methods (`AbstractMethodError` at first
    call); methods that look like overrides but match no supertype signature
    (an overload the host will never call -- the usual result of a host API
    changing a parameter type); and class names in data files that no longer
    resolve, which silently disable whatever feature they back.

    `data_dir` enables the data-file scan."""
    from remcp.jvm import checks

    env = Envelope(
        method="hierarchy analysis + reflective-reference resolution",
        target={"subject": subject},
    )

    abstracts = checks.check_abstract_implementations(subject, classpath)
    overrides = checks.check_overrides(subject, classpath)
    data = (checks.check_data_references(data_dir, [subject], classpath)
            if data_dir else None)

    if abstracts:
        env.warn(
            "unimplemented_abstract_methods",
            f"{len(abstracts)} concrete class(es) leave an inherited abstract method "
            "unimplemented; each throws AbstractMethodError at the first call.",
            impact="unreliable",
        )
    if overrides:
        env.warn(
            "possible_broken_overrides",
            f"{len(overrides)} method(s) share a supertype method's name and parameter "
            "count but not its signature. Overloading is legal, so treat these as "
            "leads -- but a real one never gets called.",
            impact="degraded",
        )
    if data and data["missing"]:
        env.warn(
            "unresolvable_data_references",
            f"{len(data['missing'])} class name(s) in data files do not resolve; the "
            "features they back will not work while the rest of the plugin runs.",
            impact="unreliable",
        )

    env.result = {
        "unimplemented_abstract": abstracts[:limit],
        "unimplemented_abstract_count": len(abstracts),
        "possible_broken_overrides": overrides[:limit],
        "possible_broken_override_count": len(overrides),
        "data_references": data,
        "clean": not abstracts and not overrides and not (data and data["missing"]),
    }
    return env.to_dict()


@mcp.tool()
@tool
def re_jvm_duplicates(paths: list[str]) -> dict:
    """Classes defined in more than one jar on a shared classpath.

    Which copy wins is load-order dependent, so a duplicate is a real defect
    even when both copies are individually valid."""
    from remcp.jvm import linkage

    dups = linkage.find_duplicate_classes(paths)
    env = Envelope(method="class-name collision scan across the supplied jars",
                   target={"inputs": len(paths)})
    if dups:
        env.warn(
            "duplicate_class_definitions",
            f"{len(dups)} class(es) are defined in more than one jar. The winner "
            "depends on classpath order, which the host controls.",
            impact="degraded",
        )
    env.result = {"duplicate_count": len(dups), "duplicates": dups[:200]}
    return env.to_dict()


@mcp.tool()
@tool
def re_cache(action: str = "stats", binary: str = "") -> dict:
    """Inspect or clear the analysis cache. `action` is stats | clear."""
    if action == "clear":
        sha = _open(binary).sha256 if binary else None
        n = cache.clear(sha)
        return {
            "ok": True,
            "method": "cache maintenance",
            "reliability": "sound",
            "warnings": [],
            "result": {"cleared": n, "scope": binary or "all"},
        }
    return {
        "ok": True,
        "method": "cache maintenance",
        "reliability": "sound",
        "warnings": [],
        "result": {**cache.stats(), "engine_version": __version__},
    }


if __name__ == "__main__":
    mcp.run()
