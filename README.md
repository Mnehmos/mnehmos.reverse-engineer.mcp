# remcp — a general reverse-engineering MCP server

A read-only binary analysis engine exposed over MCP. Built from first
principles after auditing a predecessor whose defects are documented here
and pinned by regression tests, so they cannot come back quietly.

**Status:** working, tested. 139 tests — 138 passing, 1 environment-dependent
skip — plus an end-to-end MCP wire test. Licensed MIT.

```sh
git clone https://github.com/Mnehmos/mnehmos.reverse-engineer.mcp.git
cd mnehmos.reverse-engineer.mcp
pip install -r requirements.txt
python server.py            # stdio MCP server
python -m pytest tests/ -q  # 138 passed, 1 skipped
python tests/wire_test.py   # end-to-end over stdio
```

## What it analyzes

| Axis | Support |
|---|---|
| Containers | PE/COFF, ELF, Mach-O (thin), headerless blobs |
| Architectures | x86-16/32/64, ARM, AArch64, MIPS 32/64, PowerPC 32/64, SPARC, RISC-V — 19 arch/bits/endian combinations |
| Bitness | Derived from the header. A mismatch is refused, never guessed |
| Symbols | PE imports/exports, ELF symtab + dynsym + DT_NEEDED, Mach-O symtab + dylibs |
| Fat Mach-O | Detected and refused with instructions, not silently sliced |

Anything unsupported raises a typed error naming what was detected and what
to do instead. Nothing is analyzed on a guess.

## The seven design principles

Each one exists because its absence was *measured* as a defect.

### 1. An address is meaningless without its space

File offsets, RVAs and VAs are three different spaces. `remcp/image.py` owns
every conversion; they go through the section table and return `None` for
addresses that do not map.

The predecessor computed string addresses as `image_base + file_offset`.
Measured against a real PE, **1.17% of the resulting addresses were correct**
— and the coincidental overlap was the only reason any were. The matching
signal built on them was dead in every shipped database.

`test_naive_base_plus_offset_is_wrong` asserts the shortcut is *not*
equivalent, so nobody reintroduces it thinking it is harmless.

### 2. Decode with the declared architecture, or refuse

`remcp/disasm.py` derives the capstone mode from the image header. An
unsupported combination raises `UnsupportedError` listing what is supported.

The predecessor hardcoded 32-bit x86 in three places. Fed a 64-bit PE it
returned **1,187 fabricated call edges and zero warnings**, one call after
its own inspector had correctly printed `AMD64 (64-bit x64)`.

### 3. Warnings travel with the answer

Every response is an evidence envelope:

```json
{ "ok": true, "target": {"sha256": "...", "arch": "x86", "bits": 64},
  "method": "...", "reliability": "sound|degraded|unreliable",
  "warnings": [{"code": "...", "detail": "...", "impact": "..."}],
  "result": { ... } }
```

The predecessor detected packed code correctly and printed the warning to
**stderr**, which no MCP client surfaces to a model. Its `re_callgraph` on
the default target returned `function_count: 9` alongside **21,339
fabricated edges**, with nothing in the payload marking them as noise.

### 4. Remove the foot-gun rather than documenting it

High-entropy executable sections are **not swept by default**. On a real
16.5 MB CEG-encrypted image, sweeping `.text` produced 5,080,489 "instructions"
in 394 seconds — all of it noise.

```
predecessor:  355.4 s per call, every call, 21,339 fabricated edges, no warning
remcp:        0.00 s, an in-band warning naming the encrypted sections
```

`include_packed=true` is the deliberate override, and it attaches an
`unreliable` warning of its own.

### 5. Disassemble once, answer many questions

`remcp/codeindex.py` does one linear sweep and records cross-references, the
call graph, function starts and instruction counts. It is cached by content
hash, so a rebuilt binary gets a new key automatically and there is no
invalidation to forget.

| 23.4 MB unpacked PE, 5.0 M instructions | |
|---|---|
| cold index build | 97.8 s |
| warm (cached) | 2.7 s — **37×** |
| found | 42,085 functions, 278,187 calls, 499,814 jumps, 67,819 indirect sites |

The predecessor rebuilt the whole graph on **every** call — 355 s for a
smaller file — then discarded everything except one function's neighbourhood.

### 6. A cross-build signal must not depend on the layout

This is the audit's central finding. The predecessor's matcher advertised
four-signal triangulation. Measured over its own shipped databases:

```
min=0.55:  559 matches | without byte-identical sig:    0 | refs>0:  0
min=0.40: 2325 matches | without byte-identical sig: 1764 | refs>0:  0
min=0.30: 3363 matches | without byte-identical sig: 2802 | refs>0:  0
distinct scores: [0.70, 0.75]          theoretical max 1.00
```

Three independent defects:

1. The "masked" signature masked nothing but branch displacements —
   `fixed = min(fixed, len(insn.bytes))` where `fixed` already *was*
   `len(insn.bytes)`. Absolute addresses stayed literal.
2. The 3-gram set came from the same 64-byte window as the signature, so the
   two were perfectly collinear: `sig_eq == 1` implied `ngram == 1` in
   **559 of 559** matches.
3. The reference signal compared **RVAs across builds**. The same global sits
   at a different RVA in each build, so the intersection was empty by
   construction — 82% of functions carried reference data and the signal
   contributed to **zero** matches at any threshold.

`remcp` compares *what* a function references, not *where*:

- referenced **string contents**
- referenced **import names** (`kernel32!CreateFileW`)
- **non-address constants** — magic numbers, masks, seeds
- mnemonic 5-grams over the whole function, a deliberately different window
  from the signature so the two can disagree
- structural shape; masked signature contributes only 0.05

Signals with no evidence on either side **abstain** and the weights
renormalize, instead of scoring 0.0 and capping every achievable score.

**Verified working across architectures.** Matching the 32-bit and 64-bit
builds of the same program — where byte signatures *cannot* match:

```
19 matches, all with >=2 independent agreeing signals
0 relying on a byte-identical signature
18 distinct scores (predecessor: 2)
0 ambiguous
```

### 7. Where a claim can be checked, check it

The predecessor's `re_save_symbol` documented a six-tier policy and
implemented one rule. Its 0.80 gate tested a predicate identical to its 0.60
gate and could never fire independently. Unenforced: per-class caps (five
stored entries sat at 0.60 under a class capped at 0.40), the
two-independent-classes rule, the provenance vocabulary
(`structural-analysis` — not a policy term — was the most common class in the
database), and evidence contents, which were never inspected and could be
empty. A caller wanting 0.95 typed `dynamic_trace` and got it.

`remcp/kb.py` splits provenance in two:

**Verifiable — checked against the binary at write time; a false claim is rejected**

| Class | Cap | Checked by |
|---|---|---|
| `string_xref` | 0.40 | the string exists *and* is referenced from inside this function |
| `import_xref` | 0.40 | a call or reference to that named import lies in this function |
| `constant_xref` | 0.40 | the constant is in the function's fingerprint |
| `callgraph_position` | 0.40 | the claimed call edge exists |
| `cross_build_match` | 0.60 | a real match result with score ≥ 0.55 and ≥ 2 agreeing signals |
| `symbol_table` | 0.95 | the image's own symbol table names this address |
| `export_table` | 0.95 | the export table names this address |

**Asserted — cannot be checked from static bytes; require a named artifact and are stored as claims**

`structural_guess` (0.20), `community_source` (0.60), `dynamic_trace` (0.80),
`experimental_manipulation` (0.95), `authoritative_source` (1.00).

Also enforced: a closed vocabulary, per-class caps, ≥ 2 independent classes
above 0.40, RVA-first storage with the VA always derived, build ids bound to
a SHA-256, atomic writes with a backup, and **prior evidence preserved as
history** rather than overwritten.

Every stored record says which classes were verified and which were trusted.
That boundary is stated rather than papered over — a debugger trace is not
checkable here, and the record admits it.

## Deep algorithm recovery

Two capabilities, aimed at the question a disassembly listing cannot answer:
*what is this code actually doing?*

### JVM decompilation

Bytecode is typed, addresses locals by index, keeps method and field
references symbolic, and carries an explicit exception table. All the
information a native compiler destroys is still present, so real
decompilation is achievable rather than approximated.

`tests/fixtures/Algo.java` is compiled and checked in beside its `.class`, so
the decompiler is tested against **known source** rather than plausibility.
Given this input:

```java
public int sumEven(int[] xs) {
    int total = 0;
    for (int i = 0; i < xs.length; i++) {
        if (xs[i] % 2 == 0) { total += xs[i]; }
    }
    return total;
}
```

`re_jvm_decompile` recovers:

```java
public int sumEven(int[] xs) {
    int total = 0;
    int i = 0;
    while (i < xs.length) {
        if (xs[i] % 2 == 0) {
            total += xs[i];
        }
        i++;
    }
    return total;
}
```

Parameter and local names come from the `LocalVariableTable`; types are
recovered from descriptors; `for` appears as the `while` javac actually
emitted. Also recovered: `switch` with case labels, `try`/`catch` with its
handler body, `this.counter++`, string concatenation folded back from both
the `StringBuilder` chain (Java 8) and `invokedynamic`
`makeConcatWithConstants` (Java 9+), and ternaries recovered from the
diamond that materialises a boolean as a value.

Measured on a real 1,767-class jar: **2,241 methods decompiled in 0.3 s,
zero exceptions, 89% fully structured.**

**The `structured` flag is the point.** Irreducible control flow, `jsr`/`ret`
subroutines and obfuscated jump tables produce `structured: false` and a
best-effort listing. A decompiler that always emits clean-looking output is
wrong some of the time and never says which time.

Two correctness bugs found by these tests and fixed:

- `h = h * 31 + c` was folded to `h *= 31 + c`, which means `h * (31 + c)`.
  Compound assignment now folds only when the right-hand side is a single
  operand (`_has_toplevel_operator`).
- `catch` handler bodies were dropped entirely: `safeDiv` decompiled to just
  its `try` body with the whole clause missing.

### Native algorithm identification

Crypto and hashing primitives are recognisable by the exact constants their
specifications pin. `re_algorithms` scans for 22 catalogued algorithms across
two evidence sources -- byte tables in data, and immediates recovered from
the code index for optimisers that materialise constants inline.

The catalog's value depends on not crying wolf, so three guards apply:

| Guard | Why |
|---|---|
| `MIN_SCANNABLE` (0x10000) | `0x1B` (AES Rcon) occurs thousands of times in any binary; it is not a marker |
| `min_distinct` | a single hit is a `lead`, never an `identification` |
| `discriminators` | MD5 and SHA-1 share four init words; an identification requires a marker unique to that algorithm |

Verified against `bcryptprimitives.dll` and `ntdll.dll`: SHA-1, SHA-224/256,
SHA-384/512, MD5, CRC-32 and CRC-32C identified with discriminating markers
and attributed to the functions referencing them. `secp256k1` matched one
32-bit word in ntdll and is correctly reported as a **lead**, not Bitcoin
code.

`re_function_cfg` adds the structural half: basic blocks, dominator-based
natural loops, cyclomatic complexity, exit points. A one-block self-loop was
being reported as four blocks -- the natural-loop walk seeded its worklist
with the header and escaped backwards through the header's external
predecessors. Fixed in both the native and JVM implementations.

## Tools

| Tool | Purpose |
|---|---|
| `re_identify` | Format, arch, sections, imports/exports, and whether code analysis is possible. Start here |
| `re_sniff` | Container type from magic bytes, without parsing |
| `re_translate` | Convert between file offset, RVA and VA through the section table |
| `re_strings` | Strings with correct VAs; regex filter; `referenced_only` |
| `re_disasm` | **Disassemble at an address** — the predecessor had no disassembler at all |
| `re_xrefs` | References to a VA or a string, from code operands **and** data pointers |
| `re_functions` | Discovered functions with the evidence source for each |
| `re_callgraph` | Function-attributed graph; `focus` for one neighbourhood |
| `re_fingerprint` | Layout-invariant fingerprint of one function |
| `re_build_fingerprints` | Whole-image fingerprint database |
| `re_match_builds` | Cross-build matching with corroboration required |
| `re_kb_policy` | The policy, introspectable — caps, vocabulary, what is verified |
| `re_register_build` | Bind a build id to a SHA-256 |
| `re_save_symbol` | Record a symbol; verifiable provenance is verified |
| `re_lookup_symbol` | Query the knowledge base |
| `re_java` | JVM: .class/.jar inventory, packages, manifest, constant-pool strings with source entry |
| `re_dotnet` | .NET: CLR target, metadata streams, table row counts, #Strings identifiers, #US user strings |
| `re_read` | Bounded hex+ASCII dump of raw bytes at a file offset, RVA or VA |
| `re_jvm_methods` | Methods with signatures, complexity and loop counts |
| `re_jvm_disasm` | Bytecode listing with constant-pool references resolved |
| `re_jvm_decompile` | **Bytecode back to readable Java** |
| `re_jvm_cfg` | Per-method blocks, loops, exception table |
| `re_jvm_linkage` | Statically resolve every symbolic reference a plugin makes against a host classpath; report what would fail at first call |
| `re_jvm_health` | Plugin code that loads but does nothing: unimplemented abstract methods, overloads that match no supertype, class names in data that no longer resolve |
| `re_jvm_duplicates` | Classes defined in more than one jar on a shared classpath, where load order silently picks the winner |
| `re_algorithms` | **Identify crypto/hash/PRNG by constants**, attributed to functions |
| `re_function_cfg` | Native per-function blocks, loops, complexity |
| `re_cache` | Cache stats and clearing |

`re_disasm` matters more than it looks. The predecessor exposed no
disassembly and no decompilation — only a reader for a pre-populated cache —
so an agent following its documented workflow could never actually read
code.

`re_java` and `re_dotnet` exist because two field tests left the tool. A JVM
jar sniffed as "zip" and the analysis exited to hand-rolled constant-pool
mining; a .NET assembly identified fine but the CLI metadata walk was
reimplemented outside the engine. Both gaps are now first-class: class files
and CLI metadata are structured inventories, not VA spaces, so these modules
do not pretend to be Images — no fabricated addresses, constant-pool indices
reported as indices. `re_read` closes the third escape: reading the exact
bytes behind any reported address without dropping to a shell.

## Read-only by design

There is no patch, write, inject, or execute tool, and none is planned.
Runtime work belongs in a debugger a human is driving. The only writes are
to the knowledge base and the analysis cache.

Other eliminations: a 512 MB file-size ceiling
(`REMCP_MAX_FILE_BYTES`), a response-size clip that tells you to narrow the
query instead of flooding the context (`REMCP_MAX_RESPONSE_CHARS`), and
bounded index growth so one huge image cannot produce an unbounded cache
entry.

## Nothing escapes a tool

Every handler is wrapped by `@tool`, which catches `BaseException` and
returns a structured error.

The predecessor's `load_pe` raised `SystemExit` on a non-PE file.
`SystemExit` is a `BaseException`, so it slipped past FastMCP's
`except Exception` and killed the stdio loop. Wire-tested against the live
predecessor:

```
re_form_type('98')       -> {"ordinal": 98, "record": "ECZN"}   ok
re_inspect('README.md')  -> <TIMEOUT: no response>              dead
re_form_type('98')       -> <STDOUT CLOSED>                     dead
stderr: BaseExceptionGroup: unhandled errors in a TaskGroup
```

Reachable from six tools with any `.esp`, `.txt` or `.json` path — the most
likely mistake an agent makes, costing the whole session's tooling.

`tests/wire_test.py` drives seven failure paths — non-binary file, directory,
missing file, unmapped address, unparseable address, invalid regex, missing
database — and probes the server after **each** one. All pass.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `REMCP_CACHE_DIR` | `%LOCALAPPDATA%/remcp` (Windows), `$XDG_CACHE_HOME/remcp` or `~/.cache/remcp` | Analysis cache |
| `REMCP_KB` | `./re_kb/symbols.json` | Knowledge base |
| `REMCP_MAX_FILE_BYTES` | 536870912 | File-size ceiling |
| `REMCP_MAX_RESPONSE_CHARS` | 120000 | Response clip |

The knowledge base ships empty and is created on first write — no analyzed-target
data comes with the repo.

No hardcoded absolute paths. The predecessor had five, plus a game-directory
fallback, and its `.mcp.json` pointed at a different checkout than the one it
shipped in.

## Register with an MCP client

```json
{
  "mcpServers": {
    "remcp": {
      "command": "python",
      "args": ["/path/to/mnehmos.reverse-engineer.mcp/server.py"]
    }
  }
}
```

Point `command` at an interpreter that actually has the requirements
installed — a bare `python` may resolve to an environment without capstone
or pyelftools, which kills the server at import time.

## Layout

```
server.py              28 MCP tools; every one exception-wrapped
remcp/
  errors.py            typed errors; never SystemExit from a library path
  evidence.py          envelopes and in-band warnings
  image.py             the address model -- sections, three spaces, one conversion path
  formats/
    __init__.py        magic-byte detection, target validation, dispatch
    pe.py elf.py macho.py raw.py
    classfile.py       JVM .class/.jar inventory behind re_java
    dotnet.py          CLI metadata inventory behind re_dotnet
  disasm.py            arch-derived decoder, resilient sweep, correct masking
  codeindex.py         one sweep -> xrefs, calls, jumps, indirect sites, functions
  strings.py           extraction with correct VAs, both encodings
  xrefs.py             code-operand + data-pointer passes
  graph.py             function-attributed call graph
  fingerprint.py       layout-invariant features and matching
  cache.py             content-addressed, gzip, atomic, corruption-tolerant
  kb.py                policy with binary-backed verification
  jvm/
    bytecode.py        full opcode table, wide/switch/indy decoding
    classfile.py       constant values and attribute bodies (Code, LVT, exceptions)
    cfg.py             blocks, dominators, natural loops, post-dominators
    decompile.py       stack reconstruction + control-flow structuring
    linkage.py         static resolution of a plugin's references to its host
    checks.py          health checks over linked classes
  algo/
    constants.py       22-algorithm marker catalog with discriminator rule
    nativecfg.py       native blocks, loops, complexity
tests/
  test_engine.py       37 tests, one per defect class
  test_policy.py       22 tests pinning every documented policy rule
  test_formats_meta.py 13 tests for container detection
  test_jvm.py          32 tests against compiled-from-source ground truth
  test_linkage.py      20 tests for host/plugin linkage and health
  test_algo.py         15 tests, mostly false-positive guards
  fixtures/Algo.java   the ground truth, checked in beside its .class
  wire_test.py         end-to-end MCP over stdio
```

## Known limits

Stated rather than discovered later:

- **Indirect calls are recorded as sites, not resolved to targets.** Virtual
  dispatch is visible as "dispatch happens here", which is strictly better
  than the predecessor's silence but is not a resolved edge. Devirtualization
  would need vtable recovery.
- **Function boundaries are estimates** when an image has no symbols. The
  end is the next known start, refined by a terminator scan. Reported as
  `estimated_extent`, with a warning when there is no symbol evidence.
- **Mach-O is parsed but untested against a real binary** on this machine.
  The address translation is covered by a synthetic fixture; treat real-world
  Mach-O as unproven until exercised.
- **No *native* decompiler.** JVM bytecode decompiles to Java; x86/ARM
  gets disassembly, control flow and algorithm identification, not
  pseudocode. Lifting native code to an IR is the next step, and a Ghidra
  headless bridge remains the pragmatic alternative.
- **JVM structuring is 89% on real jars.** The remaining 11% is reported as
  `structured: false`, not disguised.
- **The algorithm catalog is 22 entries.** An algorithm outside it, or a
  bitsliced implementation with no constant tables, produces nothing. Absence
  of a hit is not evidence of absence.
- **Linear sweep decodes data as instructions** in code sections that
  interleave data, producing some spurious instructions. Recursive-descent
  from known entry points would be more precise and is not implemented.
- **`data_refs` finds pointer-width matches**, which can coincide with
  unrelated data. Each is reported with its section and alignment so the
  caller can judge.

## License

[MIT](LICENSE) © 2026 Mnehmos.
