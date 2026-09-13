# remcp — reverse-engineer a binary, read-only

**Understand a binary you are authorized to inspect — statically, read-only,
with evidence you can check.**

remcp is an MCP server that analyzes the programs you hand it: containers,
architectures, symbols and imports; strings and cross-references; functions,
call graphs and control flow; crypto and hashing primitives by their
constants; and for managed code, real decompilation — JVM bytecode back to
readable Java, plugin-to-host linkage resolved before anything runs. Every
answer arrives as an evidence envelope with in-band warnings, and every
symbol it stores carries provenance that is **verified against the binary
itself** where verification is possible.

There is no patch, write, inject or execute tool, and none is planned:
runtime work belongs in a debugger a human is driving.

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
| Managed | JVM `.class`/`.jar` (inventory, bytecode, decompilation), .NET CLI metadata |
| Architectures | x86-16/32/64, ARM, AArch64, MIPS 32/64, PowerPC 32/64, SPARC, RISC-V — 19 arch/bits/endian combinations |
| Bitness | Derived from the header. A mismatch is refused, never guessed |
| Symbols | PE imports/exports, ELF symtab + dynsym + DT_NEEDED, Mach-O symtab + dylibs |
| Fat Mach-O | Detected and refused with instructions, not silently sliced |

Anything unsupported raises a typed error naming what was detected and what
to do instead. Nothing is analyzed on a guess.

## What you can ask it

- "What is this file, what architecture, and can you analyze its code?"
- "Show me the strings and who references this one."
- "Disassemble the function at this address and draw its control flow."
- "What does this jar actually do? Decompile the class and tell me which
  methods are still obfuscated."
- "Will this plugin still link against the host's new version — what breaks
  at first call?"
- "Are these two builds of the same program still the same code underneath?"
- "Which functions here are crypto? Don't guess from names — use constants."

## What it actually recovers

**JVM decompilation, tested against known source.** `tests/fixtures/Algo.java`
is compiled and checked in beside its `.class`. From real bytecode:

```java
public int sumEven(int[] xs) {
    int total = 0;
    while (i < xs.length) {
        if (xs[i] % 2 == 0) { total += xs[i]; }
        i++;
    }
    return total;
}
```

Parameter and local names come from the `LocalVariableTable`, types from
descriptors, and `for` appears as the `while` javac actually emitted. Also
recovered: `switch` with case labels, `try`/`catch` with handler bodies,
string concatenation folded back from both the `StringBuilder` chain and
`invokedynamic` `makeConcatWithConstants`. Measured on a real 1,767-class
jar: **2,241 methods decompiled in 0.3 s, 89% fully structured** — the rest
reported as `structured: false`, never disguised as clean output.

**Algorithm identification by constants.** 22 catalogued crypto/hash/PRNG
algorithms, scanned as byte tables and as immediates materialised inline,
with false-positive guards (MD5 and SHA-1 share init words, so an
identification requires a marker unique to the algorithm). Verified against
`bcryptprimitives.dll` and `ntdll.dll`: SHA-1, SHA-256/384/512, MD5, CRC-32
and CRC-32C identified and attributed to the functions that reference them;
a coincidental 32-bit match in ntdll is correctly reported as a *lead*.

**Cross-build matching that survives recompilation.** Functions are compared
by *what* they reference — string contents, import names, non-address
constants, mnemonic 5-grams — never by where the bytes sit. Matching a
32-bit build against a 64-bit build of the same program: 19 matches, every
one corroborated by at least two independent agreeing signals, none relying
on a byte-identical signature, none ambiguous.

## The tools

28 tools, grouped. Ask in plain language; your agent calls these.

**Identify and inspect**

| Tool | Purpose |
|---|---|
| `re_identify` | Format, arch, sections, imports/exports, and whether code analysis is possible. Start here |
| `re_sniff` | Container type from magic bytes, without parsing |
| `re_translate` | Convert between file offset, RVA and VA through the section table |
| `re_read` | Bounded hex+ASCII dump at a file offset, RVA or VA |

**Native code analysis**

| Tool | Purpose |
|---|---|
| `re_disasm` | Disassemble at an address |
| `re_functions` | Discovered functions, each with its evidence source |
| `re_callgraph` | Function-attributed graph; `focus` for one neighbourhood |
| `re_function_cfg` | Blocks, dominator-based natural loops, complexity, exits |
| `re_xrefs` | References to an address or string — from code operands *and* data pointers |
| `re_strings` | Strings with correct VAs; regex filter; `referenced_only` |
| `re_algorithms` | Crypto/hash/PRNG identified by constants, attributed to functions |

**Managed code**

| Tool | Purpose |
|---|---|
| `re_java` | JVM inventory: classes, packages, manifest, constant-pool strings with source entry |
| `re_jvm_methods` | Methods with signatures, complexity and loop counts |
| `re_jvm_disasm` | Bytecode with constant-pool references resolved |
| `re_jvm_decompile` | Bytecode back to readable Java |
| `re_jvm_cfg` | Per-method blocks, loops, exception table |
| `re_jvm_linkage` | Resolve every symbolic reference a plugin makes against a host classpath; report what fails at first call |
| `re_jvm_health` | Plugin code that loads but does nothing: unimplemented abstract methods, overloads matching no supertype, class names in data that no longer resolve |
| `re_jvm_duplicates` | Classes defined in more than one jar on a shared classpath, where load order silently picks the winner |
| `re_dotnet` | .NET: CLR target, metadata streams, table row counts, #Strings and #US heaps |

**Knowledge base and evidence**

| Tool | Purpose |
|---|---|
| `re_kb_policy` | The policy, introspectable: caps, vocabulary, what gets verified |
| `re_register_build` | Bind a build id to a SHA-256 |
| `re_save_symbol` | Record a symbol; verifiable provenance is verified against the binary, and a false claim is rejected |
| `re_lookup_symbol` | Query the knowledge base |
| `re_cache` | Cache stats and clearing |

**Cross-build matching**

| Tool | Purpose |
|---|---|
| `re_fingerprint` | Layout-invariant fingerprint of one function |
| `re_build_fingerprints` | Whole-image fingerprint database |
| `re_match_builds` | Cross-build matching with corroboration required |

## Evidence you can check

Most analysis output is a claim. remcp stores claims with provenance, and
splits provenance into two kinds — **verified** and **asserted** — so the
boundary is visible instead of implied:

| Verified against the binary; a false claim is rejected | Cap |
|---|---|
| `string_xref` — the string exists *and* is referenced from inside this function | 0.40 |
| `import_xref` — a call/reference to that named import lies in this function | 0.40 |
| `constant_xref` — the constant is in the function's fingerprint | 0.40 |
| `callgraph_position` — the claimed call edge exists | 0.40 |
| `cross_build_match` — a real match, score ≥ 0.55 and ≥ 2 agreeing signals | 0.60 |
| `symbol_table` / `export_table` — the image's own tables name this address | 0.95 |

Asserted classes (a debugger trace, a community source, an authoritative
document) cannot be checked from static bytes; they require a named artifact
and are stored for what they are. A caller cannot type a class name and
receive confidence: per-class caps, a closed vocabulary, a
two-independent-classes rule above 0.40 and RVA-first storage are all
enforced, and prior evidence is preserved as history rather than
overwritten. `re_kb_policy` prints the entire policy at runtime.

## What it can and cannot do

Stated rather than discovered later:

- **Indirect calls are recorded as sites, not resolved to targets.**
  Virtual dispatch is visible as "dispatch happens here", not a resolved
  edge; devirtualization would need vtable recovery.
- **Function boundaries are estimates** when an image has no symbols,
  reported as `estimated_extent` with a warning.
- **Mach-O is parsed but unproven** against a real binary on this machine;
  the address translation is covered by a synthetic fixture.
- **No native decompiler.** JVM bytecode decompiles to Java; x86/ARM gets
  disassembly, control flow and algorithm identification, not pseudocode.
- **JVM structuring is 89% on real jars**; the rest is `structured: false`.
- **The algorithm catalog is 22 entries.** An algorithm outside it, or a
  bitsliced implementation with no constant tables, produces nothing.
  Absence of a hit is not evidence of absence.
- **Linear sweep decodes data as instructions** in sections that interleave
  code and data; recursive-descent from entry points is not implemented.
- **`data_refs` pointer-width matches can coincide** with unrelated data;
  each is reported with section and alignment so you can judge it.

## Measured, not promised

- **139 tests** (138 passing, 1 environment-dependent skip), including
  decompilation tested against compiled-from-source ground truth and
  false-positive guards for algorithm identification.
- **A wire test** that drives seven failure paths — non-binary file,
  directory, missing file, unmapped address, unparseable address, invalid
  regex, missing database — and probes the server for liveness after
  **each** one. Nothing escapes a tool: every handler is exception-wrapped
  so a bad argument cannot end the session.
- **Performance discipline:** disassembly is done once per image and cached
  by content hash (23.4 MB PE: 97.8 s cold, 2.7 s warm); high-entropy
  (packed/encrypted) sections are skipped with an in-band warning instead of
  producing millions of fabricated instructions.

The engineering record behind these claims — what was measured, what was
rejected, and which regression test pins each lesson — is in
[docs/design-principles.md](docs/design-principles.md).

## Install and register

Requires Python 3.10+. Analysis dependencies are pinned exactly (`pefile`,
`capstone`, `pyelftools`): pinning extractors and decoders is the same
discipline as pinning a compiler — results are only reproducible if the
tools are.

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

| Variable | Default | Purpose |
|---|---|---|
| `REMCP_CACHE_DIR` | `%LOCALAPPDATA%/remcp` (Windows), `$XDG_CACHE_HOME/remcp` or `~/.cache/remcp` | Analysis cache |
| `REMCP_KB` | `./re_kb/symbols.json` | Knowledge base |
| `REMCP_MAX_FILE_BYTES` | 536870912 | File-size ceiling |
| `REMCP_MAX_RESPONSE_CHARS` | 120000 | Response clip |

The knowledge base ships empty and is created on first write — no
analyzed-target data comes with the repo. The only writes remcp makes
anywhere are to that knowledge base and the analysis cache.

## For developers

```text
server.py              28 MCP tools; every one exception-wrapped
remcp/
  errors.py            typed errors; never SystemExit from a library path
  evidence.py          envelopes and in-band warnings
  image.py             the address model -- sections, three spaces, one conversion path
  formats/             magic-byte detection, PE/ELF/Mach-O/raw, JVM and .NET inventories
  disasm.py            arch-derived decoder, resilient sweep, correct masking
  codeindex.py         one sweep -> xrefs, calls, jumps, indirect sites, functions
  strings.py xrefs.py  extraction and references with correct address spaces
  graph.py             function-attributed call graph
  fingerprint.py       layout-invariant features and matching
  cache.py             content-addressed, gzip, atomic, corruption-tolerant
  kb.py                policy with binary-backed verification
  jvm/                 bytecode, classfile attributes, CFG, decompiler, linkage, health
  algo/                22-algorithm catalog with discriminator rule; native CFG
docs/
  design-principles.md the seven principles, each pinned by a regression test
tests/
  139 tests across engine, policy, formats, JVM, linkage, algorithms
  fixtures/Algo.java   ground truth, checked in beside its .class
  wire_test.py         end-to-end MCP over stdio, failure paths included
```

## License

[MIT](LICENSE) © 2026 Mnehmos.
