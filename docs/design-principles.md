# The seven design principles

Each one exists because its absence was **measured** as a defect in the
predecessor this engine replaces. The measurements are kept here — with the
regression tests that pin them — so the reasons survive the people who
remember them.

## 1. An address is meaningless without its space

File offsets, RVAs and VAs are three different spaces. `remcp/image.py` owns
every conversion; they go through the section table and return `None` for
addresses that do not map.

The predecessor computed string addresses as `image_base + file_offset`.
Measured against a real PE, **1.17% of the resulting addresses were correct**
— and the coincidental overlap was the only reason any were. The matching
signal built on them was dead in every shipped database.

`test_naive_base_plus_offset_is_wrong` asserts the shortcut is *not*
equivalent, so nobody reintroduces it thinking it is harmless.

## 2. Decode with the declared architecture, or refuse

`remcp/disasm.py` derives the capstone mode from the image header. An
unsupported combination raises `UnsupportedError` listing what is supported.

The predecessor hardcoded 32-bit x86 in three places. Fed a 64-bit PE it
returned **1,187 fabricated call edges and zero warnings**, one call after
its own inspector had correctly printed `AMD64 (64-bit x64)`.

## 3. Warnings travel with the answer

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

## 4. Remove the foot-gun rather than documenting it

High-entropy executable sections are **not swept by default**. On a real
16.5 MB CEG-encrypted image, sweeping `.text` produced 5,080,489
"instructions" in 394 seconds — all of it noise.

```
predecessor:  355.4 s per call, every call, 21,339 fabricated edges, no warning
remcp:        0.00 s, an in-band warning naming the encrypted sections
```

`include_packed=true` is the deliberate override, and it attaches an
`unreliable` warning of its own.

## 5. Disassemble once, answer many questions

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

## 6. A cross-build signal must not depend on the layout

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

## 7. Where a claim can be checked, check it

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
checkable here, and the record admits it (`re_kb_policy` prints the whole
policy at runtime).

## Defects the capability tests found and fixed

- **Operator precedence in folding:** `h = h * 31 + c` was folded to
  `h *= 31 + c`, which means `h * (31 + c)`. Compound assignment now folds
  only when the right-hand side is a single operand
  (`_has_toplevel_operator`).
- **Dropped catch handlers:** `catch` bodies were omitted entirely;
  `safeDiv` decompiled to just its `try` body with the whole clause missing.
- **Self-loop over-counting:** a one-block self-loop was reported as four
  blocks — the natural-loop walk seeded its worklist with the header and
  escaped backwards through the header's external predecessors. Fixed in
  both the native and JVM implementations.
- **Algorithm false-positive guards:** `MIN_SCANNABLE` (0x10000) keeps
  ubiquitous bytes like `0x1B` (AES Rcon) from counting as markers;
  `min_distinct` makes a single hit a `lead`, never an identification; and
  `discriminators` require a marker unique to the algorithm, because MD5 and
  SHA-1 share four init words. Verified against `bcryptprimitives.dll` and
  `ntdll.dll`: SHA-1, SHA-224/256, SHA-384/512, MD5, CRC-32 and CRC-32C
  identified with discriminating markers; `secp256k1` matched one 32-bit
  word in ntdll and is correctly reported as a lead, not Bitcoin code.

## Nothing escapes a tool

Every handler is wrapped by `@tool`, which catches `BaseException` and
returns a structured error. The predecessor's `load_pe` raised `SystemExit`
on a non-PE file; `SystemExit` is a `BaseException`, so it slipped past
FastMCP's `except Exception` and killed the stdio loop. Wire-tested against
the live predecessor:

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
database — and probes the server after **each** one.

## The JVM decompiler's contract

Bytecode is typed, addresses locals by index, keeps method and field
references symbolic, and carries an explicit exception table — all the
information a native compiler destroys. `tests/fixtures/Algo.java` is
compiled and checked in beside its `.class`, so the decompiler is tested
against **known source** rather than plausibility. Measured on a real
1,767-class jar: **2,241 methods decompiled in 0.3 s, zero exceptions, 89%
fully structured.**

**The `structured` flag is the point.** Irreducible control flow, `jsr`/`ret`
subroutines and obfuscated jump tables produce `structured: false` and a
best-effort listing. A decompiler that always emits clean-looking output is
wrong some of the time and never says which time.
