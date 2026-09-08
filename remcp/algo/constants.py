"""Algorithm identification by characteristic constants.

First principle: corroboration, not a single match.

Cryptographic and hashing primitives are recognisable because their
specifications pin exact magic numbers -- SHA-256's initial state is the
fractional parts of the square roots of the first eight primes, and nothing
else in a binary looks like that. This is how an analyst identifies a
routine without reading a line of its disassembly, and it works on stripped,
optimised, inlined code where a decompiler struggles.

The trap is that some constants are shared. `0x5A827999` is SHA-1's first
round constant *and* appears in RIPEMD-160 and MD4. A single hit is a lead;
several distinct hits from one family, referenced from one function, is an
identification. Every entry therefore declares how many distinct constants
must match before the result is reported as confident -- the same
corroboration rule the cross-build matcher and the symbol policy use.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class Algorithm:
    name: str
    family: str
    # (label, value, bit width)
    constants: tuple[tuple[str, int, int], ...]
    min_distinct: int
    note: str = ""
    strings: tuple[str, ...] = ()
    # Markers unique to this algorithm. MD5 and SHA-1 share their four init
    # words, so a binary containing only SHA-1 would otherwise "identify" as
    # MD5 too. An identification requires at least one of these.
    discriminators: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return len(self.constants) + len(self.strings)


A = Algorithm

CATALOG: tuple[Algorithm, ...] = (
    A("MD5", "hash", (
        ("init A", 0x67452301, 32), ("init B", 0xEFCDAB89, 32),
        ("init C", 0x98BADCFE, 32), ("init D", 0x10325476, 32),
        ("T[1]", 0xD76AA478, 32), ("T[2]", 0xE8C7B756, 32),
        ("T[13]", 0x6B901122, 32), ("T[64]", 0xEB86D391, 32),
    ), min_distinct=3,
      note="init words are shared with SHA-1 and MD4; a T-table hit disambiguates",
      discriminators=("T[1]", "T[2]", "T[13]", "T[64]")),

    A("SHA-1", "hash", (
        ("init A", 0x67452301, 32), ("init B", 0xEFCDAB89, 32),
        ("init C", 0x98BADCFE, 32), ("init D", 0x10325476, 32),
        ("init E", 0xC3D2E1F0, 32),
        ("K[0..19]", 0x5A827999, 32), ("K[20..39]", 0x6ED9EBA1, 32),
        ("K[40..59]", 0x8F1BBCDC, 32), ("K[60..79]", 0xCA62C1D6, 32),
    ), min_distinct=3,
      note="init E (0xC3D2E1F0) is the strongest single discriminator vs MD5",
      discriminators=("init E", "K[0..19]", "K[20..39]", "K[40..59]", "K[60..79]")),

    A("SHA-224/256", "hash", (
        ("H0", 0x6A09E667, 32), ("H1", 0xBB67AE85, 32), ("H2", 0x3C6EF372, 32),
        ("H3", 0xA54FF53A, 32), ("H4", 0x510E527F, 32), ("H5", 0x9B05688C, 32),
        ("H6", 0x1F83D9AB, 32), ("H7", 0x5BE0CD19, 32),
        ("K[0]", 0x428A2F98, 32), ("K[1]", 0x71374491, 32), ("K[63]", 0xC67178F2, 32),
        ("SHA-224 H0", 0xC1059ED8, 32),
    ), min_distinct=3,
      discriminators=("H4", "H5", "H6", "H7", "K[0]", "K[1]", "K[63]", "SHA-224 H0")),

    A("SHA-384/512", "hash", (
        ("H0", 0x6A09E667F3BCC908, 64), ("H1", 0xBB67AE8584CAA73B, 64),
        ("H2", 0x3C6EF372FE94F82B, 64), ("H3", 0xA54FF53A5F1D36F1, 64),
        ("K[0]", 0x428A2F98D728AE22, 64), ("K[1]", 0x7137449123EF65CD, 64),
    ), min_distinct=2),

    A("SHA-3 / Keccak", "hash", (
        ("RC[1]", 0x0000000000008082, 64), ("RC[2]", 0x800000000000808A, 64),
        ("RC[3]", 0x8000000080008000, 64), ("RC[7]", 0x8000000000008003, 64),
        ("RC[22]", 0x8000000080008081, 64),
    ), min_distinct=2),

    A("AES / Rijndael", "cipher", (
        ("S-box head", 0x7C6363C6, 32), ("Te0[0]", 0xC66363A5, 32),
        ("Td0[0]", 0x51F4A750, 32),
        ("inv S-box head", 0x0952EDD5, 32),
    ), min_distinct=2,
      note="table-driven implementations expose Te/Td; bitsliced ones may show none"),

    A("Blowfish", "cipher", (
        ("P[0]", 0x243F6A88, 32), ("P[1]", 0x85A308D3, 32),
        ("P[2]", 0x13198A2E, 32), ("P[3]", 0x03707344, 32),
    ), min_distinct=2, note="P-array is digits of pi; shared with some PRNGs"),

    A("TEA / XTEA / XXTEA", "cipher", (
        ("delta", 0x9E3779B9, 32), ("sum after 32 rounds", 0xC6EF3720, 32),
    ), min_distinct=1,
      note="0x9E3779B9 is the golden-ratio constant and also appears in xxHash "
           "and some hash mixers; treat a lone hit as a lead"),

    A("ChaCha / Salsa20", "cipher", (
        ("'expa'", 0x61707865, 32), ("'nd 3'", 0x3320646E, 32),
        ("'2-by'", 0x79622D32, 32), ("'te k'", 0x6B206574, 32),
    ), min_distinct=2, strings=("expand 32-byte k", "expand 16-byte k")),

    A("CRC-32 (IEEE)", "checksum", (
        ("reflected poly", 0xEDB88320, 32), ("normal poly", 0x04C11DB7, 32),
        ("table[1]", 0x77073096, 32), ("table[2]", 0xEE0E612C, 32),
    ), min_distinct=2),

    A("CRC-32C (Castagnoli)", "checksum", (
        ("reflected poly", 0x82F63B78, 32), ("normal poly", 0x1EDC6F41, 32),
        ("table[1]", 0xF26B8303, 32),
    ), min_distinct=2),

    A("MurmurHash3", "hash", (
        ("c1", 0xCC9E2D51, 32), ("c2", 0x1B873593, 32),
        ("fmix c1", 0x85EBCA6B, 32), ("fmix c2", 0xC2B2AE35, 32),
        ("n", 0xE6546B64, 32),
    ), min_distinct=2),

    A("xxHash", "hash", (
        ("PRIME32_1", 0x9E3779B1, 32), ("PRIME32_2", 0x85EBCA77, 32),
        ("PRIME32_3", 0xC2B2AE3D, 32), ("PRIME32_4", 0x27D4EB2F, 32),
        ("PRIME32_5", 0x165667B1, 32),
        ("PRIME64_1", 0x9E3779B185EBCA87, 64), ("PRIME64_2", 0xC2B2AE3D27D4EB4F, 64),
    ), min_distinct=2),

    A("FNV-1/1a", "hash", (
        ("offset basis 32", 0x811C9DC5, 32), ("prime 32", 0x01000193, 32),
        ("offset basis 64", 0xCBF29CE484222325, 64), ("prime 64", 0x00000100000001B3, 64),
    ), min_distinct=1),

    A("Mersenne Twister (MT19937)", "prng", (
        ("matrix A", 0x9908B0DF, 32), ("init multiplier", 0x6C078965, 32),
        ("temper b", 0x9D2C5680, 32), ("temper c", 0xEFC60000, 32),
    ), min_distinct=2),

    A("Java LCG (java.util.Random)", "prng", (
        ("multiplier", 0x5DEECE66D, 64),
    ), min_distinct=1),

    A("MSVC / glibc LCG", "prng", (
        ("MSVC multiplier", 0x343FD, 32), ("MSVC addend", 0x269EC3, 32),
        ("glibc multiplier", 0x41C64E6D, 32),
    ), min_distinct=2),

    A("Base64", "encoding", (), min_distinct=1,
      strings=("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
               "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")),

    A("zlib / DEFLATE", "compression", (), min_distinct=1,
      strings=("1.2.", "inflate 1.", "deflate 1.", " deflate ", "incorrect header check",
               "invalid distance too far back")),

    A("RC4", "cipher", (), min_distinct=2, strings=("RC4", "ARCFOUR", "arcfour"),
      note="RC4 has no distinctive constants -- its key schedule is a plain 0..255 "
           "permutation. Name strings alone are weak evidence, so a single hit "
           "stays a lead"),

    A("secp256k1 / Bitcoin", "asymmetric", (
        ("field prime low word", 0xFFFFFC2F, 32),
    ), min_distinct=2, strings=("secp256k1",),
      note="the field prime's low word alone is not enough; a lone hit in a large "
           "binary is coincidence"),

    A("Curve25519", "asymmetric", (
        ("a24", 0x0001DB41, 32),
    ), min_distinct=2, strings=("curve25519", "x25519", "ed25519")),
)


@dataclass
class Hit:
    algorithm: str
    family: str
    label: str
    value: int
    width: int
    kind: str                      # "constant" | "string"
    vas: list[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "value": (f"0x{self.value:0{self.width // 4}X}" if self.kind == "constant"
                      else self.label),
            "kind": self.kind,
            "locations": [f"0x{v:x}" for v in self.vas[:8]],
            "occurrences": len(self.vas),
        }


# Below this, a value is indistinguishable from ordinary integer data and
# byte-scanning for it produces noise, not evidence. `0x1B` (AES Rcon) occurs
# thousands of times in any binary; it is not a marker.
MIN_SCANNABLE = 0x10000


def _encodings(value: int, width: int, endian: str) -> list[bytes]:
    """Byte encodings a constant may appear as in a data table."""
    if abs(value) < MIN_SCANNABLE:
        return []
    nbytes = width // 8
    out = []
    try:
        out.append(value.to_bytes(nbytes, endian))
    except OverflowError:
        return []
    # A 32-bit constant is frequently materialised inside a 64-bit slot.
    if width == 32:
        try:
            out.append(value.to_bytes(8, endian))
        except OverflowError:
            pass
    return out


def scan_image(image, *, index: dict | None = None,
               max_locations: int = 32) -> list[dict]:
    """Find every catalogued algorithm whose constants appear in the image.

    Two evidence sources are combined: raw byte occurrences (which catch
    precomputed tables in `.rdata`) and immediate operands recovered from the
    code index (which catch constants materialised inline by an optimiser).
    """
    data = image.data
    endian = "little" if image.endian == "little" else "big"

    # Immediates seen in code, mapped to the sites that use them.
    imm_sites: dict[int, list[int]] = {}
    if index:
        for value_s, sites in index.get("immediates", {}).items():
            imm_sites.setdefault(int(value_s, 16), []).extend(
                int(a, 16) for a in sites
            )

    results: list[dict] = []
    for algo in CATALOG:
        hits: list[Hit] = []

        for label, value, width in algo.constants:
            vas: list[int] = []
            for enc in _encodings(value, width, endian):
                idx = data.find(enc)
                while idx != -1 and len(vas) < max_locations:
                    va = image.off_to_va(idx)
                    if va is not None:
                        vas.append(va)
                    idx = data.find(enc, idx + 1)
                if vas:
                    break
            if value in imm_sites:
                vas.extend(imm_sites[value][:max_locations])
            if vas:
                hits.append(Hit(algo.name, algo.family, label, value, width,
                                "constant", vas))

        for text in algo.strings:
            vas = []
            for enc in (text.encode("ascii", "ignore"), text.encode("utf-16-le")):
                if not enc:
                    continue
                idx = data.find(enc)
                while idx != -1 and len(vas) < max_locations:
                    va = image.off_to_va(idx)
                    if va is not None:
                        vas.append(va)
                    idx = data.find(enc, idx + 1)
                if vas:
                    break
            if vas:
                hits.append(Hit(algo.name, algo.family, text, 0, 0, "string", vas))

        if not hits:
            continue

        distinct = len(hits)
        found = {h.label for h in hits}
        has_discriminator = (
            not algo.discriminators or bool(found & set(algo.discriminators))
        )
        confident = distinct >= algo.min_distinct and has_discriminator
        results.append({
            "algorithm": algo.name,
            "family": algo.family,
            "distinct_markers": distinct,
            "markers_in_catalog": algo.total,
            "required_for_confidence": algo.min_distinct,
            "confident": confident,
            "verdict": "identified" if confident else "lead",
            "discriminating_markers": sorted(found & set(algo.discriminators))
            if algo.discriminators else [],
            "why_not_confident": (
                None if confident
                else ("only shared markers matched; no marker unique to this "
                      "algorithm was found"
                      if distinct >= algo.min_distinct and not has_discriminator
                      else f"{distinct} distinct marker(s) found, "
                           f"{algo.min_distinct} required")
            ),
            "note": algo.note,
            "evidence": [h.to_dict() for h in hits],
        })

    results.sort(key=lambda r: (not r["confident"], -r["distinct_markers"]))
    return results


def attribute_to_functions(image, index: dict, results: list[dict]) -> list[dict]:
    """Map each algorithm's constant locations to the functions that use them."""
    from ..graph import FunctionMap

    starts = [int(s, 16) for s in index.get("func_starts", [])]
    fmap = FunctionMap(starts)
    refs = index.get("refs_by_target", {})
    names = {s.va: s.name for s in image.symbols + image.exports}

    for r in results:
        users: dict[int, int] = {}
        for ev in r["evidence"]:
            for loc in ev["locations"]:
                va = int(loc, 16)
                for site, _kind in refs.get(f"0x{va:x}", []):
                    fn = fmap.containing(int(site, 16))
                    if fn is not None:
                        users[fn] = users.get(fn, 0) + 1
        r["used_by_functions"] = [
            {"va": f"0x{fn:x}", "name": names.get(fn), "marker_references": n}
            for fn, n in sorted(users.items(), key=lambda kv: -kv[1])[:12]
        ]
        if not users:
            r.setdefault("note", "")
            r["function_attribution"] = (
                "constants found in data but no code reference recorded; they may be "
                "reached through a pointer table or the referencing code may be packed"
            )
    return results
