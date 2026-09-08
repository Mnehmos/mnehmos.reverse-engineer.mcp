"""Function-level views over the code index.

A call graph whose nodes are call-site addresses is not a call graph; it is
an edge list. The predecessor returned `callers`/`callees` keyed by the
address of the calling *instruction*, so "who calls this function" produced
a list of unrelated instruction addresses with no way to tell which function
each belonged to. Attributing every site to its containing function is what
makes the graph navigable.
"""
from __future__ import annotations

import bisect
from collections import defaultdict
from typing import Any


class FunctionMap:
    """Maps any address to the function that contains it."""

    def __init__(self, starts: list[int]) -> None:
        self.starts = sorted(starts)

    def containing(self, va: int) -> int | None:
        if not self.starts:
            return None
        i = bisect.bisect_right(self.starts, va) - 1
        return self.starts[i] if i >= 0 else None

    def extent(self, va: int, *, hard_cap: int = 65536) -> tuple[int, int]:
        """(start, end) for the function containing `va`, end exclusive.

        The end is the next known start, which over-estimates when a function
        is followed by padding and under-estimates when a start was missed.
        Both are reported honestly rather than hidden.
        """
        start = self.containing(va)
        if start is None:
            return (va, va + hard_cap)
        i = bisect.bisect_right(self.starts, start)
        end = self.starts[i] if i < len(self.starts) else start + hard_cap
        return (start, min(end, start + hard_cap))


def build_function_graph(index: dict) -> dict[str, Any]:
    """Aggregate site-level edges into a function-to-function graph."""
    starts = [int(s, 16) for s in index.get("func_starts", [])]
    fmap = FunctionMap(starts)

    callees: dict[int, set[int]] = defaultdict(set)
    callers: dict[int, set[int]] = defaultdict(set)
    import_use: dict[int, set[str]] = defaultdict(set)
    indirect_by_fn: dict[int, int] = defaultdict(int)
    unattributed = 0

    for site_s, tgt_s in index.get("call_edges", []):
        site, tgt = int(site_s, 16), int(tgt_s, 16)
        fn = fmap.containing(site)
        if fn is None:
            unattributed += 1
            continue
        callees[fn].add(tgt)
        callers[tgt].add(fn)

    for site_s, _slot_s, qualified in index.get("import_calls", []):
        fn = fmap.containing(int(site_s, 16))
        if fn is not None:
            import_use[fn].add(qualified)

    for site_s, _mn, _op in index.get("indirect_calls", []):
        fn = fmap.containing(int(site_s, 16))
        if fn is not None:
            indirect_by_fn[fn] += 1

    return {
        "function_count": len(starts),
        "callees": {f"0x{k:x}": sorted(f"0x{v:x}" for v in vs) for k, vs in callees.items()},
        "callers": {f"0x{k:x}": sorted(f"0x{v:x}" for v in vs) for k, vs in callers.items()},
        "imports_used": {f"0x{k:x}": sorted(vs) for k, vs in import_use.items()},
        "indirect_calls": {f"0x{k:x}": n for k, n in indirect_by_fn.items()},
        "unattributed_call_sites": unattributed,
        "edge_count": sum(len(v) for v in callees.values()),
    }


def neighborhood(image, index: dict, va: int, *, depth: int = 1) -> dict[str, Any]:
    """One function's callers and callees, out to `depth` hops.

    This is the query the predecessor answered by building the entire graph
    and discarding all but one entry -- six minutes per call on a 16 MB
    image, recomputed every time.
    """
    g = build_function_graph(index)
    starts = [int(s, 16) for s in index.get("func_starts", [])]
    fmap = FunctionMap(starts)

    fn = fmap.containing(va)
    exact = fn == va
    if fn is None:
        return {
            "focus_va": f"0x{va:x}",
            "resolved": False,
            "reason": "no function start found at or before this address",
        }

    key = f"0x{fn:x}"
    names = {f"0x{s.va:x}": s.name for s in image.symbols + image.exports}

    def label(k: str) -> dict:
        return {"va": k, "name": names.get(k)}

    seen_up = {key}
    seen_down = {key}
    up_levels: list[list[str]] = []
    down_levels: list[list[str]] = []
    frontier_up, frontier_down = [key], [key]

    for _ in range(max(depth, 1)):
        nxt_up = sorted({c for f in frontier_up for c in g["callers"].get(f, []) if c not in seen_up})
        nxt_down = sorted({c for f in frontier_down for c in g["callees"].get(f, []) if c not in seen_down})
        if nxt_up:
            up_levels.append(nxt_up)
            seen_up.update(nxt_up)
        if nxt_down:
            down_levels.append(nxt_down)
            seen_down.update(nxt_down)
        frontier_up, frontier_down = nxt_up, nxt_down

    start, end = fmap.extent(fn)
    return {
        "focus_va": f"0x{va:x}",
        "resolved": True,
        "function": {
            "va": key,
            "name": names.get(key),
            "exact_start": exact,
            "estimated_extent": {"start": f"0x{start:x}", "end": f"0x{end:x}", "size": end - start},
        },
        "callers": [[label(k) for k in lvl] for lvl in up_levels],
        "callees": [[label(k) for k in lvl] for lvl in down_levels],
        "imports_used": g["imports_used"].get(key, []),
        "indirect_call_sites": g["indirect_calls"].get(key, 0),
        "direct_caller_count": len(g["callers"].get(key, [])),
        "direct_callee_count": len(g["callees"].get(key, [])),
    }
