"""Content-addressed analysis cache.

First principle: an expensive analysis over immutable bytes should run once.

The audited predecessor rebuilt an entire call graph on every `re_callgraph`
call -- 355 seconds for a 16.5 MB image -- and then, in `focus_va` mode,
threw all of it away except one function's neighbourhood. Nothing was cached,
so the cost was paid again on the next question about the same file.

The cache key is the file's SHA-256 plus the analysis name and its
parameters. Because the key is derived from content, a rebuilt or patched
binary gets a different key automatically; there is no staleness to manage
and no invalidation to forget.
"""
from __future__ import annotations

import gzip
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable



def cache_root() -> Path:
    env = os.environ.get("REMCP_CACHE_DIR")
    if env:
        return Path(env)
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_CACHE_HOME")
    if base:
        return Path(base) / "remcp" / "cache"
    return Path.home() / ".cache" / "remcp"


def _key(sha256: str, name: str, params: dict[str, Any]) -> str:
    canon = json.dumps(params, sort_keys=True, separators=(",", ":"))
    import hashlib

    ph = hashlib.sha256(canon.encode()).hexdigest()[:12]
    return f"{sha256[:16]}.{name}.{ph}.json.gz"


def get_or_build(
    sha256: str,
    name: str,
    params: dict[str, Any],
    build: Callable[[], Any],
    *,
    enabled: bool = True,
) -> tuple[Any, bool]:
    """Return (value, from_cache). Cache failures degrade to recompute."""
    if not enabled:
        return build(), False

    root = cache_root()
    path = root / _key(sha256, name, params)

    if path.exists():
        try:
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                return json.load(fh), True
        except Exception:
            # A corrupt cache entry must never be a hard failure; the answer
            # is recomputable by construction.
            try:
                path.unlink()
            except OSError:
                pass

    value = build()

    try:
        root.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(root), suffix=".tmp")
        os.close(fd)
        with gzip.open(tmp, "wt", encoding="utf-8") as fh:
            json.dump(value, fh, separators=(",", ":"))
        os.replace(tmp, path)
    except Exception:
        # Losing the write is acceptable; returning a wrong answer is not.
        pass

    return value, False


def clear(sha256: str | None = None) -> int:
    """Remove cache entries; all of them, or just one image's. Returns count."""
    root = cache_root()
    if not root.exists():
        return 0
    n = 0
    prefix = f"{sha256[:16]}." if sha256 else ""
    for p in root.glob(f"{prefix}*.json.gz"):
        try:
            p.unlink()
            n += 1
        except OSError:
            pass
    return n


def stats() -> dict:
    root = cache_root()
    if not root.exists():
        return {"dir": str(root), "entries": 0, "bytes": 0}
    entries = list(root.glob("*.json.gz"))
    return {
        "dir": str(root),
        "entries": len(entries),
        "bytes": sum(p.stat().st_size for p in entries),
    }
