"""Behavioural checks: code that loads cleanly and still does nothing.

Linkage proves a plugin can be *loaded*. These checks target the failures
that survive loading and only show up as absent behaviour:

* An inherited abstract method left unimplemented throws `AbstractMethodError`
  at the first call, not at load.
* A method that looks like an override but matches no supertype signature is
  a new overload the host will never call. This is the ordinary consequence
  of a host API changing a parameter type: the plugin still compiles against
  the old headers, still loads, and silently stops participating.
* A class named in a data file is loaded reflectively by name. A stale name
  there is invisible to the compiler; the plugin loads and that one feature
  is dead.

All three are statically decidable, and all three are invisible to a
"does it start up?" test.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .linkage import (
    ClassInfo,
    collect_requirements,
    index_classpath,
    is_jdk,
)


def all_supertypes(universe: dict[str, ClassInfo], name: str) -> list[ClassInfo]:
    """Every resolvable supertype of `name`, nearest first."""
    out: list[ClassInfo] = []
    seen: set[str] = set()
    queue = [name]
    while queue:
        cur = queue.pop(0)
        if cur in seen or is_jdk(cur):
            continue
        seen.add(cur)
        info = universe.get(cur)
        if info is None:
            continue
        if cur != name:
            out.append(info)
        if info.superclass:
            queue.append(info.superclass)
        queue.extend(info.interfaces)
    return out


def _universe(subject, classpath) -> tuple[dict[str, ClassInfo], dict[str, ClassInfo]]:
    own, _ = collect_requirements(subject)
    provided, _ = index_classpath(classpath)
    universe = dict(provided)
    universe.update(own)
    return own, universe


def _arity(descriptor: str) -> int:
    """Number of parameters in a method descriptor."""
    if "(" not in descriptor or ")" not in descriptor:
        return -1
    inner = descriptor[descriptor.index("(") + 1:descriptor.index(")")]
    n = 0
    i = 0
    while i < len(inner):
        while i < len(inner) and inner[i] == "[":
            i += 1
        if i >= len(inner):
            break
        if inner[i] == "L":
            end = inner.find(";", i)
            if end == -1:
                break
            i = end + 1
        else:
            i += 1
        n += 1
    return n


def check_abstract_implementations(subject, classpath: Iterable = ()) -> list[dict]:
    """Concrete classes leaving an inherited abstract method unimplemented."""
    own, universe = _universe(subject, classpath)
    findings = []
    for name, info in sorted(own.items()):
        if info.is_abstract:
            continue
        supers = all_supertypes(universe, name)
        if not supers:
            continue
        # An unresolvable supertype means the picture is incomplete, and an
        # incomplete picture must not produce a confident negative.
        unresolved = [p for p in ([info.superclass] + info.interfaces)
                      if p and not is_jdk(p) and p not in universe]
        if unresolved:
            continue

        required: set[tuple[str, str]] = set()
        implemented = set(info.methods)
        for sup in supers:
            required |= sup.abstract_methods
            implemented |= (sup.methods - sup.abstract_methods)

        missing = sorted(required - implemented)
        if missing:
            findings.append({
                "class": name,
                "unimplemented": [f"{n}{d}" for n, d in missing[:10]],
                "count": len(missing),
                "consequence": "AbstractMethodError at the first call",
            })
    return findings


def check_overrides(subject, classpath: Iterable = ()) -> list[dict]:
    """Methods that look like overrides but match no supertype signature."""
    own, universe = _universe(subject, classpath)
    findings = []
    for name, info in sorted(own.items()):
        supers = all_supertypes(universe, name)
        if not supers:
            continue
        super_sigs: set[tuple[str, str]] = set()
        by_name: dict[str, set[str]] = {}
        for sup in supers:
            for mn, md in sup.methods:
                super_sigs.add((mn, md))
                by_name.setdefault(mn, set()).add(md)

        for mn, md in sorted(info.methods):
            if mn in ("<init>", "<clinit>"):
                continue
            if (mn, md) in super_sigs:
                continue                       # a genuine override
            others = by_name.get(mn)
            if not others:
                continue                       # a genuinely new method
            same_arity = sorted(o for o in others if _arity(o) == _arity(md))
            if same_arity:
                findings.append({
                    "class": name,
                    "method": f"{mn}{md}",
                    "supertype_signatures": same_arity[:4],
                    "risk": "same name and parameter count as a supertype method but a "
                            "different signature: this is an overload, not an override, "
                            "so the engine will never call it",
                })
    return findings


# A fully-qualified class name: one or more lowercase package segments then a
# capitalised type name. Loose on purpose -- precision comes from the
# package-ownership rule below, not from the pattern.
CLASS_REF = re.compile(r"\b((?:[a-z][A-Za-z0-9_]*\.)+[A-Z][A-Za-z0-9_$]*)\b")


def check_data_references(mod_dir, subject_jars: Iterable,
                          classpath: Iterable = ()) -> dict:
    """Class names appearing in data files must resolve."""
    own: dict[str, ClassInfo] = {}
    for j in subject_jars:
        o, _ = collect_requirements(j)
        own.update(o)
    provided, _ = index_classpath(classpath)
    universe = dict(provided)
    universe.update(own)

    root = Path(mod_dir)
    referenced: dict[str, list[str]] = {}
    patterns = ("*.csv", "*.json", "*.faction", "*.ship", "*.variant")

    def is_game_data(p: Path) -> bool:
        """Only files the engine actually reads.

        Scanning the whole mod directory swept up build and tooling
        metadata -- a `.repowise/knowledge-graph.json` naming JUnit classes
        produced three "unresolvable script" findings for files the game
        never opens. The engine loads from `data/`, plus a handful of
        recognised files at the mod root.
        """
        rel = p.relative_to(root)
        if any(part.startswith(".") for part in rel.parts):
            return False
        if rel.parts[0] in ("out", "test-out", "build", "target", "lib", "jars", "src"):
            return False
        return rel.parts[0] == "data" or len(rel.parts) == 1

    for pat in patterns:
        for f in root.rglob(pat):
            try:
                if not is_game_data(f):
                    continue
                text = f.read_text(encoding="utf-8", errors="ignore")
            except (OSError, ValueError):
                continue
            for m in CLASS_REF.finditer(text):
                cls = m.group(1)
                if is_jdk(cls):
                    continue
                referenced.setdefault(cls, []).append(str(f.relative_to(root)))

    # Packages the plugin itself defines. A renamed or deleted script leaves
    # its package behind, so an unresolved name inside one of the plugin's
    # own packages is a defect; an unresolved name outside them is more
    # likely another mod's class, a typo, or ordinary prose that happens to
    # look like an identifier -- reported as a lead, not a finding.
    own_packages = {c.rsplit(".", 1)[0] for c in own if "." in c}

    missing: list[dict] = []
    external: list[dict] = []
    for cls, files in sorted(referenced.items()):
        if cls in universe:
            continue
        pkg = cls.rsplit(".", 1)[0]
        row = {"class": cls, "named_in": sorted(set(files))[:4]}
        if pkg in own_packages:
            row["consequence"] = ("the engine cannot load this script reflectively; "
                                  "the feature it backs will silently not work")
            missing.append(row)
        else:
            row["note"] = ("not defined by this plugin and not on the supplied "
                           "classpath: another mod's class, a typo, or not a class "
                           "reference at all")
            external.append(row)

    return {
        "referenced": len(referenced),
        "resolved": len(referenced) - len(missing) - len(external),
        "missing": missing,
        "unresolved_external": external,
    }
