"""Static linkage verification for JVM plugins.

First principle: a reference the runtime cannot resolve is a crash with a
known address.

A compiled class names every external method it calls as a symbolic
`Methodref` -- owner class, name, descriptor -- resolved lazily at the moment
of first execution. If the host application changed since the plugin was
compiled, that resolution fails with `NoSuchMethodError` or
`NoClassDefFoundError` *at the call site*, potentially hours into a session
and only on the code path that reaches it.

That makes it a statically decidable question. Every required symbol is in
the constant pool; every provided symbol is in the host's jars. The
difference is the set of latent crashes.

This matters more, not less, when the host disables verification. Starsector
launches with `-noverify -XX:-BytecodeVerificationLocal
-XX:-BytecodeVerificationRemote`, so nothing checks linkage at load time --
the first symptom is a mid-game exception.

Resolution follows the JVM's own order: a method is looked up on the class,
then its superclasses, then its interfaces (for default methods); a field is
looked up on the class, then its interfaces, then its superclasses. A
supertype outside the supplied classpath stops the walk and the result is
reported as `unchecked` rather than as a failure, because an absent answer
is not a negative one.
"""
from __future__ import annotations

import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from ..errors import ReError
from . import classfile

# Packages assumed to come from the JRE. Their members are not checked: the
# risk being measured is drift in the *host application's* API, and the JDK
# is a separately versioned, far more stable surface.
JDK_PREFIXES = (
    "java.", "javax.", "jdk.", "sun.", "com.sun.", "org.w3c.", "org.xml.",
    "jakarta.",
)


def is_jdk(name: str) -> bool:
    return name.startswith(JDK_PREFIXES)


@dataclass
class ClassInfo:
    name: str
    superclass: str | None
    interfaces: list[str]
    methods: set[tuple[str, str]] = field(default_factory=set)
    fields: set[tuple[str, str]] = field(default_factory=set)
    abstract_methods: set[tuple[str, str]] = field(default_factory=set)
    access: list[str] = field(default_factory=list)
    source: str = ""

    @property
    def is_abstract(self) -> bool:
        return "abstract" in self.access or "interface" in self.access


@dataclass
class Requirement:
    kind: str            # "class" | "method" | "field"
    owner: str
    name: str
    descriptor: str
    from_class: str

    def key(self) -> tuple:
        return (self.kind, self.owner, self.name, self.descriptor)

    def to_dict(self) -> dict:
        d = {"kind": self.kind, "owner": self.owner, "referenced_by": self.from_class}
        if self.kind != "class":
            d["member"] = self.name
            d["descriptor"] = self.descriptor
        return d


def _is_abstract_method(member, cf) -> bool:
    """True only for methods with no implementation.

    Marking every interface method abstract is wrong for Java 8 and later:
    `default` methods carry a body and no ACC_ABSTRACT flag. That mistake
    produced 28 false "unimplemented method" findings against anonymous
    classes implementing Starsector's `InstallableItemEffect`, whose
    `getSpecialNotes` and `getSpecialNotesName` are defaults.

    ACC_ABSTRACT is authoritative; the absent Code attribute is a
    cross-check for it.
    """
    if "static" in member.access:
        return False
    return "abstract" in member.access and member.code is None


def _iter_class_entries(path: Path) -> Iterable[tuple[str, bytes]]:
    """Yield (entry name, bytes) for every class in a jar, dir, or class file."""
    if path.is_dir():
        for p in path.rglob("*.class"):
            yield str(p.relative_to(path)).replace("\\", "/"), p.read_bytes()
        return
    if path.suffix.lower() == ".class":
        yield path.name, path.read_bytes()
        return
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.endswith(".class"):
                    try:
                        yield n, z.read(n)
                    except (KeyError, zipfile.BadZipFile, RuntimeError):
                        continue
        return
    raise ReError(f"{path.name} is not a jar, directory, or class file")


def index_classpath(paths: Iterable[str | Path], *, limit: int | None = None
                    ) -> tuple[dict[str, ClassInfo], list[dict]]:
    """Build the provided-symbol index from a list of jars and directories."""
    provided: dict[str, ClassInfo] = {}
    sources: list[dict] = []

    for raw in paths:
        p = Path(raw)
        if not p.exists():
            sources.append({"path": str(p), "status": "missing", "classes": 0})
            continue
        n = 0
        bad = 0
        try:
            entries = list(_iter_class_entries(p))
        except ReError:
            # A stray non-jar on the classpath (a readme in a jars folder) is
            # not a reason to abandon the whole analysis.
            sources.append({"path": str(p), "status": "skipped: not a class source",
                            "classes": 0})
            continue
        for entry, data in entries:
            if limit is not None and n >= limit:
                break
            try:
                cf = classfile.parse(data)
            except Exception:
                bad += 1
                continue
            info = ClassInfo(
                name=cf.name,
                superclass=cf.superclass,
                interfaces=list(cf.interfaces),
                access=list(cf.access),
                source=p.name,
            )
            for m in cf.methods:
                info.methods.add((m.name, m.descriptor))
                if _is_abstract_method(m, cf):
                    info.abstract_methods.add((m.name, m.descriptor))
            for f in cf.fields:
                info.fields.add((f.name, f.descriptor))
            # First definition wins, matching classpath precedence order.
            provided.setdefault(cf.name, info)
            n += 1
        sources.append({"path": str(p), "status": "ok", "classes": n,
                        "unparsable": bad})
    return provided, sources


def collect_requirements(path: str | Path) -> tuple[dict[str, ClassInfo], list[Requirement]]:
    """Extract every external symbol the subject's classes reference."""
    p = Path(path)
    own: dict[str, ClassInfo] = {}
    reqs: list[Requirement] = []

    for _entry, data in _iter_class_entries(p):
        try:
            cf = classfile.parse(data)
        except Exception:
            continue
        info = ClassInfo(name=cf.name, superclass=cf.superclass,
                         interfaces=list(cf.interfaces), access=list(cf.access),
                         source=p.name)
        for m in cf.methods:
            info.methods.add((m.name, m.descriptor))
            if _is_abstract_method(m, cf):
                info.abstract_methods.add((m.name, m.descriptor))
        for f in cf.fields:
            info.fields.add((f.name, f.descriptor))
        own[cf.name] = info

        pool = cf.pool
        for idx, e in pool.entries.items():
            tag = e.get("tag")
            if tag == "Class":
                cls = pool.class_at(idx)
                if cls:
                    reqs.append(Requirement("class", cls, "", "", cf.name))
            elif tag in ("Methodref", "InterfaceMethodref"):
                r = pool.methodref(idx)
                if r:
                    reqs.append(Requirement("method", r[0], r[1], r[2], cf.name))
            elif tag == "Fieldref":
                r = pool.fieldref(idx)
                if r:
                    reqs.append(Requirement("field", r[0], r[1], r[2], cf.name))

        # A class must also be able to link its own supertypes.
        if cf.superclass:
            reqs.append(Requirement("class", cf.superclass, "", "", cf.name))
        for i in cf.interfaces:
            reqs.append(Requirement("class", i, "", "", cf.name))

    return own, reqs


def _lookup(universe: dict[str, ClassInfo], owner: str, member: tuple[str, str],
            kind: str) -> tuple[str, str | None]:
    """Resolve a member through the type hierarchy.

    Returns (status, defining class) where status is
    "found" | "missing" | "unchecked".
    """
    seen: set[str] = set()

    def walk(name: str) -> tuple[str, str | None]:
        if name in seen:
            return ("missing", None)
        seen.add(name)
        if is_jdk(name):
            # The JDK is assumed present and is not the drift risk here.
            return ("unchecked", name)
        info = universe.get(name)
        if info is None:
            return ("unchecked", name)

        table = info.methods if kind == "method" else info.fields
        if member in table:
            return ("found", name)

        # JVM order: methods walk superclasses then interfaces; fields walk
        # interfaces then superclasses.
        order = ([info.superclass] + info.interfaces if kind == "method"
                 else info.interfaces + [info.superclass])
        unchecked = False
        for parent in order:
            if not parent:
                continue
            status, where = walk(parent)
            if status == "found":
                return ("found", where)
            if status == "unchecked":
                unchecked = True
        return ("unchecked" if unchecked else "missing", None)

    return walk(owner)


def verify(subject: str | Path, classpath: Iterable[str | Path]) -> dict:
    """Check that every symbol the subject references can be resolved."""
    own, reqs = collect_requirements(subject)
    provided, sources = index_classpath(classpath)

    universe: dict[str, ClassInfo] = dict(provided)
    universe.update(own)   # the plugin's own classes are on its classpath too

    missing_classes: dict[str, Requirement] = {}
    missing_members: dict[tuple, Requirement] = {}
    unchecked_members = 0
    checked_members = 0
    jdk_refs = 0
    seen: set[tuple] = set()

    for r in reqs:
        k = r.key()
        if k in seen:
            continue
        seen.add(k)

        owner = r.owner
        if owner.startswith("["):          # array type: members come from Object
            continue
        if is_jdk(owner):
            jdk_refs += 1
            continue

        if r.kind == "class":
            if owner not in universe:
                missing_classes.setdefault(owner, r)
            continue

        if owner not in universe:
            missing_classes.setdefault(owner, r)
            continue

        status, _where = _lookup(universe, owner, (r.name, r.descriptor), r.kind)
        if status == "found":
            checked_members += 1
        elif status == "missing":
            missing_members.setdefault(k, r)
        else:
            unchecked_members += 1

    return {
        "subject": str(subject),
        "subject_classes": len(own),
        "classpath": sources,
        "provided_classes": len(provided),
        "distinct_references": len(seen),
        "jdk_references": jdk_refs,
        "resolved_members": checked_members,
        "unchecked_members": unchecked_members,
        "missing_classes": [r.to_dict() for r in missing_classes.values()],
        "missing_members": [r.to_dict() for r in missing_members.values()],
        "links_cleanly": not missing_classes and not missing_members,
    }


def find_duplicate_classes(paths: Iterable[str | Path]) -> list[dict]:
    """Classes defined in more than one place.

    On a flat plugin classpath the winner is load-order dependent, so a
    duplicate is a real defect even when both copies are individually valid.
    """
    where: dict[str, list[str]] = {}
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            continue
        for _entry, data in _iter_class_entries(p):
            try:
                cf = classfile.parse(data)
            except Exception:
                continue
            where.setdefault(cf.name, []).append(p.name)
    return [
        {"class": name, "defined_in": sorted(set(src)), "copies": len(src)}
        for name, src in sorted(where.items())
        if len(set(src)) > 1
    ]


def check_entrypoints(subject: str | Path, entries: Iterable[str],
                      classpath: Iterable[str | Path] = ()) -> list[dict]:
    """Confirm named classes exist, are instantiable, and their supertypes link.

    A plugin declared in a manifest is loaded reflectively by name. A typo, a
    refactor, or an abstract class produces a load-time failure that no
    compiler catches.
    """
    own, _reqs = collect_requirements(subject)
    provided, _sources = index_classpath(classpath)
    universe = dict(provided)
    universe.update(own)

    out = []
    for name in entries:
        info = own.get(name)
        row: dict = {"declared": name, "present": info is not None}
        if info is None:
            near = [c for c in own if c.rsplit(".", 1)[-1] == name.rsplit(".", 1)[-1]]
            row["near_matches"] = near[:5]
            row["verdict"] = "missing -- the game will fail to load this plugin"
            out.append(row)
            continue

        row["access"] = info.access
        row["superclass"] = info.superclass
        row["interfaces"] = info.interfaces
        row["has_no_arg_constructor"] = ("<init>", "()V") in info.methods
        problems = []
        if "abstract" in info.access:
            problems.append("class is abstract and cannot be instantiated")
        if "interface" in info.access:
            problems.append("entry is an interface, not a class")
        if not row["has_no_arg_constructor"]:
            problems.append("no public no-argument constructor for reflective load")
        for parent in [info.superclass] + info.interfaces:
            if parent and not is_jdk(parent) and parent not in universe:
                problems.append(f"supertype {parent} is not on the classpath")
        row["problems"] = problems
        row["verdict"] = "ok" if not problems else "will not load cleanly"
        out.append(row)
    return out
