"""Plugin linkage and behavioural checks.

`fixtures/api/` models the real scenario these checks exist for: a plugin
compiled against v1 of a host API, verified against v2. The `.java` sources
are checked in beside the classes.

  v1  Host { requiredName(); default optionalNote(); }
      Base implements Host { void tick(int); }
  v2  Host { requiredName(); default optionalNote(); addedLater(); }
      Base implements Host { void tick(float); }

  plugin  MyPlugin extends Base { tick(int); requiredName(); }

Against v1 the plugin is correct. Against v2 it has two defects that a
compiler never sees and a launch test would not surface: `addedLater()` is
unimplemented, and `tick(int)` is no longer an override.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from remcp.jvm import checks, linkage

FIX = Path(__file__).parent / "fixtures" / "api"
V1 = FIX / "v1"
V2 = FIX / "v2"
PLUGIN = FIX / "plugin"

needs = pytest.mark.skipif(not (V1.exists() and V2.exists() and PLUGIN.exists()),
                           reason="api fixtures missing")


# --------------------------------------------------------------------------
# The default-method false positive
# --------------------------------------------------------------------------


@needs
def test_default_interface_methods_are_not_abstract():
    """Marking every interface method abstract produced 28 false
    "unimplemented method" findings against real Starsector mods, whose
    anonymous classes rely on `InstallableItemEffect`'s default methods."""
    provided, _ = linkage.index_classpath([V1])
    host = provided["api.Host"]
    assert ("requiredName", "()Ljava/lang/String;") in host.abstract_methods
    assert ("optionalNote", "()Ljava/lang/String;") in host.methods
    assert ("optionalNote", "()Ljava/lang/String;") not in host.abstract_methods


@needs
def test_plugin_relying_on_a_default_method_is_not_flagged():
    assert checks.check_abstract_implementations(PLUGIN, [V1]) == []


# --------------------------------------------------------------------------
# Linkage
# --------------------------------------------------------------------------


@needs
def test_plugin_links_against_the_api_it_was_built_for():
    r = linkage.verify(PLUGIN, [V1])
    assert r["links_cleanly"] is True
    assert r["missing_classes"] == [] and r["missing_members"] == []


@needs
def test_missing_classpath_entry_is_reported_not_silently_ignored():
    r = linkage.verify(PLUGIN, [FIX / "does-not-exist"])
    assert any(s["status"] == "missing" for s in r["classpath"])
    assert r["links_cleanly"] is False


@needs
def test_absent_api_produces_unresolved_references():
    """Simulates the host jar being absent or renamed."""
    r = linkage.verify(PLUGIN, [])
    assert r["links_cleanly"] is False
    owners = {c["owner"] for c in r["missing_classes"]}
    assert "api.Base" in owners


@needs
def test_stray_non_jar_on_the_classpath_does_not_abort_the_run(tmp_path):
    junk = tmp_path / "readme.txt"
    junk.write_text("not a jar", encoding="utf-8")
    r = linkage.verify(PLUGIN, [V1, junk])
    assert r["links_cleanly"] is True
    assert any("skipped" in s["status"] for s in r["classpath"])


@needs
def test_member_resolution_walks_the_supertype_chain():
    """`requiredName` is declared on the interface and implemented on Base;
    resolving it requires walking both."""
    provided, _ = linkage.index_classpath([V1])
    status, where = linkage._lookup(
        provided, "api.Base", ("optionalNote", "()Ljava/lang/String;"), "method"
    )
    assert status == "found" and where == "api.Host"


def test_jdk_references_are_assumed_present_not_reported_missing():
    assert linkage.is_jdk("java.lang.String")
    assert linkage.is_jdk("javax.swing.JFrame")
    assert not linkage.is_jdk("com.fs.starfarer.api.BaseModPlugin")


# --------------------------------------------------------------------------
# API drift: the whole point
# --------------------------------------------------------------------------


@needs
def test_api_drift_surfaces_an_unimplemented_abstract_method():
    """v2 adds `addedLater()`. The plugin still loads and throws
    AbstractMethodError the first time the host calls it."""
    found = checks.check_abstract_implementations(PLUGIN, [V2])
    assert found, "the new abstract method was not detected"
    names = " ".join(f["unimplemented"][0] for f in found)
    assert "addedLater" in names
    assert "AbstractMethodError" in found[0]["consequence"]


@needs
def test_api_drift_surfaces_a_broken_override():
    """v2 changes `tick(int)` to `tick(float)`. The plugin's method becomes a
    new overload the host will never call -- it loads, and does nothing."""
    found = checks.check_overrides(PLUGIN, [V2])
    ticks = [f for f in found if f["method"].startswith("tick")]
    assert ticks, "the signature change was not detected"
    assert "(I)V" in ticks[0]["method"]
    assert any("(F)V" in s for s in ticks[0]["supertype_signatures"])


@needs
def test_no_broken_overrides_against_the_original_api():
    """The same check must stay quiet when nothing drifted."""
    found = checks.check_overrides(PLUGIN, [V1])
    assert [f for f in found if f["method"].startswith("tick")] == []


def test_arity_counts_descriptor_parameters():
    assert checks._arity("()V") == 0
    assert checks._arity("(I)V") == 1
    assert checks._arity("(IF)V") == 2
    assert checks._arity("(Ljava/lang/String;I)V") == 2
    assert checks._arity("([[Ljava/lang/String;J)V") == 2


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------


@needs
def test_entrypoint_present_and_instantiable():
    ep = linkage.check_entrypoints(PLUGIN, ["plug.MyPlugin"], [V1])[0]
    assert ep["present"] and ep["verdict"] == "ok"
    assert ep["has_no_arg_constructor"] is True
    assert ep["superclass"] == "api.Base"


@needs
def test_missing_entrypoint_is_reported_with_near_matches():
    ep = linkage.check_entrypoints(PLUGIN, ["plug.MyPlugn"], [V1])[0]
    assert ep["present"] is False
    assert "will fail to load" in ep["verdict"]


@needs
def test_abstract_entrypoint_cannot_be_instantiated():
    ep = linkage.check_entrypoints(V1, ["api.Base"], [V1])[0]
    assert ep["present"] is True
    assert ep["verdict"] != "ok"
    assert any("abstract" in p for p in ep["problems"])


# --------------------------------------------------------------------------
# Duplicates and data references
# --------------------------------------------------------------------------


@needs
def test_duplicate_classes_across_two_sources():
    dups = linkage.find_duplicate_classes([V1, V2])
    names = {d["class"] for d in dups}
    assert {"api.Host", "api.Base"} <= names
    assert all(d["copies"] >= 2 for d in dups)


@needs
def test_no_duplicates_within_one_source():
    assert linkage.find_duplicate_classes([V1]) == []


@needs
def test_data_reference_scan_resolves_and_reports(tmp_path):
    mod = tmp_path / "mod"
    (mod / "data" / "hullmods").mkdir(parents=True)
    (mod / "data" / "hullmods" / "hull_mods.csv").write_text(
        "id,script\nfoo,plug.MyPlugin\nbar,plug.DoesNotExist\n", encoding="utf-8"
    )
    r = checks.check_data_references(mod, [PLUGIN], [V1])
    assert r["referenced"] == 2
    # Both live in a package the plugin defines, so the unresolved one is a
    # defect rather than a lead.
    assert {m["class"] for m in r["missing"]} == {"plug.DoesNotExist"}
    assert r["unresolved_external"] == []


@needs
def test_data_scan_ignores_tooling_and_build_directories(tmp_path):
    """A `.repowise/knowledge-graph.json` naming JUnit classes produced three
    false findings; the engine only reads `data/` and the mod root."""
    mod = tmp_path / "mod"
    (mod / ".repowise").mkdir(parents=True)
    (mod / ".repowise" / "graph.json").write_text(
        '{"x": "org.junit.jupiter.api.Test"}', encoding="utf-8"
    )
    (mod / "out").mkdir()
    (mod / "out" / "stale.json").write_text('{"y": "plug.Gone"}', encoding="utf-8")
    (mod / "data").mkdir()
    (mod / "data" / "real.csv").write_text("script\nplug.MyPlugin\n", encoding="utf-8")

    r = checks.check_data_references(mod, [PLUGIN], [V1])
    assert r["referenced"] == 1          # only data/real.csv was read
    assert r["missing"] == []
    assert r["unresolved_external"] == []


@needs
def test_unresolved_name_outside_the_plugin_packages_is_only_a_lead(tmp_path):
    """`org.junit.jupiter.api.Test` in a tooling file is not a broken script
    reference. Names outside the plugin's own packages are reported
    separately so they cannot be mistaken for defects."""
    mod = tmp_path / "mod"
    (mod / "data").mkdir(parents=True)
    (mod / "data" / "x.json").write_text(
        '{"a": "org.junit.jupiter.api.Test", "b": "plug.MyPlugin"}', encoding="utf-8"
    )
    r = checks.check_data_references(mod, [PLUGIN], [V1])
    assert r["missing"] == []
    assert [e["class"] for e in r["unresolved_external"]] == ["org.junit.jupiter.api.Test"]
