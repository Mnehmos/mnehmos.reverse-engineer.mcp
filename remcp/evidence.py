"""Evidence envelopes.

First principle: an analysis result without its provenance and its caveats is
a bare claim. Every tool in this server returns the same envelope shape:

    {
      "ok": true,
      "target":   what was analyzed, content-addressed
      "method":   how the answer was produced
      "reliability": "sound" | "degraded" | "unreliable"
      "warnings": [ {code, detail} ]   <- IN BAND, not on stderr
      "result":   the actual answer
    }

The predecessor emitted its packed-code warning to stderr, where an MCP
client never surfaces it to the model. The model therefore received 21,339
fabricated call edges with nothing marking them as noise. Warnings belong in
the payload.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

Reliability = Literal["sound", "degraded", "unreliable"]

# Ordered worst-last so we can take a maximum.
_RANK: dict[str, int] = {"sound": 0, "degraded": 1, "unreliable": 2}


@dataclass
class Warning_:
    code: str
    detail: str
    # How much this warning should be allowed to discredit the result.
    impact: Reliability = "degraded"

    def to_dict(self) -> dict:
        return {"code": self.code, "detail": self.detail, "impact": self.impact}


@dataclass
class Envelope:
    method: str
    target: dict[str, Any] = field(default_factory=dict)
    warnings: list[Warning_] = field(default_factory=list)
    result: Any = None
    extra: dict[str, Any] = field(default_factory=dict)

    def warn(self, code: str, detail: str, impact: Reliability = "degraded") -> "Envelope":
        self.warnings.append(Warning_(code, detail, impact))
        return self

    @property
    def reliability(self) -> Reliability:
        worst: Reliability = "sound"
        for w in self.warnings:
            if _RANK[w.impact] > _RANK[worst]:
                worst = w.impact
        return worst

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "ok": True,
            "target": self.target,
            "method": self.method,
            "reliability": self.reliability,
            "warnings": [w.to_dict() for w in self.warnings],
            "result": self.result,
        }
        d.update(self.extra)
        return d


def image_warnings(image) -> list[Warning_]:
    """Caveats that apply to any code analysis over this image.

    These are the checks the predecessor either logged to stderr or never
    made at all. They are computed once per image and attached to every
    envelope whose answer depends on decoding instructions.
    """
    out: list[Warning_] = []

    for sec in image.sections:
        if sec.x and sec.filesize > 0 and sec.entropy is not None and sec.entropy > 7.5:
            out.append(
                Warning_(
                    "packed_exec_section",
                    f"executable section {sec.name!r} has entropy {sec.entropy:.2f}; "
                    "code is encrypted, packed, or compressed. Disassembly, xrefs, "
                    "call graphs and signatures over this section are meaningless. "
                    "Analyze an unpacked image or a process dump instead.",
                    impact="unreliable",
                )
            )

    if not any(s.x for s in image.sections):
        out.append(
            Warning_(
                "no_executable_sections",
                "no section is marked executable; code analyses will find nothing.",
                impact="degraded",
            )
        )

    return out
