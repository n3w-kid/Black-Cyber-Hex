from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


@dataclass
class Finding:
    source: str
    title: str
    severity: str = "info"
    target: str = ""
    evidence: str = ""
    reference: str = ""
    kind: str = "finding"
    metadata: dict[str, Any] | None = None

    def to_dict(self):
        return asdict(self)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.source, f.title, f.severity, f.target, f.reference)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return sorted(out, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.source, x.title, x.target))
