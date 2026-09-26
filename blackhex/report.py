from __future__ import annotations
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from .findings import Finding, deduplicate


def write_report(out_dir: Path, target: str, findings: list[Finding], runs: list[dict]) -> tuple[Path, Path]:
    findings = deduplicate(findings)
    payload = {
        "framework": "Black Cyber Hex",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "counts": dict(Counter(f.severity for f in findings)),
        "findings": [f.to_dict() for f in findings],
        "tool_runs": runs,
    }
    json_path = out_dir / "summary.json"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    lines = [
        "# Black Cyber Hex — Scan Report",
        "",
        f"**Target:** `{target}`  ",
        f"**Generated:** {payload['generated_at']}  ",
        "",
        "## Severity summary",
        "",
    ]
    counts = payload["counts"]
    lines.append(" | ".join(f"**{s.title()}**: {counts.get(s, 0)}" for s in ["critical", "high", "medium", "low", "info", "unknown"]))
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No normalized findings were produced. Check individual tool logs for skipped/error states.")
    for i, f in enumerate(findings, 1):
        lines += [
            f"### {i}. [{f.severity.upper()}] {f.title}",
            f"- Source: `{f.source}`",
            f"- Target: `{f.target}`" if f.target else "- Target: n/a",
            f"- Reference: `{f.reference}`" if f.reference else "- Reference: n/a",
        ]
        if f.evidence:
            clean = f.evidence.replace("```", "'''")
            lines += ["", "```text", clean[:6000], "```"]
        lines.append("")
    lines += ["## Tool execution", ""]
    for run in runs:
        lines.append(f"- **{run.get('tool')}**: {run.get('status')} (exit {run.get('returncode')}, {run.get('duration_seconds')}s)")
    md_path = out_dir / "summary.md"
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path
