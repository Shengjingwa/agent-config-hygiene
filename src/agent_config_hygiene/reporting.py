from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .fs_safety import first_linklike_component, is_linklike
from .model import AuditReport, Severity


def render_human(report: AuditReport) -> str:
    data = report.to_dict()
    summary = data["summary"]
    lines = [
        "Agent configuration hygiene",
        f"  Artifacts: {summary['artifacts']}",
        f"  Findings: {summary['findings']}",
        (
            "  Severity: "
            + ", ".join(
                f"{name}={count}" for name, count in summary["findings_by_severity"].items()
            )
        ),
        "",
    ]
    if not report.findings:
        lines.append("No hygiene findings.")
    else:
        for finding in report.findings:
            lines.extend(
                [
                    f"[{finding.severity.value.upper()}] {finding.code} ({finding.finding_id})",
                    f"  {finding.title}",
                    f"  {finding.explanation}",
                    "  Evidence: "
                    + json.dumps(
                        finding.evidence,
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    f"  Recommendation: {finding.recommendation}",
                    "",
                ]
            )
    lines.extend(
        [
            "Privacy receipt:",
            "  No absolute paths or configuration free text emitted.",
            "  No provider credential stores or memory bodies read.",
            "  No network used.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def render_json(report: AuditReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _sarif_level(severity: Severity) -> str:
    if severity == Severity.HIGH:
        return "error"
    if severity in {Severity.MEDIUM, Severity.LOW}:
        return "warning"
    return "note"


def render_sarif(report: AuditReport) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    artifacts = {artifact.artifact_id: artifact for artifact in report.artifacts}
    for finding in report.findings:
        rules.setdefault(
            finding.code,
            {
                "id": finding.code,
                "shortDescription": {"text": finding.title},
                "help": {"text": finding.recommendation},
            },
        )
        locations = []
        for artifact_id in finding.artifact_ids:
            artifact = artifacts.get(artifact_id)
            if artifact is None:
                continue
            if artifact.display_path.startswith("<repo>/"):
                uri = quote(
                    artifact.display_path.removeprefix("<repo>/"),
                    safe="/",
                )
            elif artifact.display_path == "<repo>":
                uri = "."
            else:
                continue
            locations.append({"physicalLocation": {"artifactLocation": {"uri": uri}}})
        result: dict[str, Any] = {
            "ruleId": finding.code,
            "level": _sarif_level(finding.severity),
            "message": {"text": f"{finding.explanation} {finding.recommendation}"},
            "properties": {"findingId": finding.finding_id},
        }
        if locations:
            result["locations"] = locations
        results.append(result)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-config-hygiene",
                        "version": report.tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"privacy": report.privacy},
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def render(report: AuditReport, output_format: str) -> str:
    if output_format == "human":
        return render_human(report)
    if output_format == "json":
        return render_json(report)
    if output_format == "sarif":
        return render_sarif(report)
    raise ValueError(f"Unsupported report format: {output_format}")


def write_atomic(path: Path, content: str) -> None:
    path = path.expanduser().absolute()
    boundary = Path(path.anchor)
    if first_linklike_component(path.parent, boundary) is not None:
        raise ValueError(f"Refusing to write through an unsafe directory: {path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if first_linklike_component(path.parent, boundary) is not None or not path.parent.is_dir():
        raise ValueError(f"Refusing to write through an unsafe directory: {path.parent}")
    if is_linklike(path):
        raise ValueError(f"Refusing to replace a symlink output: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
