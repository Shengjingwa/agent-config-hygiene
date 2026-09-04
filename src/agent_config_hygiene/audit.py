from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

from . import __version__
from .discovery import DiscoveryRequest, discover
from .metadata import stable_id
from .model import Artifact, AuditReport, Coverage, Finding, Severity


def _finding(
    code: str,
    severity: Severity,
    title: str,
    explanation: str,
    artifacts: list[Artifact],
    *,
    evidence: dict[str, Any] | None = None,
    recommendation: str,
) -> Finding:
    artifact_ids = tuple(sorted(artifact.artifact_id for artifact in artifacts))
    finding_id = stable_id(code, *artifact_ids)
    return Finding(
        finding_id=finding_id,
        code=code,
        severity=severity,
        title=title,
        explanation=explanation,
        artifact_ids=artifact_ids,
        evidence=evidence or {},
        recommendation=recommendation,
    )


def build_findings(artifacts: list[Artifact]) -> list[Finding]:
    findings: list[Finding] = []

    for artifact in artifacts:
        if artifact.kind == "discovery-boundary":
            findings.append(
                _finding(
                    "DISCOVERY_PARTIAL",
                    Severity.HIGH if artifact.external_target else Severity.MEDIUM,
                    "Configuration discovery stopped at a safety boundary",
                    "The scanner did not traverse this path, so the audit is incomplete.",
                    [artifact],
                    evidence={
                        "path": artifact.display_path,
                        "reason": list(artifact.metadata_errors),
                    },
                    recommendation="Review the path manually or replace the boundary with an owned regular directory.",
                )
            )
        elif artifact.coverage == Coverage.PARTIAL:
            findings.append(
                _finding(
                    "DISCOVERY_PARTIAL",
                    Severity.MEDIUM,
                    "Configuration metadata is incomplete",
                    "A bounded or link-safe scan could not inspect all metadata.",
                    [artifact],
                    evidence={
                        "path": artifact.display_path,
                        "reason": list(artifact.metadata_errors) or ["bounded-read-incomplete"],
                    },
                    recommendation=(
                        "Review the reported boundary manually; do not broaden automatic cleanup."
                    ),
                )
            )

        if artifact.kind in {"skill", "rule", "command-rule"} and not artifact.metadata_valid:
            findings.append(
                _finding(
                    "METADATA_INVALID",
                    Severity.HIGH if artifact.kind == "skill" else Severity.MEDIUM,
                    f"Invalid {artifact.kind} metadata",
                    "The artifact cannot be discovered or scoped reliably.",
                    [artifact],
                    evidence={
                        "path": artifact.display_path,
                        "errors": list(artifact.metadata_errors),
                    },
                    recommendation="Fix the metadata in its owning repository; do not copy the artifact to another root.",
                )
            )

        if artifact.external_target:
            findings.append(
                _finding(
                    "EXTERNAL_SYMLINK",
                    Severity.HIGH,
                    "Configuration symlink escapes its declared root",
                    "The discovered path resolves outside the configuration root, so ownership and cleanup boundaries are unclear.",
                    [artifact],
                    evidence={"path": artifact.display_path},
                    recommendation="Replace it with an explicitly owned location or review the target manually. Never auto-delete it.",
                )
            )

        if artifact.kind in {"rule", "instruction"} and artifact.attributes.get("always_loaded"):
            if artifact.bytes > 16 * 1024 or artifact.attributes.get("frontmatter_lines", 0) > 200:
                findings.append(
                    _finding(
                        "ALWAYS_LOADED_RULE_LARGE",
                        Severity.MEDIUM,
                        "Large always-loaded instruction",
                        "This file is likely added to agent context on every matching session.",
                        [artifact],
                        evidence={
                            "path": artifact.display_path,
                            "bytes": artifact.bytes,
                        },
                        recommendation="Keep only invariant guidance here and move task-specific detail behind an on-demand Skill or reference.",
                    )
                )

        if artifact.kind == "opaque-state":
            findings.append(
                _finding(
                    "OPAQUE_PROVIDER_STATE",
                    Severity.INFO,
                    "Provider state requires an interactive review",
                    "The provider does not expose a stable local file interface for these settings.",
                    [artifact],
                    evidence={"path": artifact.display_path},
                    recommendation="Review this state through the product UI; do not scrape internal databases.",
                )
            )

        if artifact.kind == "memory-state":
            findings.append(
                _finding(
                    "MEMORY_STATE_PRESENT",
                    Severity.INFO,
                    "Agent memory state is present",
                    "Only file count, total bytes, and modification time were inspected; memory text was not opened.",
                    [artifact],
                    evidence={
                        "path": artifact.display_path,
                        "files": artifact.files,
                        "bytes": artifact.bytes,
                    },
                    recommendation="Use the provider's supported memory controls for review or deletion.",
                )
            )

        if (
            artifact.kind == "skill"
            and not artifact.managed
            and any(
                route.startswith("codex:") and route.endswith(":legacy")
                for route in artifact.routes
            )
        ):
            findings.append(
                _finding(
                    "LEGACY_CODEX_SKILL_ROOT",
                    Severity.LOW,
                    "Skill uses a legacy Codex root",
                    "Codex currently supports this path for compatibility, but its documented native root is .agents/skills.",
                    [artifact],
                    evidence={"path": artifact.display_path},
                    recommendation="Plan a migration to the native root, checking Cursor compatibility discovery before moving anything.",
                )
            )

    skill_groups: dict[tuple[str, str, str], list[Artifact]] = defaultdict(list)
    for artifact in artifacts:
        if artifact.kind == "skill" and artifact.name:
            skill_groups[(artifact.scope, artifact.scope_anchor, artifact.name)].append(artifact)

    for (_, _, name), group in sorted(skill_groups.items()):
        if len(group) < 2:
            continue
        realpaths = {item.attributes.get("_realpath_id") for item in group}
        tree_hashes = {item.tree_hash for item in group}
        paths = [item.display_path for item in group]
        routes = sorted({route for item in group for route in item.routes})
        evidence = {
            "name": name,
            "paths": paths,
            "routes": routes,
            "managed_present": any(item.managed for item in group),
        }

        if len(realpaths) == 1:
            code = "SKILL_ALIAS_DUPLICATE"
            title = f"Skill '{name}' is discovered through multiple aliases"
            explanation = "Several discovery paths resolve to the same physical Skill."
            recommendation = (
                "Keep one native discovery route. Do not assume symlink de-duplication is shared "
                "across Cursor, Claude Code, and Codex."
            )
            severity = Severity.MEDIUM
        elif None not in tree_hashes and len(tree_hashes) == 1:
            code = "SKILL_EXACT_DUPLICATE"
            title = f"Skill '{name}' has exact copies in multiple roots"
            explanation = "The Skill trees have identical bounded content fingerprints."
            recommendation = (
                "Choose one physical owner for the agents you actually use, archive the other "
                "copies, and verify discovery before deleting them."
            )
            severity = Severity.MEDIUM
        else:
            code = "SKILL_NAME_COLLISION"
            title = f"Skill '{name}' has conflicting definitions"
            explanation = (
                "The same normalized Skill name maps to different or partially hashed content."
            )
            recommendation = (
                "Rename or consolidate the definitions after a manual semantic review. Never "
                "auto-delete a collision."
            )
            severity = Severity.HIGH

        findings.append(
            _finding(
                code,
                severity,
                title,
                explanation,
                group,
                evidence=evidence,
                recommendation=recommendation,
            )
        )

    return sorted(
        findings,
        key=lambda finding: (
            -{"high": 3, "medium": 2, "low": 1, "info": 0}[finding.severity.value],
            finding.code,
            finding.finding_id,
        ),
    )


def run_audit(
    *,
    home: Path,
    projects: tuple[Path, ...],
    providers: tuple[str, ...],
    include_user: bool,
) -> AuditReport:
    request = DiscoveryRequest(
        home=home,
        projects=projects,
        providers=providers,
        include_user=include_user,
    )
    artifacts = discover(request)
    findings = build_findings(artifacts)
    return AuditReport.create(
        tool_version=__version__,
        artifacts=artifacts,
        findings=findings,
        providers=providers,
        projects=tuple(f"<repo:{index}>" for index, _ in enumerate(projects, start=1)),
        user_scope=include_user,
    )


def dedupe_plan(report: AuditReport) -> list[dict[str, Any]]:
    plans: list[dict[str, Any]] = []
    artifact_by_id = {artifact.artifact_id: artifact for artifact in report.artifacts}
    for finding in report.findings:
        if finding.code not in {
            "SKILL_ALIAS_DUPLICATE",
            "SKILL_EXACT_DUPLICATE",
            "SKILL_NAME_COLLISION",
        }:
            continue
        candidates = [
            artifact_by_id[artifact_id]
            for artifact_id in finding.artifact_ids
            if artifact_id in artifact_by_id
        ]
        plans.append(
            {
                "finding_id": finding.finding_id,
                "name": finding.evidence.get("name"),
                "classification": finding.code,
                "candidates": [
                    {
                        "path": artifact.display_path,
                        "routes": list(artifact.routes),
                        "managed": artifact.managed,
                        "tree_fingerprint_available": artifact.tree_hash is not None,
                    }
                    for artifact in candidates
                ],
                "action": "manual-choice-required",
                "guardrails": [
                    "Never delete a managed candidate.",
                    "Keep the candidate native to the agents that must discover it.",
                    "Archive first, then verify discovery in each agent.",
                    "Re-run audit after the move.",
                ],
            }
        )
    return plans
