from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}


class Coverage(str, Enum):
    SUPPORTED = "supported"
    PARTIAL = "partial"
    OPAQUE = "opaque"
    SENSITIVE_SKIPPED = "sensitive-skipped"
    PERMISSION_DENIED = "permission-denied"


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    kind: str
    scope: str
    scope_anchor: str
    display_path: str
    routes: tuple[str, ...]
    path: Path = field(repr=False, compare=False)
    name: str | None = None
    metadata_valid: bool = True
    metadata_errors: tuple[str, ...] = ()
    content_hash: str | None = None
    tree_hash: str | None = None
    bytes: int = 0
    files: int = 0
    modified_at: str | None = None
    managed: bool = False
    symlink: bool = False
    external_target: bool = False
    coverage: Coverage = Coverage.SUPPORTED
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.artifact_id,
            "kind": self.kind,
            "scope": self.scope,
            "scope_anchor": self.scope_anchor,
            "path": self.display_path,
            "routes": list(self.routes),
            "name": self.name,
            "metadata_valid": self.metadata_valid,
            "metadata_errors": list(self.metadata_errors),
            "content_fingerprint_available": self.content_hash is not None,
            "tree_fingerprint_available": self.tree_hash is not None,
            "bytes": self.bytes,
            "files": self.files,
            "modified_at": self.modified_at,
            "managed": self.managed,
            "symlink": self.symlink,
            "external_target": self.external_target,
            "coverage": self.coverage.value,
            "attributes": {
                key: value for key, value in self.attributes.items() if not key.startswith("_")
            },
        }


@dataclass(frozen=True)
class Finding:
    finding_id: str
    code: str
    severity: Severity
    title: str
    explanation: str
    artifact_ids: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.finding_id,
            "code": self.code,
            "severity": self.severity.value,
            "title": self.title,
            "explanation": self.explanation,
            "artifact_ids": list(self.artifact_ids),
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class AuditReport:
    schema_version: str
    tool_version: str
    generated_at: str
    artifacts: tuple[Artifact, ...]
    findings: tuple[Finding, ...]
    providers: tuple[str, ...]
    projects: tuple[str, ...]
    user_scope: bool
    privacy: dict[str, Any]

    @classmethod
    def create(
        cls,
        *,
        tool_version: str,
        artifacts: list[Artifact],
        findings: list[Finding],
        providers: tuple[str, ...],
        projects: tuple[str, ...],
        user_scope: bool,
    ) -> AuditReport:
        return cls(
            schema_version="1",
            tool_version=tool_version,
            generated_at=datetime.now(timezone.utc).isoformat(),
            artifacts=tuple(artifacts),
            findings=tuple(findings),
            providers=providers,
            projects=projects,
            user_scope=user_scope,
            privacy={
                "absolute_paths_emitted": False,
                "free_text_emitted": False,
                "memory_bodies_read": False,
                "credential_stores_read": False,
                "network_used": False,
            },
        )

    def to_dict(self) -> dict[str, Any]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return {
            "schema_version": self.schema_version,
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "scope": {
                "providers": list(self.providers),
                "projects": list(self.projects),
                "user": self.user_scope,
            },
            "summary": {
                "artifacts": len(self.artifacts),
                "findings": len(self.findings),
                "findings_by_severity": counts,
            },
            "artifacts": [artifact.to_dict() for artifact in self.artifacts],
            "findings": [finding.to_dict() for finding in self.findings],
            "privacy": self.privacy,
        }
