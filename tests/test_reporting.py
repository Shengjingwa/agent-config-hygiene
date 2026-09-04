from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_config_hygiene.model import (
    Artifact,
    AuditReport,
    Finding,
    Severity,
)
from agent_config_hygiene.reporting import render, write_atomic


class ReportingTests(unittest.TestCase):
    def test_sarif_percent_encodes_relative_location(self) -> None:
        artifact = Artifact(
            artifact_id="artifact",
            kind="rule",
            scope="project",
            scope_anchor="<repo:1>",
            display_path="<repo>/unsafe #?.md",
            routes=("cursor:project:rule",),
            path=Path("unsafe #?.md"),
        )
        finding = Finding(
            finding_id="finding",
            code="TEST",
            severity=Severity.MEDIUM,
            title="Test",
            explanation="Test",
            artifact_ids=("artifact",),
            recommendation="Test",
        )
        report = AuditReport.create(
            tool_version="test",
            artifacts=[artifact],
            findings=[finding],
            providers=("cursor",),
            projects=("<repo:1>",),
            user_scope=False,
        )

        payload = render(report, "sarif")

        self.assertIn("unsafe%20%23%3F.md", payload)

    def test_atomic_write_refuses_linked_parent_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            outside = base / "outside"
            outside.mkdir()
            linked = base / "linked"
            try:
                linked.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")

            with self.assertRaisesRegex(ValueError, "unsafe directory"):
                write_atomic(linked / "nested" / "report.json", "{}\n")
            self.assertFalse((outside / "nested").exists())

    def test_json_omits_absolute_paths_internal_ids_and_raw_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            absolute = Path(directory) / "private" / "skill"
            artifact = Artifact(
                artifact_id="public-id",
                kind="skill",
                scope="user",
                scope_anchor="<user>",
                display_path="~/.cursor/skills/sample",
                routes=("cursor:user:native",),
                path=absolute,
                name="sample",
                content_hash="CONTENT_FINGERPRINT_SECRET",
                tree_hash="TREE_FINGERPRINT_SECRET",
                attributes={
                    "_realpath_id": "REALPATH_SECRET",
                    "source_root": "~/.cursor/skills",
                },
            )
            report = AuditReport.create(
                tool_version="test",
                artifacts=[artifact],
                findings=[],
                providers=("cursor",),
                projects=(),
                user_scope=True,
            )
            payload = render(report, "json")
            self.assertNotIn(str(absolute), payload)
            self.assertNotIn("CONTENT_FINGERPRINT_SECRET", payload)
            self.assertNotIn("TREE_FINGERPRINT_SECRET", payload)
            self.assertNotIn("REALPATH_SECRET", payload)
            self.assertIn('"tree_fingerprint_available": true', payload)
            self.assertIn('"credential_stores_read": false', payload)


if __name__ == "__main__":
    unittest.main()
