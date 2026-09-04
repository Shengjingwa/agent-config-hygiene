from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_config_hygiene.metadata as metadata_module
from agent_config_hygiene.audit import build_findings, run_audit
from agent_config_hygiene.discovery import (
    DiscoveryRequest,
    _display_path,
    discover,
)


def write_skill(root: Path, name: str, body: str = "instructions") -> None:
    skill = root / name
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: Test Skill.\n---\n{body}\n",
        encoding="utf-8",
    )


class UserDiscoveryTests(unittest.TestCase):
    def test_detects_cross_root_exact_duplicates_without_emitting_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            write_skill(home / ".cursor" / "skills", "same-skill", "HONEY_SECRET")
            write_skill(home / ".claude" / "skills", "same-skill", "HONEY_SECRET")
            write_skill(
                home / ".codex" / "skills" / ".system",
                "builtin-skill",
                "SYSTEM_SECRET",
            )
            memory = home / ".codex" / "memories"
            memory.mkdir(parents=True)
            (memory / "private.md").write_text("MEMORY_SECRET", encoding="utf-8")

            with patch.dict(
                os.environ,
                {
                    "CLAUDE_CONFIG_DIR": str(home / ".claude"),
                    "CODEX_HOME": str(home / ".codex"),
                },
            ):
                report = run_audit(
                    home=home,
                    projects=(),
                    providers=("cursor", "claude", "codex"),
                    include_user=True,
                )

            finding_codes = {finding.code for finding in report.findings}
            self.assertIn("SKILL_EXACT_DUPLICATE", finding_codes)
            self.assertIn("MEMORY_STATE_PRESENT", finding_codes)
            system_skills = [
                artifact for artifact in report.artifacts if artifact.name == "builtin-skill"
            ]
            self.assertEqual(len(system_skills), 1)
            self.assertTrue(system_skills[0].managed)

            serialized = json.dumps(report.to_dict(), ensure_ascii=False)
            self.assertNotIn("HONEY_SECRET", serialized)
            self.assertNotIn("SYSTEM_SECRET", serialized)
            self.assertNotIn("MEMORY_SECRET", serialized)
            self.assertNotIn(str(home), serialized)
            self.assertFalse(report.privacy["memory_bodies_read"])

    def test_invalid_skill_name_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            write_skill(home / ".cursor" / "skills", "bad_name")
            report = run_audit(
                home=home,
                projects=(),
                providers=("cursor",),
                include_user=True,
            )
            invalid = [finding for finding in report.findings if finding.code == "METADATA_INVALID"]
            self.assertEqual(len(invalid), 1)
            self.assertIn("invalid-name", invalid[0].evidence["errors"])

    def test_invalid_skill_name_value_is_not_emitted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            skill = home / ".cursor" / "skills" / "bad-skill"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: INVALID_SECRET\u001b[31m\ndescription: test\n---\n",
                encoding="utf-8",
            )
            report = run_audit(
                home=home,
                projects=(),
                providers=("cursor",),
                include_user=True,
            )
            serialized = json.dumps(report.to_dict(), ensure_ascii=False)
            self.assertNotIn("INVALID_SECRET", serialized)
            skills = [artifact for artifact in report.artifacts if artifact.kind == "skill"]
            self.assertEqual(len(skills), 1)
            self.assertIsNone(skills[0].name)

    def test_linked_provider_root_is_not_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            outside = base / "outside"
            home.mkdir()
            write_skill(
                outside / "skills",
                "outside-skill",
                "OUTSIDE_SECRET",
            )
            try:
                (home / ".cursor").symlink_to(
                    outside,
                    target_is_directory=True,
                )
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")
            report = run_audit(
                home=home,
                projects=(),
                providers=("cursor",),
                include_user=True,
            )
            self.assertFalse(any(artifact.kind == "skill" for artifact in report.artifacts))
            self.assertTrue(
                any(
                    artifact.kind == "discovery-boundary"
                    and artifact.metadata_errors == ("linked-ancestor-not-traversed",)
                    and artifact.external_target
                    for artifact in report.artifacts
                )
            )
            self.assertIn(
                "EXTERNAL_SYMLINK",
                {finding.code for finding in report.findings},
            )
            self.assertNotIn(
                "OUTSIDE_SECRET",
                json.dumps(report.to_dict()),
            )

    def test_linked_claude_memory_is_reported_as_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            project_state = home / ".claude" / "projects" / "project"
            outside = Path(directory) / "outside"
            project_state.mkdir(parents=True)
            outside.mkdir()
            (outside / "private.md").write_text(
                "MEMORY_SECRET",
                encoding="utf-8",
            )
            try:
                (project_state / "memory").symlink_to(
                    outside,
                    target_is_directory=True,
                )
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")
            report = run_audit(
                home=home,
                projects=(),
                providers=("claude",),
                include_user=True,
            )
            boundaries = [
                artifact for artifact in report.artifacts if artifact.kind == "discovery-boundary"
            ]
            self.assertEqual(len(boundaries), 1)
            self.assertEqual(
                boundaries[0].metadata_errors,
                ("linked-memory-root-not-traversed",),
            )
            self.assertNotIn(
                "MEMORY_SECRET",
                json.dumps(report.to_dict()),
            )

    def test_nested_memory_link_marks_state_scan_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "home"
            memory = home / ".codex" / "memories"
            outside = Path(directory) / "outside"
            memory.mkdir(parents=True)
            outside.mkdir()
            (outside / "private.md").write_text(
                "MEMORY_SECRET",
                encoding="utf-8",
            )
            try:
                (memory / "linked").symlink_to(
                    outside,
                    target_is_directory=True,
                )
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")

            report = run_audit(
                home=home,
                projects=(),
                providers=("codex",),
                include_user=True,
            )
            states = [artifact for artifact in report.artifacts if artifact.kind == "memory-state"]
            self.assertEqual(len(states), 1)
            self.assertEqual(states[0].coverage.value, "partial")
            self.assertEqual(states[0].attributes["links_skipped"], 1)
            self.assertIn(
                "DISCOVERY_PARTIAL",
                {finding.code for finding in report.findings},
            )
            self.assertNotIn("MEMORY_SECRET", json.dumps(report.to_dict()))


class ProjectDiscoveryTests(unittest.TestCase):
    def test_instruction_body_is_not_hashed_beyond_frontmatter_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "repo"
            project.mkdir()
            instruction = project / "AGENTS.md"
            instruction.write_bytes(b"x" * (1024 * 1024))
            original = metadata_module._read_regular_prefix
            reads: list[tuple[Path, int]] = []

            def record_read(
                path: Path,
                limit: int,
            ) -> tuple[bytes | None, int, bool]:
                reads.append((path, limit))
                return original(path, limit)

            with patch.object(
                metadata_module,
                "_read_regular_prefix",
                side_effect=record_read,
            ):
                report = run_audit(
                    home=Path(directory),
                    projects=(project,),
                    providers=("codex",),
                    include_user=False,
                )

            instruction_reads = [limit for path, limit in reads if path == instruction]
            self.assertEqual(
                instruction_reads,
                [metadata_module.FRONTMATTER_LIMIT],
            )
            artifacts = [
                artifact for artifact in report.artifacts if artifact.kind == "instruction"
            ]
            self.assertEqual(artifacts[0].bytes, 1024 * 1024)
            self.assertIsNone(artifacts[0].content_hash)

    def test_display_path_escapes_terminal_controls(self) -> None:
        root = Path("/repo")
        display = _display_path(
            root / "unsafe\u001b[31m.md",
            home=Path("/home"),
            project=root,
        )
        self.assertEqual(display, r"<repo>/unsafe\u{1b}[31m.md")

    def test_linked_project_root_is_not_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            outside = base / "outside"
            outside.mkdir()
            (outside / "AGENTS.md").write_text(
                "DO_NOT_READ_THIS_BODY",
                encoding="utf-8",
            )
            linked = base / "linked-repo"
            try:
                linked.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")

            artifacts = discover(
                DiscoveryRequest(
                    home=base,
                    projects=(linked,),
                    providers=("cursor",),
                )
            )
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(
                artifacts[0].metadata_errors,
                ("linked-project-root-not-traversed",),
            )

    def test_linked_project_subtree_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            project = base / "repo"
            outside = base / "outside"
            project.mkdir()
            outside.mkdir()
            linked = project / "linked"
            try:
                linked.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")

            artifacts = discover(
                DiscoveryRequest(
                    home=base,
                    projects=(project,),
                    providers=("cursor",),
                )
            )
            self.assertTrue(
                any(
                    artifact.metadata_errors == ("linked-project-subtree-not-traversed",)
                    for artifact in artifacts
                )
            )

    def test_detects_cursor_and_agents_project_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "repo"
            project.mkdir()
            write_skill(project / ".cursor" / "skills", "shared-skill")
            write_skill(project / ".agents" / "skills", "shared-skill")
            report = run_audit(
                home=Path(directory),
                projects=(project,),
                providers=("cursor", "codex"),
                include_user=False,
            )
            duplicate = [
                finding for finding in report.findings if finding.code == "SKILL_EXACT_DUPLICATE"
            ]
            self.assertEqual(len(duplicate), 1)
            self.assertEqual(len(duplicate[0].evidence["paths"]), 2)

    def test_finds_dot_claude_instruction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "repo"
            instruction = project / ".claude" / "CLAUDE.md"
            instruction.parent.mkdir(parents=True)
            instruction.write_text("Project guidance.\n", encoding="utf-8")
            report = run_audit(
                home=Path(directory),
                projects=(project,),
                providers=("claude",),
                include_user=False,
            )
            paths = {artifact.display_path for artifact in report.artifacts}
            self.assertIn("<repo>/.claude/CLAUDE.md", paths)

    def test_same_named_repositories_do_not_share_duplicate_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            first = base / "one" / "repo"
            second = base / "two" / "repo"
            first.mkdir(parents=True)
            second.mkdir(parents=True)
            write_skill(first / ".cursor" / "skills", "local-skill")
            write_skill(second / ".cursor" / "skills", "local-skill")
            report = run_audit(
                home=base,
                projects=(first, second),
                providers=("cursor",),
                include_user=False,
            )
            self.assertEqual(len({item.artifact_id for item in report.artifacts}), 2)
            self.assertNotIn(
                "SKILL_EXACT_DUPLICATE",
                {finding.code for finding in report.findings},
            )

    def test_project_walk_limit_is_reported_as_partial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "repo"
            project.mkdir()
            artifacts = discover(
                DiscoveryRequest(
                    home=Path(directory),
                    projects=(project,),
                    providers=("cursor",),
                    max_project_directories=0,
                )
            )
            findings = build_findings(artifacts)
            self.assertIn("DISCOVERY_PARTIAL", {item.code for item in findings})

    def test_symlinked_skill_directory_is_reported_without_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            project = base / "repo"
            skill_root = project / ".cursor" / "skills"
            skill_root.mkdir(parents=True)
            outside = base / "outside-skill"
            write_skill(base, "outside-skill", "DO_NOT_READ_THIS_BODY")
            link = skill_root / "linked-skill"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")

            report = run_audit(
                home=base,
                projects=(project,),
                providers=("cursor",),
                include_user=False,
            )
            codes = {finding.code for finding in report.findings}
            self.assertIn("DISCOVERY_PARTIAL", codes)
            self.assertIn("EXTERNAL_SYMLINK", codes)
            payload = json.dumps(report.to_dict())
            self.assertIn("<repo>/.cursor/skills/linked-skill", payload)
            self.assertNotIn("DO_NOT_READ_THIS_BODY", payload)

    def test_cursor_non_always_rule_is_not_classified_as_always_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "repo"
            rules = project / ".cursor" / "rules"
            rules.mkdir(parents=True)
            (rules / "manual.mdc").write_text(
                "---\ndescription: On-demand guidance.\nalwaysApply: false\n---\n" + ("x" * 20_000),
                encoding="utf-8",
            )
            report = run_audit(
                home=Path(directory),
                projects=(project,),
                providers=("cursor",),
                include_user=False,
            )
            self.assertNotIn(
                "ALWAYS_LOADED_RULE_LARGE",
                {finding.code for finding in report.findings},
            )

    def test_unscoped_claude_rule_is_classified_as_always_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "repo"
            rules = project / ".claude" / "rules"
            rules.mkdir(parents=True)
            (rules / "global.md").write_text("x" * 20_000, encoding="utf-8")
            report = run_audit(
                home=Path(directory),
                projects=(project,),
                providers=("claude",),
                include_user=False,
            )
            self.assertIn(
                "ALWAYS_LOADED_RULE_LARGE",
                {finding.code for finding in report.findings},
            )


if __name__ == "__main__":
    unittest.main()
