from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_config_hygiene.skill_install import install, plan_install


class SkillInstallTests(unittest.TestCase):
    def test_installs_one_copy_and_blocks_multipath_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            result = install(
                target="cursor",
                scope="user",
                home=home,
                project=None,
                allow_multipath=False,
            )
            self.assertTrue(result["changed"])
            skill = home / ".cursor" / "skills" / "agent-config-hygiene" / "SKILL.md"
            self.assertTrue(skill.is_file())
            unchanged = install(
                target="cursor",
                scope="user",
                home=home,
                project=None,
                allow_multipath=False,
            )
            self.assertFalse(unchanged["changed"])

            with self.assertRaises(RuntimeError):
                install(
                    target="claude",
                    scope="user",
                    home=home,
                    project=None,
                    allow_multipath=False,
                )
            self.assertFalse((home / ".claude" / "skills").exists())
            self.assertFalse((home / ".agents").exists())

    def test_existing_skill_with_extra_file_is_not_trusted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            install(
                target="cursor",
                scope="user",
                home=home,
                project=None,
                allow_multipath=False,
            )
            destination = home / ".cursor" / "skills" / "agent-config-hygiene"
            (destination / "unexpected.py").write_text(
                "raise SystemExit\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "different Skill"):
                install(
                    target="cursor",
                    scope="user",
                    home=home,
                    project=None,
                    allow_multipath=False,
                )

    def test_failed_atomic_install_removes_empty_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            destination = home / ".cursor" / "skills" / "agent-config-hygiene"
            with patch(
                "agent_config_hygiene.skill_install.os.rename",
                side_effect=OSError("failed"),
            ):
                with self.assertRaisesRegex(OSError, "failed"):
                    install(
                        target="cursor",
                        scope="user",
                        home=home,
                        project=None,
                        allow_multipath=False,
                    )
            self.assertFalse(destination.exists())

    def test_codex_plan_does_not_create_agents_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            result = plan_install(
                target="codex",
                scope="user",
                home=home,
                project=None,
            )
            self.assertEqual(
                result["destination"],
                "~/.agents/skills/agent-config-hygiene",
            )
            self.assertFalse((home / ".agents").exists())

    def test_project_install_requires_existing_project(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            missing = home / "missing-project"
            with self.assertRaises(ValueError):
                plan_install(
                    target="cursor",
                    scope="project",
                    home=home,
                    project=missing,
                )
            self.assertFalse(missing.exists())

    def test_project_install_refuses_linked_project_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            outside = base / "outside"
            home.mkdir()
            outside.mkdir()
            linked_project = base / "linked-project"
            try:
                linked_project.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")

            with self.assertRaisesRegex(RuntimeError, "contains a symlink"):
                install(
                    target="cursor",
                    scope="project",
                    home=home,
                    project=linked_project,
                    allow_multipath=False,
                )
            self.assertFalse((outside / ".cursor").exists())


if __name__ == "__main__":
    unittest.main()
