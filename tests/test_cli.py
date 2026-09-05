from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from test_discovery import write_skill

from agent_config_hygiene.cli import _run_scheduled, main
from agent_config_hygiene.scheduling import schedule_identity, scheduled_command
from agent_config_hygiene.state import ensure_state_root, write_json


class CliTests(unittest.TestCase):
    def test_audit_writes_redacted_json_and_honors_fail_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "repo"
            project.mkdir()
            write_skill(project / ".cursor" / "skills", "bad_name")
            output = Path(directory) / "audit.json"

            result = main(
                [
                    "audit",
                    str(project),
                    "--format",
                    "json",
                    "--output",
                    str(output),
                    "--fail-on",
                    "high",
                ]
            )
            payload = output.read_text(encoding="utf-8")
            self.assertEqual(result, 1)
            self.assertIn('"METADATA_INVALID"', payload)
            self.assertNotIn(str(project), payload)

    def test_clean_apply_requires_explicit_safe_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = main(
                    [
                        "clean",
                        "--state-root",
                        directory,
                        "--apply",
                    ]
                )
            self.assertEqual(result, 2)
            self.assertIn("--safe-only", stderr.getvalue())

    def test_schedule_install_is_dry_run_without_apply(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            stdout = io.StringIO()
            with (
                patch(
                    "agent_config_hygiene.scheduling.platform.system",
                    return_value="Windows",
                ),
                redirect_stdout(stdout),
            ):
                result = main(
                    [
                        "schedule",
                        "install",
                        "--backend",
                        "windows",
                        "--anchor-date",
                        "2026-09-14",
                        "--state-root",
                        str(state),
                    ]
                )
            self.assertEqual(result, 0)
            self.assertIn('"applied": false', stdout.getvalue())
            self.assertFalse(state.exists())

    def test_scheduled_run_writes_report_once_per_day(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state = base / "state"
            home = base / "home"
            home.mkdir()
            ensure_state_root(state)
            write_json(
                state / "schedule.json",
                {
                    "backend": "windows",
                    "anchor_date": "2026-09-04",
                    "weekday": "friday",
                    "at": "09:00",
                    "every_weeks": 2,
                    "providers": ["cursor"],
                    "include_user": True,
                    "safe_cleanup": False,
                    "retention_days": 90,
                    "state_root": str(state.resolve()),
                    "identity": schedule_identity(state),
                    "command": scheduled_command(state),
                },
            )

            with (
                patch("agent_config_hygiene.cli.schedule_is_due", return_value=True),
                patch("agent_config_hygiene.cli.Path.home", return_value=home),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(_run_scheduled(state), 0)
                self.assertEqual(_run_scheduled(state), 0)

            reports = list((state / "reports").glob("audit-*.json"))
            self.assertEqual(len(reports), 1)
            config = (state / "schedule.json").read_text(encoding="utf-8")
            self.assertIn('"last_run_date"', config)

    def test_cleanup_failure_does_not_duplicate_daily_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            state = base / "state"
            home = base / "home"
            home.mkdir()
            ensure_state_root(state)
            write_json(
                state / "schedule.json",
                {
                    "backend": "windows",
                    "anchor_date": "2026-09-04",
                    "weekday": "friday",
                    "at": "09:00",
                    "every_weeks": 2,
                    "providers": ["cursor"],
                    "include_user": True,
                    "safe_cleanup": True,
                    "retention_days": 90,
                    "state_root": str(state.resolve()),
                    "identity": schedule_identity(state),
                    "command": scheduled_command(state),
                },
            )

            with (
                patch(
                    "agent_config_hygiene.cli.schedule_is_due",
                    return_value=True,
                ),
                patch(
                    "agent_config_hygiene.cli.Path.home",
                    return_value=home,
                ),
                patch(
                    "agent_config_hygiene.cli.apply_cleanup",
                    side_effect=RuntimeError("cleanup failed"),
                ),
                redirect_stdout(io.StringIO()),
            ):
                with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                    _run_scheduled(state)
                self.assertEqual(_run_scheduled(state), 0)

            reports = list((state / "reports").glob("audit-*.json"))
            self.assertEqual(len(reports), 1)


if __name__ == "__main__":
    unittest.main()
