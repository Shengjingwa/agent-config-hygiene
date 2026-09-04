from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path

from agent_config_hygiene.cleanup import apply_cleanup, plan_cleanup
from agent_config_hygiene.state import ensure_state_root


class CleanupTests(unittest.TestCase):
    def test_dry_run_and_apply_only_touch_owned_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "state"
            ensure_state_root(root)
            reports = root / "reports"
            reports.mkdir()
            old_report = reports / "audit-old.json"
            old_report.write_text("{}\n", encoding="utf-8")
            old_timestamp = time.time() - 120 * 24 * 60 * 60
            os.utime(old_report, (old_timestamp, old_timestamp))
            outside = base / "unrelated.tmp"
            outside.write_text("keep", encoding="utf-8")

            plan = plan_cleanup(root, retention_days=90)
            self.assertEqual(len(plan.candidates), 1)
            self.assertTrue(old_report.exists(), "planning must be read-only")

            result = apply_cleanup(root, plan)
            self.assertEqual(result["removed"], ["<state>/reports/audit-old.json"])
            self.assertFalse(old_report.exists())
            self.assertTrue(outside.exists())

    def test_unowned_state_is_never_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reports = root / "reports"
            reports.mkdir()
            target = reports / "unknown.tmp"
            target.write_text("keep", encoding="utf-8")

            plan = plan_cleanup(root, retention_days=7)
            self.assertFalse(plan.state_verified)
            self.assertEqual(plan.candidates, ())
            with self.assertRaises(RuntimeError):
                apply_cleanup(root, plan)
            self.assertTrue(target.exists())

    def test_cleanup_does_not_follow_directory_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "state"
            ensure_state_root(root)
            reports = root / "reports"
            reports.mkdir()
            outside = base / "outside"
            outside.mkdir()
            target = outside / "old.json"
            target.write_text("{}\n", encoding="utf-8")
            old_timestamp = time.time() - 120 * 24 * 60 * 60
            os.utime(target, (old_timestamp, old_timestamp))
            try:
                (reports / "linked").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")

            plan = plan_cleanup(root, retention_days=90)
            self.assertEqual(plan.candidates, ())
            self.assertIn("unsafe-entry:reports", plan.errors)
            with self.assertRaises(RuntimeError):
                apply_cleanup(root, plan)
            self.assertTrue(target.exists())

    def test_cleanup_rejects_hard_linked_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "state"
            ensure_state_root(root)
            reports = root / "reports"
            reports.mkdir()
            external = base / "external.json"
            external.write_text("{}\n", encoding="utf-8")
            try:
                (reports / "linked.json").hardlink_to(external)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")

            plan = plan_cleanup(root, retention_days=90)
            self.assertEqual(plan.candidates, ())
            self.assertIn("unsafe-entry:reports", plan.errors)
            with self.assertRaises(RuntimeError):
                apply_cleanup(root, plan)
            self.assertEqual(external.read_text(encoding="utf-8"), "{}\n")


if __name__ == "__main__":
    unittest.main()
