from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_config_hygiene.state import (
    RunLock,
    ensure_state_root,
    ensure_state_subdirectory,
    verify_state_root,
)


class StateOwnershipTests(unittest.TestCase):
    def test_refuses_non_file_owner_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            root.mkdir()
            (root / ".owner").mkdir()
            with self.assertRaises(RuntimeError):
                ensure_state_root(root)
            self.assertFalse(verify_state_root(root))

    def test_creates_and_verifies_owner_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            ensure_state_root(root)
            self.assertTrue(verify_state_root(root))

    def test_refuses_to_adopt_nonempty_state_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            root.mkdir()
            unrelated = root / "reports"
            unrelated.mkdir()
            (unrelated / "keep.txt").write_text("keep", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "non-empty"):
                ensure_state_root(root)
            self.assertFalse((root / ".owner").exists())
            self.assertTrue((unrelated / "keep.txt").exists())

    def test_state_root_rejects_linked_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            outside = base / "outside"
            outside.mkdir()
            linked = base / "linked"
            try:
                linked.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")

            with self.assertRaisesRegex(RuntimeError, "symlink"):
                ensure_state_root(linked / "state")
            self.assertFalse((outside / "state").exists())

    def test_run_lock_is_released_without_deleting_lock_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            ensure_state_root(root)
            with RunLock(root):
                with self.assertRaises(RuntimeError):
                    with RunLock(root):
                        pass
            self.assertTrue((root / "run.lock").is_file())
            with RunLock(root):
                pass

    def test_state_subdirectory_rejects_directory_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "state"
            outside = base / "outside"
            outside.mkdir()
            ensure_state_root(root)
            try:
                (root / "reports").symlink_to(
                    outside,
                    target_is_directory=True,
                )
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "Unsafe"):
                ensure_state_subdirectory(root, "reports")

    def test_run_lock_rejects_hard_link_without_modifying_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "state"
            external = base / "external.txt"
            external.write_bytes(b"protected")
            ensure_state_root(root)
            try:
                (root / "run.lock").hardlink_to(external)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "Unsafe"):
                with RunLock(root):
                    pass
            self.assertEqual(external.read_bytes(), b"protected")

    def test_run_lock_recovers_owned_zero_length_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            ensure_state_root(root)
            lock_path = root / "run.lock"
            lock_path.write_bytes(b"")
            with RunLock(root):
                pass
            self.assertEqual(lock_path.read_bytes(), b"\0")


if __name__ == "__main__":
    unittest.main()
