from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import agent_config_hygiene.metadata as metadata_module
from agent_config_hygiene.metadata import (
    fingerprint_tree,
    hash_file,
    read_frontmatter,
    validate_skill_frontmatter,
)


class FrontmatterTests(unittest.TestCase):
    def test_valid_skill_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            skill = Path(directory) / "sample-skill"
            skill.mkdir()
            path = skill / "SKILL.md"
            path.write_text(
                "---\n"
                "name: sample-skill\n"
                "description: Audits sample data.\n"
                "disable-model-invocation: true\n"
                "---\n"
                "secret body that must not be reported\n",
                encoding="utf-8",
            )
            metadata = read_frontmatter(path)
            name, errors = validate_skill_frontmatter(metadata, skill.name)
            self.assertEqual(name, "sample-skill")
            self.assertEqual(errors, ())

    def test_missing_name_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            skill = Path(directory) / "sample-skill"
            skill.mkdir()
            path = skill / "SKILL.md"
            path.write_text(
                "---\ndescription: Missing name.\n---\n",
                encoding="utf-8",
            )
            name, errors = validate_skill_frontmatter(read_frontmatter(path), skill.name)
            self.assertIsNone(name)
            self.assertIn("missing-name", errors)

    def test_inline_comment_and_malformed_quote(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commented = root / "commented.md"
            commented.write_text(
                "---\nname: sample-skill # YAML comment\n---\n",
                encoding="utf-8",
            )
            self.assertEqual(
                read_frontmatter(commented).values["name"],
                "sample-skill",
            )

            malformed = root / "malformed.md"
            malformed.write_text(
                '---\nname: "sample-skill\n---\n',
                encoding="utf-8",
            )
            self.assertIn(
                "malformed-quoted-scalar",
                read_frontmatter(malformed).errors,
            )


class FingerprintTests(unittest.TestCase):
    def test_hash_file_stops_at_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.bin"
            path.write_bytes(b"x" * 1025)
            digest, size, partial = hash_file(path, limit=1024)
            self.assertIsNone(digest)
            self.assertEqual(size, 1025)
            self.assertTrue(partial)

    def test_hash_file_rejects_hard_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.bin"
            linked = root / "linked.bin"
            source.write_bytes(b"private")
            try:
                linked.hardlink_to(source)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")

            digest, size, partial = hash_file(linked)

            self.assertIsNone(digest)
            self.assertEqual(size, len(b"private"))
            self.assertTrue(partial)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs require POSIX")
    def test_hash_file_rejects_fifo_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "input"
            os.mkfifo(fifo)

            digest, _, partial = hash_file(fifo)

            self.assertIsNone(digest)
            self.assertTrue(partial)

    def test_tree_fingerprint_stops_reading_after_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "a.txt"
            second = root / "b.txt"
            first.write_bytes(b"aaaa")
            second.write_bytes(b"bbbb")
            original = metadata_module._read_regular_prefix
            opened: list[Path] = []

            def record_open(path: Path, limit: int) -> tuple[bytes | None, int, bool]:
                opened.append(path)
                return original(path, limit)

            with patch.object(
                metadata_module,
                "_read_regular_prefix",
                side_effect=record_open,
            ):
                fingerprint = fingerprint_tree(root, limit=4)

            self.assertEqual(opened, [first])
            self.assertEqual(fingerprint.files, 2)
            self.assertTrue(fingerprint.partial)

    def test_tree_fingerprint_stops_at_entry_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("a.txt", "b.txt", "c.txt"):
                (root / name).write_text(name, encoding="utf-8")

            fingerprint = fingerprint_tree(root, entry_limit=1)

            self.assertLessEqual(fingerprint.files, 1)
            self.assertTrue(fingerprint.partial)
            self.assertIsNone(fingerprint.digest)

    def test_ignores_python_cache(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            left = Path(first)
            right = Path(second)
            for root in (left, right):
                (root / "SKILL.md").write_text("same", encoding="utf-8")
            cache = right / "__pycache__"
            cache.mkdir()
            (cache / "generated.pyc").write_bytes(b"different")

            self.assertEqual(
                fingerprint_tree(left).digest,
                fingerprint_tree(right).digest,
            )

    def test_does_not_follow_directory_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            skill = base / "skill"
            outside = base / "outside"
            skill.mkdir()
            outside.mkdir()
            (skill / "SKILL.md").write_text("safe", encoding="utf-8")
            (outside / "secret.bin").write_bytes(b"x" * 1024)
            link = skill / "linked"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")

            fingerprint = fingerprint_tree(skill)
            self.assertEqual(fingerprint.files, 1)
            self.assertEqual(fingerprint.bytes, 4)
            self.assertEqual(fingerprint.symlinks, 1)
            self.assertTrue(fingerprint.partial)
            self.assertIsNone(fingerprint.digest)


if __name__ == "__main__":
    unittest.main()
