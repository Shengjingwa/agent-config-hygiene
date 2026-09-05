from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent_config_hygiene.fs_safety import (
    current_principal_identifiers,
    first_linklike_component,
    is_linklike,
    safe_display_text,
)


class FileSystemSafetyTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows token test")
    def test_principal_identifiers_ignore_spoofed_environment(self) -> None:
        expected = current_principal_identifiers()
        with patch.dict(
            os.environ,
            {
                "USERNAME": "SYSTEM",
                "USERDOMAIN": "NT AUTHORITY",
            },
        ):
            identifiers = current_principal_identifiers()
        self.assertEqual(identifiers, expected)

    def test_display_escaping_is_injective_for_literal_escape_text(self) -> None:
        self.assertNotEqual(
            safe_display_text("\n"),
            safe_display_text(r"\u000a"),
        )
        self.assertNotEqual(
            safe_display_text("\U0001fffe"),
            safe_display_text("\x01fffe"),
        )

    def test_windows_junction_is_treated_as_linklike(self) -> None:
        with (
            patch.object(Path, "is_symlink", return_value=False),
            patch(
                "agent_config_hygiene.fs_safety.os.path.isjunction",
                return_value=True,
                create=True,
            ),
        ):
            self.assertTrue(is_linklike(Path("junction")))

    def test_windows_reparse_fallback_supports_old_python(self) -> None:
        candidate = Path("junction")
        with (
            patch.object(Path, "is_symlink", return_value=False),
            patch(
                "agent_config_hygiene.fs_safety.os.path.isjunction",
                return_value=False,
                create=True,
            ),
            patch(
                "agent_config_hygiene.fs_safety.os.name",
                "nt",
            ),
            patch.object(
                Path,
                "lstat",
                return_value=SimpleNamespace(st_file_attributes=0x400),
            ),
        ):
            self.assertTrue(is_linklike(candidate))

    def test_platform_temp_root_alias_is_not_a_user_link_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "state"
            self.assertIsNone(
                first_linklike_component(
                    candidate,
                    Path(candidate.anchor),
                )
            )


if __name__ == "__main__":
    unittest.main()
