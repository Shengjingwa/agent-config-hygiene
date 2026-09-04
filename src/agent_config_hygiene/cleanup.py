from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .fs_safety import (
    is_linklike,
    owned_by_current_principal,
    safe_display_text,
)
from .state import is_owned_directory, verify_state_root

CLEANUP_ENTRY_LIMIT = 200_000


@dataclass(frozen=True)
class CleanupCandidate:
    path: Path
    display_path: str
    reason: str
    bytes: int
    device: int
    inode: int
    modified_ns: int

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.display_path,
            "reason": self.reason,
            "bytes": self.bytes,
        }


@dataclass(frozen=True)
class CleanupPlan:
    state_verified: bool
    candidates: tuple[CleanupCandidate, ...]
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "state_verified": self.state_verified,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "errors": list(self.errors),
            "total_bytes": sum(candidate.bytes for candidate in self.candidates),
        }


def _has_owned_parent_chain(path: Path, root: Path) -> bool:
    try:
        relative_parent = path.parent.relative_to(root)
    except ValueError:
        return False
    current = root
    for part in relative_parent.parts:
        current /= part
        if not is_owned_directory(current):
            return False
    return True


def plan_cleanup(root: Path, retention_days: int) -> CleanupPlan:
    if not 7 <= retention_days <= 3650:
        raise ValueError("retention_days must be between 7 and 3650")
    if not root.exists():
        return CleanupPlan(state_verified=False, candidates=(), errors=("state-not-created",))
    if not verify_state_root(root):
        return CleanupPlan(
            state_verified=False,
            candidates=(),
            errors=("state-ownership-unverified",),
        )

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    candidates: list[CleanupCandidate] = []
    errors: list[str] = []
    for directory_name in ("reports", "tmp", "quarantine"):
        directory = root / directory_name
        if not os.path.lexists(directory):
            continue
        if is_linklike(directory):
            errors.append(f"symlink-directory:{directory_name}")
            continue
        if not is_owned_directory(directory):
            errors.append(f"unsafe-directory:{directory_name}")
            continue

        pending = [directory]
        entries_seen = 0
        stop = False
        while pending and not stop:
            current = pending.pop()
            try:
                iterator = os.scandir(current)
                with iterator:
                    for raw_entry in iterator:
                        entries_seen += 1
                        if entries_seen > CLEANUP_ENTRY_LIMIT:
                            errors.append(f"entry-limit-reached:{directory_name}")
                            stop = True
                            break
                        entry = Path(raw_entry.path)
                        if is_linklike(entry):
                            errors.append(f"unsafe-entry:{directory_name}")
                            continue
                        try:
                            metadata = entry.lstat()
                        except (OSError, PermissionError):
                            errors.append(f"unreadable-entry:{directory_name}")
                            continue
                        if stat.S_ISDIR(metadata.st_mode):
                            if is_owned_directory(entry):
                                pending.append(entry)
                            else:
                                errors.append(f"unsafe-directory:{directory_name}")
                            continue
                        if (
                            not stat.S_ISREG(metadata.st_mode)
                            or metadata.st_nlink != 1
                            or not owned_by_current_principal(entry)
                        ):
                            errors.append(f"unsafe-entry:{directory_name}")
                            continue
                        modified = datetime.fromtimestamp(
                            metadata.st_mtime,
                            tz=timezone.utc,
                        )
                        if modified >= cutoff:
                            continue
                        candidates.append(
                            CleanupCandidate(
                                path=entry,
                                display_path="<state>/"
                                + safe_display_text(entry.relative_to(root).as_posix()),
                                reason=(f"owned-{directory_name}-retention"),
                                bytes=metadata.st_size,
                                device=metadata.st_dev,
                                inode=metadata.st_ino,
                                modified_ns=metadata.st_mtime_ns,
                            )
                        )
            except (OSError, PermissionError):
                errors.append(f"unreadable-directory:{directory_name}")
    return CleanupPlan(
        state_verified=True,
        candidates=tuple(candidates),
        errors=tuple(sorted(set(errors))),
    )


def apply_cleanup(root: Path, plan: CleanupPlan) -> dict[str, object]:
    if not plan.state_verified or not verify_state_root(root):
        raise RuntimeError("Refusing cleanup because state ownership is not verified")
    if plan.errors:
        raise RuntimeError("Refusing cleanup because the plan contains safety errors")
    removed: list[str] = []
    skipped: list[str] = []
    root_resolved = root.resolve(strict=True)

    for candidate in plan.candidates:
        try:
            candidate.path.resolve(strict=True).relative_to(root_resolved)
            metadata = candidate.path.lstat()
        except (OSError, ValueError):
            skipped.append(candidate.display_path)
            continue
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
        )
        expected = (
            candidate.device,
            candidate.inode,
            candidate.bytes,
            candidate.modified_ns,
        )
        if (
            identity != expected
            or is_linklike(candidate.path)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or not owned_by_current_principal(candidate.path)
            or not _has_owned_parent_chain(candidate.path, root)
        ):
            skipped.append(candidate.display_path)
            continue
        candidate.path.unlink()
        removed.append(candidate.display_path)

    return {
        "removed": removed,
        "skipped": skipped,
        "bytes_removed": sum(
            candidate.bytes for candidate in plan.candidates if candidate.display_path in removed
        ),
    }
