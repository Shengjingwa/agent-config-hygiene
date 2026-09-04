from __future__ import annotations

import json
import os
import stat
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, BinaryIO

from .fs_safety import (
    first_linklike_component,
    is_linklike,
    owned_by_current_principal,
)
from .metadata import read_bounded_regular

OWNER_MARKER = "agent-config-hygiene-state-v1\n"


def is_owned_regular_file(path: Path) -> bool:
    if is_linklike(path):
        return False
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and owned_by_current_principal(path)
        and (os.name == "nt" or metadata.st_mode & 0o022 == 0)
    )


def is_owned_directory(path: Path) -> bool:
    if is_linklike(path):
        return False
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and owned_by_current_principal(path)
        and (os.name == "nt" or metadata.st_mode & 0o022 == 0)
    )


def canonical_state_root(path: Path) -> Path:
    lexical = Path(os.path.abspath(path.expanduser()))
    if first_linklike_component(lexical, Path(lexical.anchor)) is not None:
        raise RuntimeError(f"State root cannot contain a symlink: {lexical}")
    return lexical.resolve(strict=False)


def state_root(home: Path | None = None) -> Path:
    override = os.environ.get("ACH_STATE_DIR")
    if override:
        return canonical_state_root(Path(override))
    base = home or Path.home()
    return canonical_state_root(base / ".agent-config-hygiene")


def ensure_state_root(root: Path) -> None:
    root = canonical_state_root(root)
    if first_linklike_component(root, Path(root.anchor)) is not None:
        raise RuntimeError(f"State root cannot be a symlink: {root}")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not is_owned_directory(root):
        raise RuntimeError(f"State root is not an owned safe directory: {root}")
    marker = root / ".owner"
    if os.path.lexists(marker):
        if not is_owned_regular_file(marker) or read_bounded_regular(
            marker, 128
        ) != OWNER_MARKER.encode("utf-8"):
            raise RuntimeError(f"State ownership marker is invalid: {marker}")
        return
    try:
        iterator = os.scandir(root)
        with iterator:
            has_entries = next(iterator, None) is not None
    except OSError as exc:
        raise RuntimeError(f"Unable to inspect unowned state root: {root}") from exc
    if has_entries:
        raise RuntimeError("Refusing to adopt a non-empty directory as tool-owned state")
    try:
        descriptor = os.open(
            marker,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
    except FileExistsError as exc:
        raise RuntimeError(f"State ownership marker appeared concurrently: {marker}") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(OWNER_MARKER)
        handle.flush()
        os.fsync(handle.fileno())


def verify_state_root(root: Path) -> bool:
    root = canonical_state_root(root)
    if first_linklike_component(root, Path(root.anchor)) is not None:
        return False
    marker = root / ".owner"
    if not is_owned_directory(root) or not is_owned_regular_file(marker):
        return False
    try:
        return read_bounded_regular(marker, 128) == OWNER_MARKER.encode("utf-8")
    except OSError:
        return False


def ensure_state_subdirectory(root: Path, name: str) -> Path:
    if not name or Path(name).name != name:
        raise ValueError("State subdirectory name must be one path component")
    if not verify_state_root(root):
        raise RuntimeError("State ownership is not verified")
    directory = root / name
    if os.path.lexists(directory):
        if not is_owned_directory(directory):
            raise RuntimeError(f"Unsafe state subdirectory: {directory}")
        return directory
    directory.mkdir()
    if not is_owned_directory(directory):
        raise RuntimeError(f"Unsafe state subdirectory: {directory}")
    return directory


def write_json(path: Path, payload: dict[str, Any]) -> None:
    from .reporting import write_atomic

    write_atomic(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


class RunLock(AbstractContextManager["RunLock"]):
    def __init__(self, root: Path) -> None:
        self.path = root / "run.lock"
        self._handle: BinaryIO | None = None

    def __enter__(self) -> RunLock:
        if is_linklike(self.path):
            raise RuntimeError(f"Run lock cannot be a symlink: {self.path}")
        flags = os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(
                self.path,
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            try:
                descriptor = os.open(self.path, flags)
            except OSError as exc:
                raise RuntimeError(f"Unable to open hygiene run lock: {self.path}") from exc
        except OSError as exc:
            raise RuntimeError(f"Unable to open hygiene run lock: {self.path}") from exc

        handle = os.fdopen(descriptor, "r+b", buffering=0)
        try:
            opened = os.fstat(descriptor)
            linked = self.path.lstat()
            if is_linklike(self.path) or (
                opened.st_dev,
                opened.st_ino,
            ) != (
                linked.st_dev,
                linked.st_ino,
            ):
                raise OSError("Run lock path changed while opening")
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or not owned_by_current_principal(self.path)
                or (os.name != "nt" and opened.st_mode & 0o022 != 0)
                or opened.st_size not in {0, 1}
            ):
                raise OSError("Run lock is not an owned regular file")
            handle.seek(0)
        except OSError as exc:
            handle.close()
            raise RuntimeError(f"Unsafe hygiene run lock: {self.path}") from exc

        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as exc:
            handle.close()
            raise RuntimeError(f"Another hygiene run may be active: {self.path}") from exc

        try:
            handle.seek(0)
            locked = os.fstat(descriptor)
            if locked.st_size == 0:
                handle.write(b"\0")
                handle.flush()
            elif locked.st_size != 1 or handle.read(1) != b"\0":
                raise OSError("Run lock has invalid contents")
            handle.seek(0)
        except OSError as exc:
            handle.close()
            raise RuntimeError(f"Unsafe hygiene run lock: {self.path}") from exc

        self._handle = handle
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._handle is None:
            return
        descriptor = self._handle.fileno()
        try:
            self._handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            self._handle.close()
            self._handle = None
