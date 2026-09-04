from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .fs_safety import is_linklike

FRONTMATTER_LIMIT = 64 * 1024
HASH_FILE_LIMIT = 4 * 1024 * 1024
HASH_TREE_LIMIT = 32 * 1024 * 1024
SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
KEY_RE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9_-]*):(?:\s*(?P<value>.*))?$")
SKIP_DIRECTORIES = {".git", ".hg", ".svn", ".venv", "node_modules", "__pycache__"}


@dataclass(frozen=True)
class Frontmatter:
    values: dict[str, str]
    errors: tuple[str, ...]
    bytes_read: int
    file_bytes: int
    lines: int


@dataclass(frozen=True)
class TreeFingerprint:
    digest: str | None
    files: int
    bytes: int
    partial: bool
    symlinks: int


def stable_id(*parts: str) -> str:
    payload = "\0".join(parts).encode("utf-8", errors="surrogatepass")
    return hashlib.sha256(payload).hexdigest()[:16]


def _read_regular_prefix(
    path: Path,
    limit: int,
) -> tuple[bytes | None, int, bool]:
    if limit < 0:
        raise ValueError("read limit cannot be negative")
    try:
        before = path.lstat()
    except (OSError, PermissionError):
        return None, 0, True
    if is_linklike(path) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        return None, before.st_size, True

    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOINHERIT"):
        flags |= os.O_NOINHERIT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except (OSError, PermissionError):
        return None, 0, True
    try:
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(descriptor)
            try:
                linked = path.lstat()
            except (OSError, PermissionError):
                return None, opened.st_size, True
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or is_linklike(path)
                or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or (opened.st_dev, opened.st_ino) != (linked.st_dev, linked.st_ino)
            ):
                return None, opened.st_size, True
            payload = handle.read(limit)
            after = os.fstat(descriptor)
            changed = (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_mtime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            )
            expected_bytes = min(opened.st_size, limit)
            partial = opened.st_size > limit or len(payload) != expected_bytes or changed
            return payload, opened.st_size, partial
    except (OSError, PermissionError):
        return None, 0, True


def read_bounded_regular(path: Path, limit: int) -> bytes | None:
    payload, _, partial = _read_regular_prefix(path, limit)
    return None if partial else payload


def iso_mtime(path: Path) -> str | None:
    try:
        timestamp = path.lstat().st_mtime
    except OSError:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def read_frontmatter(path: Path, limit: int = FRONTMATTER_LIMIT) -> Frontmatter:
    errors: list[str] = []
    payload, file_bytes, truncated = _read_regular_prefix(path, limit)
    if payload is None:
        return Frontmatter({}, ("unreadable",), 0, file_bytes, 0)
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        return Frontmatter({}, ("not-utf8",), len(payload), file_bytes, 0)

    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return Frontmatter(
            {},
            ("missing-frontmatter",),
            len(payload),
            file_bytes,
            len(lines),
        )

    closing_index: int | None = None
    for index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            closing_index = index
            break
    if closing_index is None:
        errors.append("frontmatter-not-closed")
        if truncated:
            errors.append("frontmatter-over-limit")
        return Frontmatter(
            {},
            tuple(errors),
            len(payload),
            file_bytes,
            len(lines),
        )

    values: dict[str, str] = {}
    for line in lines[1:closing_index]:
        if not line or line[0].isspace() or line.lstrip().startswith("#"):
            continue
        match = KEY_RE.match(line)
        if not match:
            errors.append("unsupported-frontmatter-line")
            continue
        key = match.group("key")
        value = (match.group("value") or "").strip()
        if value.startswith(("'", '"')) or value.endswith(("'", '"')):
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            else:
                errors.append("malformed-quoted-scalar")
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
        if key in values:
            errors.append("duplicate-key")
            continue
        values[key] = value

    return Frontmatter(
        values,
        tuple(sorted(set(errors))),
        len(payload),
        file_bytes,
        len(lines),
    )


def validate_skill_frontmatter(
    frontmatter: Frontmatter, directory_name: str
) -> tuple[str | None, tuple[str, ...]]:
    errors = list(frontmatter.errors)
    name = frontmatter.values.get("name", "").strip()
    if not name:
        errors.append("missing-name")
        normalized_name: str | None = None
    else:
        normalized_name = None
        if len(name) > 64:
            errors.append("name-too-long")
        elif not SKILL_NAME_RE.fullmatch(name):
            errors.append("invalid-name")
        else:
            normalized_name = name
        if name != directory_name:
            errors.append("name-directory-mismatch")

    description = frontmatter.values.get("description")
    if description is None:
        errors.append("missing-description")
    elif len(description) > 1024:
        errors.append("description-too-long")

    return normalized_name, tuple(sorted(set(errors)))


def validate_rule_frontmatter(frontmatter: Frontmatter) -> tuple[str, ...]:
    errors = list(frontmatter.errors)
    always_apply = frontmatter.values.get("alwaysApply")
    if always_apply is not None and always_apply.lower() not in {"true", "false"}:
        errors.append("alwaysApply-not-boolean")
    return tuple(sorted(set(errors)))


def hash_file(path: Path, limit: int = HASH_FILE_LIMIT) -> tuple[str | None, int, bool]:
    payload, size, partial = _read_regular_prefix(path, limit)
    if payload is None or partial:
        return None, size, True
    return hashlib.sha256(payload).hexdigest(), size, False


def fingerprint_tree(
    path: Path,
    limit: int = HASH_TREE_LIMIT,
    entry_limit: int = 100_000,
) -> TreeFingerprint:
    digest = hashlib.sha256()
    file_count = 0
    byte_count = 0
    symlink_count = 0
    partial = False
    entries_seen = 0

    def record_symlink(entry: Path) -> None:
        nonlocal partial, symlink_count
        partial = True
        try:
            target = os.readlink(entry)
        except (OSError, PermissionError):
            partial = True
            return
        symlink_count += 1
        digest.update(b"link:")
        digest.update(entry.relative_to(path).as_posix().encode("utf-8", errors="surrogatepass"))
        digest.update(target.encode("utf-8", errors="surrogatepass"))

    pending = [path]
    stop = False
    while pending and not stop:
        current = pending.pop()
        entries: list[os.DirEntry[str]] = []
        try:
            iterator = os.scandir(current)
            with iterator:
                for raw_entry in iterator:
                    entries_seen += 1
                    if entries_seen > entry_limit:
                        partial = True
                        stop = True
                        break
                    entries.append(raw_entry)
        except (OSError, PermissionError):
            partial = True
            continue

        child_directories: list[Path] = []
        for raw_entry in sorted(entries, key=lambda item: item.name):
            entry = Path(raw_entry.path)
            if is_linklike(entry):
                record_symlink(entry)
                continue
            try:
                metadata = raw_entry.stat(follow_symlinks=False)
            except (OSError, PermissionError):
                partial = True
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if raw_entry.name not in SKIP_DIRECTORIES:
                    child_directories.append(entry)
                continue
            remaining = max(0, min(HASH_FILE_LIMIT, limit - byte_count))
            if remaining == 0:
                file_count += 1
                byte_count += metadata.st_size
                partial = True
                continue
            file_hash, size, file_partial = hash_file(entry, remaining)
            file_count += 1
            byte_count += size
            if file_hash is None or file_partial:
                partial = True
                continue
            digest.update(
                entry.relative_to(path).as_posix().encode("utf-8", errors="surrogatepass")
            )
            digest.update(b"\0")
            digest.update(file_hash.encode("ascii"))
            digest.update(b"\0")
        pending.extend(reversed(child_directories))

    return TreeFingerprint(
        digest=None if partial else digest.hexdigest(),
        files=file_count,
        bytes=byte_count,
        partial=partial,
        symlinks=symlink_count,
    )


def state_metadata(
    path: Path,
    entry_limit: int = 200_000,
) -> tuple[int, int, str | None, bool, int, int]:
    files = 0
    bytes_total = 0
    newest: float | None = None
    partial = False
    links_skipped = 0
    entries_seen = 0
    try:
        root_metadata = path.lstat()
    except (OSError, PermissionError):
        return (
            files,
            bytes_total,
            None,
            partial,
            links_skipped,
            entries_seen,
        )
    if is_linklike(path) or not stat.S_ISDIR(root_metadata.st_mode):
        return files, bytes_total, None, True, links_skipped, entries_seen

    pending = [path]
    stop = False
    while pending and not stop:
        current = pending.pop()
        try:
            iterator = os.scandir(current)
            with iterator:
                for raw_entry in iterator:
                    entries_seen += 1
                    if entries_seen > entry_limit:
                        partial = True
                        stop = True
                        break
                    entry = Path(raw_entry.path)
                    if is_linklike(entry):
                        links_skipped += 1
                        partial = True
                        continue
                    try:
                        metadata = raw_entry.stat(follow_symlinks=False)
                    except (OSError, PermissionError):
                        partial = True
                        continue
                    if stat.S_ISDIR(metadata.st_mode):
                        pending.append(entry)
                        continue
                    if not stat.S_ISREG(metadata.st_mode):
                        partial = True
                        continue
                    files += 1
                    bytes_total += metadata.st_size
                    newest = metadata.st_mtime if newest is None else max(newest, metadata.st_mtime)
        except (OSError, PermissionError):
            partial = True

    modified = (
        datetime.fromtimestamp(newest, tz=timezone.utc).isoformat() if newest is not None else None
    )
    return (
        files,
        bytes_total,
        modified,
        partial,
        links_skipped,
        entries_seen,
    )


def is_external_symlink(path: Path, allowed_root: Path) -> bool:
    if not is_linklike(path):
        return False
    try:
        resolved = path.resolve(strict=False)
        root = allowed_root.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return True
    return False
