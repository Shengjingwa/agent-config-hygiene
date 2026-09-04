from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from importlib.resources import files
from pathlib import Path

from .fs_safety import first_linklike_component, is_linklike
from .metadata import HASH_FILE_LIMIT, hash_file

SKILL_NAME = "agent-config-hygiene"
TARGET_DIRECTORIES = {
    "cursor": ".cursor/skills",
    "claude": ".claude/skills",
    "codex": ".agents/skills",
}
COMPATIBLE_DIRECTORIES = (
    ".cursor/skills",
    ".agents/skills",
    ".claude/skills",
    ".codex/skills",
)


def _resource_skill_file() -> object:
    return files("agent_config_hygiene") / "resources" / "skill" / SKILL_NAME / "SKILL.md"


def _hash(path: Path) -> str | None:
    digest, _, partial = hash_file(path, HASH_FILE_LIMIT)
    return None if partial else digest


def target_root(
    *,
    target: str,
    scope: str,
    home: Path,
    project: Path | None,
) -> Path:
    if target not in TARGET_DIRECTORIES:
        raise ValueError(f"Unsupported Skill target: {target}")
    if scope == "user":
        if not home.is_dir():
            raise ValueError(f"Home directory does not exist: {home}")
        return home / TARGET_DIRECTORIES[target]
    if scope == "project":
        if project is None or not project.is_dir():
            raise ValueError("--project is required for project-scoped installation")
        return project / TARGET_DIRECTORIES[target]
    raise ValueError(f"Unsupported Skill scope: {scope}")


def find_existing(
    *,
    scope: str,
    home: Path,
    project: Path | None,
) -> list[Path]:
    base = home if scope == "user" else project
    if base is None:
        return []
    return [
        base / relative / SKILL_NAME
        for relative in COMPATIBLE_DIRECTORIES
        if (base / relative / SKILL_NAME / "SKILL.md").is_file()
    ]


def plan_install(
    *,
    target: str,
    scope: str,
    home: Path,
    project: Path | None,
) -> dict[str, object]:
    destination = (
        target_root(
            target=target,
            scope=scope,
            home=home,
            project=project,
        )
        / SKILL_NAME
    )
    existing = find_existing(scope=scope, home=home, project=project)
    base = home if scope == "user" else project
    assert base is not None
    return {
        "target": target,
        "scope": scope,
        "destination": _display(destination, base, scope),
        "existing": [_display(path, base, scope) for path in existing],
        "would_create_multipath": any(
            path.resolve(strict=False) != destination.resolve(strict=False) for path in existing
        ),
        "apply": False,
    }


def install(
    *,
    target: str,
    scope: str,
    home: Path,
    project: Path | None,
    allow_multipath: bool,
) -> dict[str, object]:
    plan = plan_install(target=target, scope=scope, home=home, project=project)
    if plan["would_create_multipath"] and not allow_multipath:
        raise RuntimeError(
            "Refusing to create a multi-root Skill copy. Remove or archive the "
            "existing copy first, or pass --allow-multipath after reviewing Cursor "
            "compatibility discovery."
        )

    destination = (
        target_root(
            target=target,
            scope=scope,
            home=home,
            project=project,
        )
        / SKILL_NAME
    )
    if is_linklike(destination):
        raise RuntimeError(f"Refusing to replace a symlink destination: {destination}")
    base = home if scope == "user" else project
    assert base is not None
    _reject_symlink_components(base, destination.parent)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(base, destination.parent)

    source_payload = _resource_skill_file().read_bytes()
    source_hash = hashlib.sha256(source_payload).hexdigest()
    destination_skill = destination / "SKILL.md"
    if destination.exists():
        if not destination.is_dir() or is_linklike(destination_skill):
            raise RuntimeError(f"Unsafe existing Skill destination: {destination}")
        try:
            iterator = os.scandir(destination)
            with iterator:
                entries = []
                first = next(iterator, None)
                second = next(iterator, None)
                if first is not None:
                    entries.append(Path(first.path))
                if second is not None:
                    entries.append(Path(second.path))
        except OSError as exc:
            raise RuntimeError(
                f"Unable to inspect existing Skill destination: {destination}"
            ) from exc
        if (
            entries == [destination_skill]
            and stat.S_ISREG(destination_skill.lstat().st_mode)
            and destination_skill.lstat().st_nlink == 1
            and source_hash == _hash(destination_skill)
        ):
            return {**plan, "apply": True, "changed": False}
        raise RuntimeError(
            "A different Skill already exists at the destination; archive or "
            "review it manually before installation."
        )
    skills_parent = destination.parent
    created_parent = skills_parent.lstat()

    def parent_unchanged() -> bool:
        try:
            current = skills_parent.lstat()
        except OSError:
            return False
        return not is_linklike(skills_parent) and (
            created_parent.st_dev,
            created_parent.st_ino,
        ) == (
            current.st_dev,
            current.st_ino,
        )

    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{SKILL_NAME}-install-",
            dir=skills_parent.parent,
        )
    )
    staging_metadata = staging.lstat()
    staging_skill = staging / "SKILL.md"
    try:
        descriptor = os.open(
            staging_skill,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(source_payload)
            handle.flush()
            os.fsync(handle.fileno())
        _reject_symlink_components(base, skills_parent)
        if not parent_unchanged() or os.path.lexists(destination):
            raise RuntimeError("Skill destination changed during installation")
        os.rename(staging, destination)
        staging = None
    except Exception:
        if staging is not None and os.path.lexists(staging):
            try:
                current = staging.lstat()
                if not is_linklike(staging) and (current.st_dev, current.st_ino) == (
                    staging_metadata.st_dev,
                    staging_metadata.st_ino,
                ):
                    staging_skill.unlink(missing_ok=True)
                    staging.rmdir()
            except OSError:
                pass
        raise

    return {**plan, "apply": True, "changed": True}


def _display(path: Path, base: Path, scope: str) -> str:
    prefix = "~" if scope == "user" else "<repo>"
    try:
        return (
            prefix
            + "/"
            + Path(os.path.abspath(path)).relative_to(Path(os.path.abspath(base))).as_posix()
        )
    except ValueError:
        return "<external>"


def _reject_symlink_components(base: Path, target: Path) -> None:
    base = Path(os.path.abspath(base))
    target = Path(os.path.abspath(target))
    try:
        relative = target.relative_to(base)
    except ValueError as exc:
        raise RuntimeError("Skill destination escapes its declared scope") from exc
    linked_ancestor = first_linklike_component(base, Path(base.anchor))
    if linked_ancestor is not None:
        raise RuntimeError(f"Skill destination contains a symlink: {linked_ancestor}")
    current = base
    for part in relative.parts:
        current = current / part
        if os.path.lexists(current) and is_linklike(current):
            raise RuntimeError(f"Skill destination contains a symlink: {current}")
