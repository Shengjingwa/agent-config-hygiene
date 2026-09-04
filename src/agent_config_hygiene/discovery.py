from __future__ import annotations

import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path

from .fs_safety import first_linklike_component, is_linklike, safe_display_text
from .metadata import (
    fingerprint_tree,
    is_external_symlink,
    iso_mtime,
    read_frontmatter,
    stable_id,
    state_metadata,
    validate_rule_frontmatter,
    validate_skill_frontmatter,
)
from .model import Artifact, Coverage

PROVIDERS = ("cursor", "claude", "codex")
AGENT_DIRECTORIES = {".cursor", ".agents", ".claude", ".codex"}
PROJECT_SKILL_ROUTES = {
    ".cursor": ("cursor:project:native",),
    ".agents": ("cursor:project:compatible-agents", "codex:project:native"),
    ".claude": ("cursor:project:compatible-claude", "claude:project:native"),
    ".codex": ("cursor:project:compatible-codex", "codex:project:legacy"),
}
WALK_SKIP = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
}
DISCOVERY_ENTRY_LIMIT = 100_000


def _path_kind(path: Path) -> str:
    if is_linklike(path):
        return "link"
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return "missing"
    except (OSError, PermissionError):
        return "unreadable"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    return "other"


@dataclass(frozen=True)
class DiscoveryRequest:
    home: Path
    projects: tuple[Path, ...]
    providers: tuple[str, ...] = PROVIDERS
    include_user: bool = False
    max_project_directories: int = 20_000
    max_project_entries: int = 200_000


@dataclass(frozen=True)
class SkillRoot:
    path: Path
    boundary_root: Path
    allowed_root: Path
    routes: tuple[str, ...]
    scope: str
    anchor: str
    display_root: str
    managed_names: tuple[str, ...] = ()


def _selected_routes(providers: tuple[str, ...], candidates: Iterable[str]) -> tuple[str, ...]:
    selected = set(providers)
    return tuple(sorted(route for route in candidates if route.split(":", 1)[0] in selected))


def _safe_files(
    root: Path,
    pattern: str,
    *,
    recursive: bool,
    entry_limit: int = DISCOVERY_ENTRY_LIMIT,
) -> tuple[list[Path], bool, list[Path]]:
    files: list[Path] = []
    symlink_directories: list[Path] = []
    partial = False
    entries_seen = 0
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            iterator = os.scandir(current)
        except (OSError, PermissionError):
            partial = True
            continue
        try:
            with iterator:
                for raw_entry in iterator:
                    entries_seen += 1
                    if entries_seen > entry_limit:
                        partial = True
                        pending.clear()
                        break
                    entry = Path(raw_entry.path)
                    if is_linklike(entry):
                        if fnmatch(raw_entry.name, pattern):
                            files.append(entry)
                        elif recursive:
                            symlink_directories.append(entry)
                        continue
                    try:
                        metadata = raw_entry.stat(follow_symlinks=False)
                    except (OSError, PermissionError):
                        partial = True
                        continue
                    if stat.S_ISDIR(metadata.st_mode):
                        if recursive:
                            pending.append(entry)
                    elif fnmatch(raw_entry.name, pattern):
                        files.append(entry)
        except (OSError, PermissionError):
            partial = True
    return sorted(files), partial, sorted(symlink_directories)


def _display_path(path: Path, *, home: Path, project: Path | None = None) -> str:
    lexical_path = Path(os.path.abspath(path))
    try:
        if project is not None:
            relative = lexical_path.relative_to(Path(os.path.abspath(project)))
            return (
                "<repo>"
                if relative == Path(".")
                else "<repo>/" + safe_display_text(relative.as_posix())
            )
    except (OSError, ValueError):
        pass
    try:
        relative = lexical_path.relative_to(Path(os.path.abspath(home)))
        return "~" if relative == Path(".") else "~/" + safe_display_text(relative.as_posix())
    except (OSError, ValueError):
        return "<external>/" + stable_id(str(lexical_path))


def _artifact_id(
    kind: str,
    scope: str,
    anchor: str,
    display_path: str,
    routes: tuple[str, ...],
) -> str:
    return stable_id(kind, scope, anchor, display_path, *routes)


def _discovery_boundary(
    path: Path,
    *,
    routes: tuple[str, ...],
    scope: str,
    anchor: str,
    home: Path,
    project: Path | None,
    reason: str | tuple[str, ...],
    allowed_root: Path,
) -> Artifact:
    display = _display_path(path, home=home, project=project)
    reasons = (reason,) if isinstance(reason, str) else reason
    return Artifact(
        artifact_id=_artifact_id("discovery-boundary", scope, anchor, display, routes),
        kind="discovery-boundary",
        scope=scope,
        scope_anchor=anchor,
        display_path=display,
        routes=routes,
        path=path,
        metadata_valid=False,
        metadata_errors=reasons,
        modified_at=iso_mtime(path),
        managed=True,
        symlink=is_linklike(path),
        external_target=is_external_symlink(path, allowed_root),
        coverage=Coverage.PARTIAL,
    )


def _discover_skill_root(
    spec: SkillRoot,
    *,
    home: Path,
    project: Path | None,
) -> list[Artifact]:
    if not spec.routes:
        return []
    linked_ancestor = first_linklike_component(
        spec.path,
        spec.boundary_root,
    )
    if linked_ancestor is not None:
        return [
            _discovery_boundary(
                linked_ancestor,
                routes=spec.routes,
                scope=spec.scope,
                anchor=spec.anchor,
                home=home,
                project=project,
                reason="linked-ancestor-not-traversed",
                allowed_root=spec.allowed_root,
            )
        ]
    if not os.path.lexists(spec.path):
        return []
    if is_linklike(spec.path):
        return [
            _discovery_boundary(
                spec.path,
                routes=spec.routes,
                scope=spec.scope,
                anchor=spec.anchor,
                home=home,
                project=project,
                reason="symlink-root-not-traversed",
                allowed_root=spec.allowed_root,
            )
        ]
    if _path_kind(spec.path) != "directory":
        return [
            _discovery_boundary(
                spec.path,
                routes=spec.routes,
                scope=spec.scope,
                anchor=spec.anchor,
                home=home,
                project=project,
                reason="unsafe-skill-root",
                allowed_root=spec.allowed_root,
            )
        ]

    artifacts: list[Artifact] = []
    skill_files, partial, symlink_directories = _safe_files(spec.path, "SKILL.md", recursive=True)
    if partial:
        artifacts.append(
            _discovery_boundary(
                spec.path,
                routes=spec.routes,
                scope=spec.scope,
                anchor=spec.anchor,
                home=home,
                project=project,
                reason="unreadable-skill-root",
                allowed_root=spec.allowed_root,
            )
        )
    for symlink_directory in symlink_directories:
        artifacts.append(
            _discovery_boundary(
                symlink_directory,
                routes=spec.routes,
                scope=spec.scope,
                anchor=spec.anchor,
                home=home,
                project=project,
                reason="linked-skill-entry-not-read",
                allowed_root=spec.path,
            )
        )

    for skill_file in skill_files:
        if is_linklike(skill_file):
            artifacts.append(
                _discovery_boundary(
                    skill_file,
                    routes=spec.routes,
                    scope=spec.scope,
                    anchor=spec.anchor,
                    home=home,
                    project=project,
                    reason="symlink-skill-file-not-read",
                    allowed_root=spec.path,
                )
            )
            continue
        skill_dir = skill_file.parent
        relative_parts = skill_dir.relative_to(spec.path).parts
        managed = any(part in spec.managed_names for part in relative_parts)
        frontmatter = read_frontmatter(skill_file)
        name, errors = validate_skill_frontmatter(frontmatter, skill_dir.name)
        tree = fingerprint_tree(skill_dir)
        display = _display_path(skill_dir, home=home, project=project)
        try:
            realpath_id = stable_id(str(skill_dir.resolve(strict=False)))
        except OSError:
            realpath_id = stable_id(str(skill_dir.absolute()))
        external = is_external_symlink(skill_dir, spec.path)
        coverage = Coverage.PARTIAL if tree.partial else Coverage.SUPPORTED
        artifacts.append(
            Artifact(
                artifact_id=_artifact_id("skill", spec.scope, spec.anchor, display, spec.routes),
                kind="skill",
                scope=spec.scope,
                scope_anchor=spec.anchor,
                display_path=display,
                routes=spec.routes,
                path=skill_dir,
                name=name,
                metadata_valid=not errors,
                metadata_errors=errors,
                tree_hash=tree.digest,
                bytes=tree.bytes,
                files=tree.files,
                modified_at=iso_mtime(skill_dir),
                managed=managed,
                symlink=is_linklike(skill_dir),
                external_target=external,
                coverage=coverage,
                attributes={
                    "_realpath_id": realpath_id,
                    "symlinks_in_tree": tree.symlinks,
                    "source_root": spec.display_root,
                },
            )
        )
    return artifacts


def _discover_rule(
    path: Path,
    *,
    routes: tuple[str, ...],
    scope: str,
    anchor: str,
    home: Path,
    project: Path | None,
    boundary_root: Path | None = None,
    allowed_root: Path | None = None,
    kind: str = "rule",
    frontmatter_required: bool = True,
) -> Artifact:
    safety_root = boundary_root or project or path.parent
    containment_root = allowed_root or project or path.parent
    linked_ancestor = first_linklike_component(path, safety_root)
    if linked_ancestor is not None:
        return _discovery_boundary(
            linked_ancestor,
            routes=routes,
            scope=scope,
            anchor=anchor,
            home=home,
            project=project,
            reason="linked-ancestor-not-traversed",
            allowed_root=containment_root,
        )
    if is_linklike(path):
        return _discovery_boundary(
            path,
            routes=routes,
            scope=scope,
            anchor=anchor,
            home=home,
            project=project,
            reason="symlink-rule-file-not-read",
            allowed_root=containment_root,
        )
    display = _display_path(path, home=home, project=project)
    frontmatter = read_frontmatter(path)
    if frontmatter_required:
        errors = validate_rule_frontmatter(frontmatter)
    elif frontmatter.errors == ("missing-frontmatter",):
        errors = ()
    else:
        errors = validate_rule_frontmatter(frontmatter)
    bytes_total = frontmatter.file_bytes
    partial = "unreadable" in frontmatter.errors
    always_loaded = False
    if path.name in {"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md"}:
        always_loaded = True
    elif frontmatter.values.get("alwaysApply", "").lower() == "true":
        always_loaded = True
    elif (
        kind == "rule"
        and any(route.startswith("claude:") for route in routes)
        and "paths" not in frontmatter.values
    ):
        always_loaded = True
    return Artifact(
        artifact_id=_artifact_id(kind, scope, anchor, display, routes),
        kind=kind,
        scope=scope,
        scope_anchor=anchor,
        display_path=display,
        routes=routes,
        path=path,
        name=safe_display_text(path.stem),
        metadata_valid=not errors,
        metadata_errors=errors,
        content_hash=None,
        bytes=bytes_total,
        files=1,
        modified_at=iso_mtime(path),
        symlink=is_linklike(path),
        external_target=is_external_symlink(path, containment_root),
        coverage=Coverage.PARTIAL if partial else Coverage.SUPPORTED,
        attributes={
            "always_loaded": always_loaded,
            "frontmatter_lines": frontmatter.lines,
        },
    )


def _discover_rule_root(
    root: Path,
    *,
    pattern: str,
    recursive: bool,
    routes: tuple[str, ...],
    scope: str,
    anchor: str,
    home: Path,
    project: Path | None,
    boundary_root: Path | None = None,
    allowed_root: Path | None = None,
    kind: str = "rule",
    frontmatter_required: bool = True,
) -> list[Artifact]:
    safety_root = boundary_root or project or root.parent
    containment_root = allowed_root or project or root.parent
    linked_ancestor = first_linklike_component(root, safety_root)
    if linked_ancestor is not None:
        return [
            _discovery_boundary(
                linked_ancestor,
                routes=routes,
                scope=scope,
                anchor=anchor,
                home=home,
                project=project,
                reason="linked-ancestor-not-traversed",
                allowed_root=containment_root,
            )
        ]
    if not os.path.lexists(root):
        return []
    if is_linklike(root):
        return [
            _discovery_boundary(
                root,
                routes=routes,
                scope=scope,
                anchor=anchor,
                home=home,
                project=project,
                reason="symlink-rule-root-not-traversed",
                allowed_root=containment_root,
            )
        ]
    if _path_kind(root) != "directory":
        return [
            _discovery_boundary(
                root,
                routes=routes,
                scope=scope,
                anchor=anchor,
                home=home,
                project=project,
                reason="unsafe-rule-root",
                allowed_root=containment_root,
            )
        ]
    candidates, partial, symlink_directories = _safe_files(root, pattern, recursive=recursive)
    artifacts: list[Artifact] = []
    if partial:
        artifacts.append(
            _discovery_boundary(
                root,
                routes=routes,
                scope=scope,
                anchor=anchor,
                home=home,
                project=project,
                reason="unreadable-rule-root",
                allowed_root=containment_root,
            )
        )
    for symlink_directory in symlink_directories:
        artifacts.append(
            _discovery_boundary(
                symlink_directory,
                routes=routes,
                scope=scope,
                anchor=anchor,
                home=home,
                project=project,
                reason="linked-rule-entry-not-read",
                allowed_root=root,
            )
        )
    artifacts.extend(
        _discover_rule(
            path,
            routes=routes,
            scope=scope,
            anchor=anchor,
            home=home,
            project=project,
            boundary_root=safety_root,
            allowed_root=containment_root,
            kind=kind,
            frontmatter_required=frontmatter_required,
        )
        for path in candidates
    )
    return artifacts


def _discover_state(
    path: Path,
    *,
    kind: str,
    route: str,
    scope: str,
    anchor: str,
    home: Path,
    project: Path | None = None,
    boundary_root: Path | None = None,
    allowed_root: Path | None = None,
    managed: bool = True,
) -> Artifact | None:
    safety_root = boundary_root or project or path.parent
    containment_root = allowed_root or project or path.parent
    linked_ancestor = first_linklike_component(path, safety_root)
    if linked_ancestor is not None:
        return _discovery_boundary(
            linked_ancestor,
            routes=(route,),
            scope=scope,
            anchor=anchor,
            home=home,
            project=project,
            reason="linked-ancestor-not-traversed",
            allowed_root=containment_root,
        )
    if not os.path.lexists(path):
        return None
    if is_linklike(path):
        return _discovery_boundary(
            path,
            routes=(route,),
            scope=scope,
            anchor=anchor,
            home=home,
            project=project,
            reason="symlink-state-not-traversed",
            allowed_root=containment_root,
        )
    if _path_kind(path) != "directory":
        return _discovery_boundary(
            path,
            routes=(route,),
            scope=scope,
            anchor=anchor,
            home=home,
            project=project,
            reason="unsafe-state-root",
            allowed_root=containment_root,
        )
    (
        files,
        bytes_total,
        modified,
        partial,
        links_skipped,
        entries_scanned,
    ) = state_metadata(path)
    display = _display_path(path, home=home, project=project)
    return Artifact(
        artifact_id=_artifact_id(kind, scope, anchor, display, (route,)),
        kind=kind,
        scope=scope,
        scope_anchor=anchor,
        display_path=display,
        routes=(route,),
        path=path,
        bytes=bytes_total,
        files=files,
        modified_at=modified,
        metadata_errors=("nested-state-boundary",) if partial else (),
        managed=managed,
        symlink=is_linklike(path),
        external_target=is_external_symlink(path, containment_root),
        coverage=Coverage.PARTIAL if partial else Coverage.SENSITIVE_SKIPPED,
        attributes={
            "entries_scanned": entries_scanned,
            "links_skipped": links_skipped,
        },
    )


def _discover_state_group(
    paths: list[Path],
    *,
    root: Path,
    display_path: str,
    kind: str,
    route: str,
    scope: str,
    anchor: str,
) -> Artifact | None:
    existing = [path for path in paths if not is_linklike(path) and _path_kind(path) == "directory"]
    if not existing:
        return None
    files = 0
    bytes_total = 0
    modified_values: list[str] = []
    partial = False
    links_skipped = 0
    entries_scanned = 0
    for path in existing:
        remaining = 200_000 - entries_scanned
        if remaining <= 0:
            partial = True
            break
        (
            path_files,
            path_bytes,
            modified,
            path_partial,
            path_links,
            path_entries,
        ) = state_metadata(path, entry_limit=remaining)
        files += path_files
        bytes_total += path_bytes
        partial = partial or path_partial
        links_skipped += path_links
        entries_scanned += path_entries
        if modified:
            modified_values.append(modified)
    routes = (route,)
    return Artifact(
        artifact_id=_artifact_id(kind, scope, anchor, display_path, routes),
        kind=kind,
        scope=scope,
        scope_anchor=anchor,
        display_path=display_path,
        routes=routes,
        path=root,
        bytes=bytes_total,
        files=files,
        modified_at=max(modified_values, default=None),
        metadata_errors=("nested-state-boundary",) if partial else (),
        managed=True,
        coverage=Coverage.PARTIAL if partial else Coverage.SENSITIVE_SKIPPED,
        attributes={
            "entries_scanned": entries_scanned,
            "links_skipped": links_skipped,
        },
    )


def _user_skill_roots(request: DiscoveryRequest) -> list[SkillRoot]:
    home = Path(os.path.abspath(request.home.expanduser()))
    cursor_home = home / ".cursor"
    claude_home = Path(
        os.path.abspath(Path(os.environ.get("CLAUDE_CONFIG_DIR", home / ".claude")).expanduser())
    )
    codex_home = Path(
        os.path.abspath(Path(os.environ.get("CODEX_HOME", home / ".codex")).expanduser())
    )
    candidates = [
        (
            cursor_home / "skills",
            ("cursor:user:native",),
            (".system",),
            Path(cursor_home.anchor),
            home,
        ),
        (
            home / ".agents" / "skills",
            ("cursor:user:compatible-agents", "codex:user:native"),
            (".system",),
            Path(home.anchor),
            home,
        ),
        (
            claude_home / "skills",
            ("cursor:user:compatible-claude", "claude:user:native"),
            ("synced", ".system"),
            Path(claude_home.anchor),
            claude_home.parent,
        ),
        (
            codex_home / "skills",
            ("cursor:user:compatible-codex", "codex:user:legacy"),
            (".system",),
            Path(codex_home.anchor),
            codex_home.parent,
        ),
    ]
    roots: list[SkillRoot] = []
    for (
        path,
        routes,
        managed_names,
        boundary_root,
        allowed_root,
    ) in candidates:
        selected = _selected_routes(request.providers, routes)
        if selected:
            roots.append(
                SkillRoot(
                    path=path,
                    boundary_root=boundary_root,
                    allowed_root=allowed_root,
                    routes=selected,
                    scope="user",
                    anchor="<user>",
                    display_root=_display_path(path, home=home),
                    managed_names=managed_names,
                )
            )
    return roots


def _walk_project(
    project: Path,
    directory_limit: int,
    entry_limit: int,
) -> tuple[list[Path], list[Path], tuple[str, ...], list[Path]]:
    agent_directories: list[Path] = []
    instruction_files: list[Path] = []
    linked_subtrees: list[Path] = []
    visited = 0
    entries_seen = 0
    errors: set[str] = set()
    pending = [project]
    stop = False
    instruction_names = {
        "AGENTS.md",
        "AGENTS.override.md",
        "CLAUDE.md",
        "CLAUDE.local.md",
    }
    while pending and not stop:
        current = pending.pop()
        visited += 1
        if visited > directory_limit:
            errors.add("project-directory-limit-reached")
            break
        try:
            iterator = os.scandir(current)
            with iterator:
                for raw_entry in iterator:
                    entries_seen += 1
                    if entries_seen > entry_limit:
                        errors.add("project-entry-limit-reached")
                        stop = True
                        break
                    entry = Path(raw_entry.path)
                    if is_linklike(entry):
                        if raw_entry.name in AGENT_DIRECTORIES:
                            agent_directories.append(entry)
                        elif raw_entry.name in instruction_names:
                            instruction_files.append(entry)
                        elif raw_entry.name not in WALK_SKIP:
                            linked_subtrees.append(entry)
                        continue
                    try:
                        metadata = raw_entry.stat(follow_symlinks=False)
                    except (OSError, PermissionError):
                        errors.add("unreadable-project-entry")
                        continue
                    if stat.S_ISDIR(metadata.st_mode):
                        if raw_entry.name in AGENT_DIRECTORIES:
                            agent_directories.append(entry)
                        elif raw_entry.name not in WALK_SKIP:
                            pending.append(entry)
                    elif raw_entry.name in instruction_names:
                        instruction_files.append(entry)
        except (OSError, PermissionError):
            errors.add("unreadable-project-directory")
    return (
        agent_directories,
        instruction_files,
        tuple(sorted(errors)),
        linked_subtrees,
    )


def _project_skill_roots(
    request: DiscoveryRequest,
    project: Path,
    config_directories: list[Path],
    anchor: str,
) -> list[SkillRoot]:
    roots: list[SkillRoot] = []
    for config_dir in config_directories:
        if is_linklike(config_dir):
            continue
        routes = _selected_routes(request.providers, PROJECT_SKILL_ROUTES[config_dir.name])
        if not routes:
            continue
        skill_root = config_dir / "skills"
        roots.append(
            SkillRoot(
                path=skill_root,
                boundary_root=project,
                allowed_root=project,
                routes=routes,
                scope="project",
                anchor=anchor,
                display_root=_display_path(skill_root, home=request.home, project=project),
                managed_names=(".system", "synced"),
            )
        )
    return roots


def _discover_user(request: DiscoveryRequest) -> list[Artifact]:
    home = Path(os.path.abspath(request.home.expanduser()))
    artifacts: list[Artifact] = []
    cursor_home = home / ".cursor"
    claude_home = Path(
        os.path.abspath(Path(os.environ.get("CLAUDE_CONFIG_DIR", home / ".claude")).expanduser())
    )
    codex_home = Path(
        os.path.abspath(Path(os.environ.get("CODEX_HOME", home / ".codex")).expanduser())
    )

    for root in _user_skill_roots(request):
        artifacts.extend(_discover_skill_root(root, home=home, project=None))

    if "cursor" in request.providers:
        rules_root = cursor_home / "rules"
        artifacts.extend(
            _discover_rule_root(
                rules_root,
                pattern="*.mdc",
                recursive=True,
                routes=("cursor:user:rule",),
                scope="user",
                anchor="<user>",
                home=home,
                boundary_root=Path(cursor_home.anchor),
                allowed_root=home,
                project=None,
            )
        )
        artifacts.append(
            Artifact(
                artifact_id=stable_id("cursor", "opaque", "settings"),
                kind="opaque-state",
                scope="user",
                scope_anchor="<user>",
                display_path="<cursor-settings>",
                routes=("cursor:user:settings",),
                path=cursor_home,
                managed=True,
                coverage=Coverage.OPAQUE,
                attributes={"includes": ["personal-rules", "team-rules", "ide-memories"]},
            )
        )
        for state_path, kind in (
            (cursor_home / "skills-cursor", "managed-skills"),
            (cursor_home / "plugins" / "cache", "managed-plugin-cache"),
            (cursor_home / "projects", "managed-session-state"),
            (cursor_home / "chats", "managed-session-state"),
        ):
            artifact = _discover_state(
                state_path,
                kind=kind,
                route="cursor:user:managed",
                scope="user",
                anchor="<user>",
                home=home,
                boundary_root=Path(cursor_home.anchor),
                allowed_root=home,
            )
            if artifact:
                artifacts.append(artifact)

    if "claude" in request.providers:
        for path, kind in (
            (claude_home / "CLAUDE.md", "instruction"),
            (claude_home / "rules", "rule-root"),
        ):
            path_kind = _path_kind(path)
            if path_kind == "missing":
                continue
            if kind == "instruction":
                artifacts.append(
                    _discover_rule(
                        path,
                        routes=("claude:user:instruction",),
                        scope="user",
                        anchor="<user>",
                        home=home,
                        project=None,
                        boundary_root=Path(claude_home.anchor),
                        allowed_root=claude_home.parent,
                        kind=kind,
                        frontmatter_required=False,
                    )
                )
            else:
                artifacts.extend(
                    _discover_rule_root(
                        path,
                        pattern="*.md",
                        recursive=True,
                        routes=("claude:user:rule",),
                        scope="user",
                        anchor="<user>",
                        home=home,
                        project=None,
                        boundary_root=Path(claude_home.anchor),
                        allowed_root=claude_home.parent,
                        frontmatter_required=False,
                    )
                )
        projects_root = claude_home / "projects"
        project_memories: list[Path] = []
        if os.path.lexists(projects_root):
            linked_root = first_linklike_component(
                projects_root,
                Path(claude_home.anchor),
            )
            if linked_root is not None:
                artifacts.append(
                    _discovery_boundary(
                        linked_root,
                        routes=("claude:user:memory",),
                        scope="user",
                        anchor="<user>",
                        home=home,
                        project=None,
                        reason="linked-memory-root-not-traversed",
                        allowed_root=claude_home,
                    )
                )
            elif _path_kind(projects_root) == "directory":
                try:
                    iterator = os.scandir(projects_root)
                    with iterator:
                        for index, raw_child in enumerate(iterator, start=1):
                            if index > DISCOVERY_ENTRY_LIMIT:
                                artifacts.append(
                                    _discovery_boundary(
                                        projects_root,
                                        routes=("claude:user:memory",),
                                        scope="user",
                                        anchor="<user>",
                                        home=home,
                                        project=None,
                                        reason="memory-entry-limit-reached",
                                        allowed_root=claude_home,
                                    )
                                )
                                break
                            child = Path(raw_child.path)
                            if is_linklike(child):
                                artifacts.append(
                                    _discovery_boundary(
                                        child,
                                        routes=("claude:user:memory",),
                                        scope="user",
                                        anchor="<user>",
                                        home=home,
                                        project=None,
                                        reason=("linked-memory-project-not-traversed"),
                                        allowed_root=projects_root,
                                    )
                                )
                                continue
                            try:
                                metadata = raw_child.stat(follow_symlinks=False)
                            except (OSError, PermissionError):
                                artifacts.append(
                                    _discovery_boundary(
                                        child,
                                        routes=("claude:user:memory",),
                                        scope="user",
                                        anchor="<user>",
                                        home=home,
                                        project=None,
                                        reason=("unreadable-memory-project"),
                                        allowed_root=projects_root,
                                    )
                                )
                                continue
                            if not stat.S_ISDIR(metadata.st_mode):
                                continue
                            memory = child / "memory"
                            linked_memory = first_linklike_component(
                                memory,
                                child,
                            )
                            if linked_memory is not None:
                                artifacts.append(
                                    _discovery_boundary(
                                        linked_memory,
                                        routes=("claude:user:memory",),
                                        scope="user",
                                        anchor="<user>",
                                        home=home,
                                        project=None,
                                        reason=("linked-memory-root-not-traversed"),
                                        allowed_root=child,
                                    )
                                )
                            elif _path_kind(memory) == "directory":
                                project_memories.append(memory)
                except (OSError, PermissionError):
                    artifacts.append(
                        _discovery_boundary(
                            projects_root,
                            routes=("claude:user:memory",),
                            scope="user",
                            anchor="<user>",
                            home=home,
                            project=None,
                            reason="unreadable-memory-root",
                            allowed_root=claude_home,
                        )
                    )
        memory_artifact = _discover_state_group(
            project_memories,
            root=projects_root,
            display_path="~/.claude/projects/*/memory",
            kind="memory-state",
            route="claude:user:memory",
            scope="user",
            anchor="<user>",
        )
        if memory_artifact:
            artifacts.append(memory_artifact)

        for state_path, kind in (
            (claude_home / "agent-memory", "memory-state"),
            (claude_home / "plugins" / "cache", "managed-plugin-cache"),
        ):
            artifact = _discover_state(
                state_path,
                kind=kind,
                route="claude:user:managed",
                scope="user",
                anchor="<user>",
                home=home,
                boundary_root=Path(claude_home.anchor),
                allowed_root=claude_home.parent,
            )
            if artifact:
                artifacts.append(artifact)

    if "codex" in request.providers:
        for instruction_name in ("AGENTS.override.md", "AGENTS.md"):
            path = codex_home / instruction_name
            if _path_kind(path) != "missing":
                artifacts.append(
                    _discover_rule(
                        path,
                        routes=("codex:user:instruction",),
                        scope="user",
                        anchor="<user>",
                        home=home,
                        project=None,
                        boundary_root=Path(codex_home.anchor),
                        allowed_root=codex_home.parent,
                        kind="instruction",
                        frontmatter_required=False,
                    )
                )
        rules_root = codex_home / "rules"
        artifacts.extend(
            _discover_rule_root(
                rules_root,
                pattern="*.rules",
                recursive=False,
                routes=("codex:user:command-rule",),
                scope="user",
                anchor="<user>",
                home=home,
                project=None,
                boundary_root=Path(codex_home.anchor),
                allowed_root=codex_home.parent,
                kind="command-rule",
                frontmatter_required=False,
            )
        )
        for state_name in ("memories", "threads", "sessions", "archived_sessions"):
            artifact = _discover_state(
                codex_home / state_name,
                kind="memory-state" if state_name == "memories" else "managed-session-state",
                route="codex:user:managed",
                scope="user",
                anchor="<user>",
                home=home,
                boundary_root=Path(codex_home.anchor),
                allowed_root=codex_home.parent,
            )
            if artifact:
                artifacts.append(artifact)
    return artifacts


def _discover_project(request: DiscoveryRequest, project: Path, anchor: str) -> list[Artifact]:
    artifacts: list[Artifact] = []
    linked_project_component = first_linklike_component(
        project,
        Path(project.anchor),
    )
    if linked_project_component is not None:
        routes = tuple(f"{provider}:project:discovery" for provider in request.providers)
        return [
            _discovery_boundary(
                linked_project_component,
                routes=routes,
                scope="project",
                anchor=anchor,
                home=request.home,
                project=project,
                reason=(
                    "linked-project-root-not-traversed"
                    if linked_project_component == project
                    else "linked-project-ancestor-not-traversed"
                ),
                allowed_root=project,
            )
        ]
    (
        config_directories,
        instruction_files,
        walk_errors,
        linked_subtrees,
    ) = _walk_project(
        project,
        request.max_project_directories,
        request.max_project_entries,
    )
    if walk_errors:
        routes = tuple(f"{provider}:project:discovery" for provider in request.providers)
        artifacts.append(
            _discovery_boundary(
                project,
                routes=routes,
                scope="project",
                anchor=anchor,
                home=request.home,
                project=project,
                reason=walk_errors,
                allowed_root=project,
            )
        )
    for linked_subtree in linked_subtrees:
        routes = tuple(f"{provider}:project:discovery" for provider in request.providers)
        artifacts.append(
            _discovery_boundary(
                linked_subtree,
                routes=routes,
                scope="project",
                anchor=anchor,
                home=request.home,
                project=project,
                reason="linked-project-subtree-not-traversed",
                allowed_root=project,
            )
        )
    for config_dir in config_directories:
        if not is_linklike(config_dir):
            continue
        routes = _selected_routes(request.providers, PROJECT_SKILL_ROUTES[config_dir.name])
        if routes:
            artifacts.append(
                _discovery_boundary(
                    config_dir,
                    routes=routes,
                    scope="project",
                    anchor=anchor,
                    home=request.home,
                    project=project,
                    reason="symlink-config-root-not-traversed",
                    allowed_root=config_dir.parent,
                )
            )

    for root in _project_skill_roots(request, project, config_directories, anchor):
        artifacts.extend(_discover_skill_root(root, home=request.home, project=project))

    for config_dir in config_directories:
        if is_linklike(config_dir):
            continue
        if config_dir.name == ".cursor" and "cursor" in request.providers:
            rules_root = config_dir / "rules"
            artifacts.extend(
                _discover_rule_root(
                    rules_root,
                    pattern="*.mdc",
                    recursive=True,
                    routes=("cursor:project:rule",),
                    scope="project",
                    anchor=anchor,
                    home=request.home,
                    project=project,
                )
            )
        elif config_dir.name == ".claude" and "claude" in request.providers:
            instruction = config_dir / "CLAUDE.md"
            if _path_kind(instruction) != "missing":
                artifacts.append(
                    _discover_rule(
                        instruction,
                        routes=("claude:project:instruction",),
                        scope="project",
                        anchor=anchor,
                        home=request.home,
                        project=project,
                        kind="instruction",
                        frontmatter_required=False,
                    )
                )
            rules_root = config_dir / "rules"
            artifacts.extend(
                _discover_rule_root(
                    rules_root,
                    pattern="*.md",
                    recursive=True,
                    routes=("claude:project:rule",),
                    scope="project",
                    anchor=anchor,
                    home=request.home,
                    project=project,
                    frontmatter_required=False,
                )
            )
        elif config_dir.name == ".codex" and "codex" in request.providers:
            rules_root = config_dir / "rules"
            artifacts.extend(
                _discover_rule_root(
                    rules_root,
                    pattern="*.rules",
                    recursive=False,
                    routes=("codex:project:command-rule",),
                    scope="project",
                    anchor=anchor,
                    home=request.home,
                    project=project,
                    kind="command-rule",
                    frontmatter_required=False,
                )
            )

    for instruction in sorted(instruction_files):
        routes: list[str] = []
        if instruction.name.startswith("CLAUDE") and "claude" in request.providers:
            routes.append("claude:project:instruction")
        if instruction.name.startswith("AGENTS") and "codex" in request.providers:
            routes.append("codex:project:instruction")
        if "cursor" in request.providers:
            routes.append("cursor:project:instruction")
        if not routes:
            continue
        artifacts.append(
            _discover_rule(
                instruction,
                routes=tuple(sorted(routes)),
                scope="project",
                anchor=anchor,
                home=request.home,
                project=project,
                kind="instruction",
                frontmatter_required=False,
            )
        )

    if "claude" in request.providers:
        for config_dir in config_directories:
            if config_dir.name != ".claude" or is_linklike(config_dir):
                continue
            for state_name in ("agent-memory", "agent-memory-local"):
                artifact = _discover_state(
                    config_dir / state_name,
                    kind="memory-state",
                    route="claude:project:memory",
                    scope="project",
                    anchor=anchor,
                    home=request.home,
                    project=project,
                    boundary_root=project,
                )
                if artifact:
                    artifacts.append(artifact)
    return artifacts


def discover(request: DiscoveryRequest) -> list[Artifact]:
    artifacts: list[Artifact] = []
    if request.include_user:
        artifacts.extend(_discover_user(request))
    for index, project in enumerate(request.projects, start=1):
        lexical_project = Path(os.path.abspath(project))
        artifacts.extend(_discover_project(request, lexical_project, f"<repo:{index}>"))
    unique_artifacts = {artifact.artifact_id: artifact for artifact in artifacts}
    return sorted(
        unique_artifacts.values(),
        key=lambda artifact: (
            artifact.scope,
            artifact.scope_anchor,
            artifact.kind,
            artifact.display_path,
            artifact.routes,
        ),
    )
