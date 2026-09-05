from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import plistlib
import re
import shlex
import subprocess
import sys
import unicodedata
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path

from .fs_safety import current_account_name, current_principal_identifiers
from .metadata import read_bounded_regular
from .reporting import write_atomic
from .state import (
    RunLock,
    canonical_state_root,
    ensure_state_root,
    is_owned_directory,
    is_owned_regular_file,
    verify_state_root,
    write_json,
)

TASK_PREFIX = "AgentConfigHygiene"
CRON_MARKER_PREFIX = "# agent-config-hygiene:"
LAUNCHD_LABEL_PREFIX = "dev.agent-config-hygiene.audit"
SCHEDULE_PROVIDERS = {"cursor", "claude", "codex"}
WEEKDAYS = {
    "monday": (1, "MON"),
    "tuesday": (2, "TUE"),
    "wednesday": (3, "WED"),
    "thursday": (4, "THU"),
    "friday": (5, "FRI"),
    "saturday": (6, "SAT"),
    "sunday": (7, "SUN"),
}
WINDOWS_WEEKDAY_NAMES = {weekday: weekday.title() for weekday in WEEKDAYS}


class CrontabChangedError(RuntimeError):
    pass


def _current_uid() -> int:
    getter = getattr(os, "getuid", None)
    if getter is None:
        raise RuntimeError("A POSIX user ID is unavailable on this platform")
    return int(getter())


@contextmanager
def _scheduler_mutation_lock() -> Iterator[None]:
    if os.name == "nt":
        yield
        return
    lock_root = Path("/tmp") / f"agent-config-hygiene-scheduler-{_current_uid()}"
    lock_root.mkdir(mode=0o700, exist_ok=True)
    if not is_owned_directory(lock_root):
        raise RuntimeError("Scheduler mutation lock directory is unsafe")
    with RunLock(lock_root):
        yield


def _has_control_characters(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def schedule_identity(root: Path) -> str:
    canonical = str(canonical_state_root(root))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def task_name(root: Path) -> str:
    return task_name_for_identity(schedule_identity(root))


def cron_marker(root: Path) -> str:
    return cron_marker_for_identity(schedule_identity(root))


def launchd_label(root: Path) -> str:
    return launchd_label_for_identity(schedule_identity(root))


def task_name_for_identity(identity: str) -> str:
    return f"{TASK_PREFIX}-{identity}"


def cron_marker_for_identity(identity: str) -> str:
    return f"{CRON_MARKER_PREFIX}{identity}"


def launchd_label_for_identity(identity: str) -> str:
    return f"{LAUNCHD_LABEL_PREFIX}.{identity}"


def _validate_backend_platform(backend: str) -> None:
    system = platform.system()
    if backend == "windows" and system != "Windows":
        raise ValueError("The windows backend requires Windows")
    if backend == "launchd" and system != "Darwin":
        raise ValueError("The launchd backend requires macOS")
    if backend == "cron" and system == "Windows":
        raise ValueError("The cron backend is unavailable on Windows")


@dataclass(frozen=True)
class ScheduleSpec:
    backend: str
    every_weeks: int
    weekday: str
    at: str
    anchor_date: str
    providers: tuple[str, ...]
    include_user: bool = True
    safe_cleanup: bool = False
    retention_days: int = 90

    def validate(self) -> None:
        if not all(
            isinstance(value, str)
            for value in (
                self.backend,
                self.weekday,
                self.at,
                self.anchor_date,
            )
        ):
            raise ValueError("schedule text fields must be strings")
        if self.backend not in {"windows", "cron", "launchd"}:
            raise ValueError(f"Unsupported scheduler backend: {self.backend}")
        if type(self.every_weeks) is not int:
            raise ValueError("every_weeks must be an integer")
        if not 1 <= self.every_weeks <= 52:
            raise ValueError("every_weeks must be between 1 and 52")
        if type(self.retention_days) is not int:
            raise ValueError("retention_days must be an integer")
        if not 7 <= self.retention_days <= 3650:
            raise ValueError("retention_days must be between 7 and 3650")
        if type(self.include_user) is not bool or type(self.safe_cleanup) is not bool:
            raise ValueError("schedule flags must be boolean")
        if (
            not isinstance(self.providers, tuple)
            or not self.providers
            or any(
                not isinstance(provider, str) or provider not in SCHEDULE_PROVIDERS
                for provider in self.providers
            )
            or len(set(self.providers)) != len(self.providers)
        ):
            raise ValueError("providers must be unique supported provider names")
        if self.weekday not in WEEKDAYS:
            raise ValueError(f"Unsupported weekday: {self.weekday}")
        datetime.strptime(self.at, "%H:%M")
        anchor = date.fromisoformat(self.anchor_date)
        if anchor.isoweekday() != WEEKDAYS[self.weekday][0]:
            raise ValueError("anchor_date must fall on the selected weekday")


def resolve_backend(requested: str) -> str:
    if requested != "auto":
        return requested
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "launchd"
    return "cron"


def scheduled_command(root: Path) -> list[str]:
    root = canonical_state_root(root)
    command = [
        str(Path(os.path.abspath(sys.executable))),
        "-m",
        "agent_config_hygiene",
        "scheduled-run",
        "--state-root",
        str(root),
    ]
    if any(_has_control_characters(argument) for argument in command):
        raise ValueError("Scheduler command paths cannot contain control characters")
    return command


def _cron_line(
    command: list[str],
    spec: ScheduleSpec,
    root: Path,
) -> str:
    hour, minute = (int(part) for part in spec.at.split(":"))
    weekday_number, _ = WEEKDAYS[spec.weekday]
    if any("%" in argument for argument in command):
        raise ValueError("cron scheduler paths cannot contain percent signs")
    cron_command = shlex.join(command)
    return f"{minute} {hour} * * {weekday_number % 7} {cron_command} {cron_marker(root)}"


def _launchd_payload(
    command: list[str],
    spec: ScheduleSpec,
    root: Path,
) -> dict[str, object]:
    hour, minute = (int(part) for part in spec.at.split(":"))
    weekday_number, _ = WEEKDAYS[spec.weekday]
    return {
        "Label": launchd_label(root),
        "ProgramArguments": command,
        "StartCalendarInterval": {
            "Weekday": weekday_number % 7,
            "Hour": hour,
            "Minute": minute,
        },
        "ProcessType": "Background",
    }


def _launchd_path(root: Path) -> Path:
    return _launchd_path_for_identity(schedule_identity(root))


def _launchd_path_for_identity(identity: str) -> Path:
    return (
        Path.home() / "Library" / "LaunchAgents" / f"{launchd_label_for_identity(identity)}.plist"
    )


def build_schedule_plan(spec: ScheduleSpec, root: Path) -> dict[str, object]:
    spec.validate()
    _validate_backend_platform(spec.backend)
    root = canonical_state_root(root)
    command = scheduled_command(root)
    hour, minute = (int(part) for part in spec.at.split(":"))
    weekday_number, weekday_short = WEEKDAYS[spec.weekday]
    identity = schedule_identity(root)

    if spec.backend == "windows":
        action = subprocess.list2cmdline(command)
        name = task_name(root)
        account = current_account_name()
        if _has_control_characters(account):
            raise ValueError("Windows account name contains control characters")
        install = [
            "schtasks.exe",
            "/Create",
            "/TN",
            name,
            "/SC",
            "WEEKLY",
            "/MO",
            "1",
            "/D",
            weekday_short,
            "/ST",
            spec.at,
            "/TR",
            action,
            "/RL",
            "LIMITED",
            "/RU",
            account,
            "/IT",
            "/F",
        ]
        uninstall = ["schtasks.exe", "/Delete", "/TN", name, "/F"]
        material = {"task_name": name, "install_argv": install}
    elif spec.backend == "cron":
        marker = cron_marker(root)
        cron_line = _cron_line(command, spec, root)
        material = {"cron_line": cron_line, "marker": marker}
        install = ["crontab", "<updated-stdin>"]
        uninstall = ["crontab", "<updated-stdin-without-marker>"]
    else:
        label = launchd_label(root)
        plist = plistlib.dumps(
            _launchd_payload(command, spec, root),
            fmt=plistlib.FMT_XML,
            sort_keys=False,
        ).decode("utf-8")
        plist_path = _launchd_path(root)
        domain = f"gui/{_current_uid()}"
        material = {
            "label": label,
            "plist_path": str(plist_path),
            "plist": plist,
        }
        install = ["launchctl", "bootstrap", domain, str(plist_path)]
        uninstall = [
            "launchctl",
            "bootout",
            domain,
            str(plist_path),
        ]

    return {
        "identity": identity,
        "spec": {
            **asdict(spec),
            "providers": list(spec.providers),
        },
        "command": command,
        "install": install,
        "uninstall": uninstall,
        "material": material,
        "note": (
            "The OS trigger runs weekly. scheduled-run enforces every_weeks from "
            "the anchor date and prevents duplicate runs."
        ),
    }


def _read_crontab() -> str:
    completed = subprocess.run(
        ["crontab", "-l"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return completed.stdout
    error = completed.stderr.strip()
    if (
        completed.returncode == 1
        and not completed.stdout.strip()
        and "no crontab for" in error.lower()
    ):
        return ""
    raise RuntimeError(error or "Unable to read crontab")


def _write_crontab(content: str) -> None:
    completed = subprocess.run(
        ["crontab", "-"],
        input=content,
        text=True,
        check=False,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "Unable to update crontab")


def _write_crontab_if_unchanged(
    expected: str,
    content: str,
) -> None:
    if _read_crontab() != expected:
        raise CrontabChangedError("Crontab changed concurrently; refusing stale replacement")
    _write_crontab(content)


def load_schedule_config(root: Path, *, required: bool = True) -> dict[str, object] | None:
    root = canonical_state_root(root)
    if not verify_state_root(root):
        if required:
            raise RuntimeError("State ownership is not verified")
        return None
    config_path = root / "schedule.json"
    if not is_owned_regular_file(config_path):
        if required:
            raise RuntimeError("Schedule configuration is missing or unsafe")
        return None
    config_payload = read_bounded_regular(config_path, 256 * 1024)
    if config_payload is None:
        raise RuntimeError("Schedule configuration is unreadable or too large")
    try:
        data = json.loads(config_payload.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise RuntimeError("Schedule configuration is not UTF-8") from exc
    if not isinstance(data, dict):
        raise RuntimeError("Schedule configuration must be a JSON object")
    if data.get("state_root") != str(root):
        raise RuntimeError("Schedule configuration state root does not match")
    if data.get("identity") != schedule_identity(root):
        raise RuntimeError("Schedule configuration identity does not match")
    _configured_command(data, root)
    _validate_schedule_config(data)
    return data


def _configured_command(data: dict[str, object], root: Path) -> list[str]:
    value = data.get("command")
    if (
        not isinstance(value, list)
        or not all(isinstance(item, str) for item in value)
        or len(value) != 6
        or not Path(value[0]).is_absolute()
        or value[1:]
        != [
            "-m",
            "agent_config_hygiene",
            "scheduled-run",
            "--state-root",
            str(canonical_state_root(root)),
        ]
        or any(_has_control_characters(argument) for argument in value)
    ):
        raise RuntimeError("Schedule configuration command is invalid")
    return value


def _validate_schedule_config(data: dict[str, object]) -> ScheduleSpec:
    providers = data.get("providers")
    if (
        not isinstance(providers, list)
        or not providers
        or any(
            not isinstance(provider, str) or provider not in SCHEDULE_PROVIDERS
            for provider in providers
        )
        or len(set(providers)) != len(providers)
    ):
        raise RuntimeError("Schedule configuration providers are invalid")
    for field in ("include_user", "safe_cleanup"):
        if type(data.get(field)) is not bool:
            raise RuntimeError(f"Schedule configuration {field} must be boolean")
    for field in ("every_weeks", "retention_days"):
        if type(data.get(field)) is not int:
            raise RuntimeError(f"Schedule configuration {field} must be an integer")
    try:
        spec = ScheduleSpec(
            backend=str(data["backend"]),
            every_weeks=data["every_weeks"],
            weekday=str(data["weekday"]),
            at=str(data["at"]),
            anchor_date=str(data["anchor_date"]),
            providers=tuple(providers),
            include_user=data["include_user"],
            safe_cleanup=data["safe_cleanup"],
            retention_days=data["retention_days"],
        )
        spec.validate()
        if "last_run_date" in data:
            date.fromisoformat(str(data["last_run_date"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("Schedule configuration is invalid") from exc
    return spec


def _windows_task_matches(
    xml_text: str,
    root: Path,
    expected_command: list[str] | None = None,
    expected_spec: ScheduleSpec | None = None,
) -> bool:
    try:
        document = ET.fromstring(xml_text)
    except ET.ParseError:
        return False
    actions = [
        element for element in document.iter() if element.tag.rsplit("}", 1)[-1] == "Actions"
    ]
    if len(actions) != 1:
        return False
    action_nodes = list(actions[0])
    if len(action_nodes) != 1 or action_nodes[0].tag.rsplit("}", 1)[-1] != "Exec":
        return False
    values: dict[str, list[str]] = {"Command": [], "Arguments": []}
    for element in action_nodes[0]:
        local_name = element.tag.rsplit("}", 1)[-1]
        if local_name in values and element.text is not None:
            values[local_name].append(element.text.strip())
    if len(values["Command"]) != 1 or len(values["Arguments"]) != 1:
        return False
    expected = expected_command or scheduled_command(root)
    command = values["Command"][0].strip('"')
    arguments = values["Arguments"][0]
    if (
        command.casefold() != expected[0].casefold()
        or arguments != subprocess.list2cmdline(expected[1:])
        or not _windows_task_principal_matches(document)
    ):
        return False
    return expected_spec is None or _windows_task_trigger_matches(document, expected_spec)


def _windows_task_principal_matches(document: ET.Element) -> bool:
    principals = [
        element for element in document.iter() if element.tag.rsplit("}", 1)[-1] == "Principals"
    ]
    if len(principals) != 1:
        return False
    principal_nodes = [
        child for child in principals[0] if child.tag.rsplit("}", 1)[-1] == "Principal"
    ]
    if len(principal_nodes) != 1:
        return False
    values: dict[str, list[str]] = {
        "UserId": [],
        "LogonType": [],
        "RunLevel": [],
    }
    for child in principal_nodes[0]:
        local_name = child.tag.rsplit("}", 1)[-1]
        if local_name in values and child.text:
            values[local_name].append(child.text.strip())
    return (
        len(values["UserId"]) == 1
        and values["UserId"][0].casefold() in current_principal_identifiers()
        and values["LogonType"] == ["InteractiveToken"]
        and values["RunLevel"] == ["LeastPrivilege"]
    )


def _windows_task_trigger_matches(
    document: ET.Element,
    spec: ScheduleSpec,
) -> bool:
    triggers = [
        element for element in document.iter() if element.tag.rsplit("}", 1)[-1] == "Triggers"
    ]
    if len(triggers) != 1 or len(list(triggers[0])) != 1:
        return False
    trigger = list(triggers[0])[0]
    if trigger.tag.rsplit("}", 1)[-1] != "CalendarTrigger":
        return False

    start_boundaries = [
        child for child in trigger if child.tag.rsplit("}", 1)[-1] == "StartBoundary" and child.text
    ]
    if len(start_boundaries) != 1:
        return False
    try:
        start = datetime.fromisoformat(start_boundaries[0].text.strip())
    except ValueError:
        return False
    expected_hour, expected_minute = (int(part) for part in spec.at.split(":"))
    if (start.hour, start.minute) != (expected_hour, expected_minute):
        return False

    weekly = [child for child in trigger if child.tag.rsplit("}", 1)[-1] == "ScheduleByWeek"]
    if len(weekly) != 1:
        return False
    interval = [child for child in weekly[0] if child.tag.rsplit("}", 1)[-1] == "WeeksInterval"]
    days = [child for child in weekly[0] if child.tag.rsplit("}", 1)[-1] == "DaysOfWeek"]
    if len(interval) != 1 or (interval[0].text or "").strip() != "1" or len(days) != 1:
        return False
    configured_days = {child.tag.rsplit("}", 1)[-1] for child in days[0]}
    return configured_days == {WINDOWS_WEEKDAY_NAMES[spec.weekday]}


def _windows_task_enabled(xml_text: str) -> bool:
    try:
        document = ET.fromstring(xml_text)
    except ET.ParseError:
        return False
    settings = [
        element for element in document.iter() if element.tag.rsplit("}", 1)[-1] == "Settings"
    ]
    if len(settings) != 1:
        return False
    enabled = [child for child in settings[0] if child.tag.rsplit("}", 1)[-1] == "Enabled"]
    if not enabled:
        task_enabled = True
    else:
        task_enabled = len(enabled) == 1 and (enabled[0].text or "").strip().casefold() == "true"
    if not task_enabled:
        return False

    triggers = [
        element for element in document.iter() if element.tag.rsplit("}", 1)[-1] == "Triggers"
    ]
    if not triggers:
        return True
    if len(triggers) != 1:
        return False
    trigger_states: list[bool] = []
    for trigger in triggers[0]:
        trigger_enabled = [child for child in trigger if child.tag.rsplit("}", 1)[-1] == "Enabled"]
        trigger_states.append(
            not trigger_enabled
            or (
                len(trigger_enabled) == 1
                and (trigger_enabled[0].text or "").strip().casefold() == "true"
            )
        )
    return any(trigger_states)


def _query_windows_task_by_name(
    name: str,
) -> subprocess.CompletedProcess[str] | None:
    listing = subprocess.run(
        ["schtasks.exe", "/Query", "/FO", "CSV", "/NH"],
        check=False,
        capture_output=True,
        text=True,
    )
    if listing.returncode != 0:
        raise RuntimeError(
            listing.stderr.strip() or listing.stdout.strip() or "Unable to list Windows tasks"
        )
    expected = name.casefold()
    present = any(
        row and row[0].lstrip("\\").casefold() == expected
        for row in csv.reader(listing.stdout.splitlines())
    )
    if not present:
        return None
    details = subprocess.run(
        ["schtasks.exe", "/Query", "/TN", name, "/XML"],
        check=False,
        capture_output=True,
        text=True,
    )
    if details.returncode != 0:
        raise RuntimeError(
            details.stderr.strip() or details.stdout.strip() or "Unable to inspect Windows task"
        )
    return details


def _query_windows_task(
    root: Path,
) -> subprocess.CompletedProcess[str] | None:
    return _query_windows_task_by_name(task_name(root))


def _launchd_plist_matches(
    path: Path,
    root: Path,
    expected_command: list[str] | None = None,
    expected_spec: ScheduleSpec | None = None,
) -> bool:
    if not is_owned_regular_file(path):
        return False
    raw_payload = read_bounded_regular(path, 1024 * 1024)
    if raw_payload is None:
        return False
    try:
        payload = plistlib.loads(raw_payload)
    except plistlib.InvalidFileException:
        return False
    command = expected_command or scheduled_command(root)
    if expected_spec is not None:
        return payload == _launchd_payload(command, expected_spec, root)
    return (
        payload.get("Label") == launchd_label(root) and payload.get("ProgramArguments") == command
    )


def _launchd_label_is_loaded(label: str) -> bool:
    completed = subprocess.run(
        [
            "launchctl",
            "print",
            f"gui/{_current_uid()}/{label}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return True
    message = f"{completed.stdout}\n{completed.stderr}".lower()
    if "could not find service" in message or "service not found" in message:
        return False
    raise RuntimeError(
        completed.stderr.strip() or completed.stdout.strip() or "Unable to verify LaunchAgent state"
    )


def _launchd_is_loaded(root: Path) -> bool:
    return _launchd_label_is_loaded(launchd_label(root))


def install_schedule(spec: ScheduleSpec, root: Path) -> dict[str, object]:
    spec.validate()
    _validate_backend_platform(spec.backend)
    root = canonical_state_root(root)
    ensure_state_root(root)
    with RunLock(root):
        with _scheduler_mutation_lock():
            return _install_schedule_locked(spec, root)


def _install_schedule_locked(
    spec: ScheduleSpec,
    root: Path,
) -> dict[str, object]:
    root = canonical_state_root(root)
    plan = build_schedule_plan(spec, root)
    existing_config = load_schedule_config(root, required=False)
    existing_command = (
        _configured_command(existing_config, root) if existing_config is not None else None
    )
    existing_spec = (
        _validate_schedule_config(existing_config) if existing_config is not None else None
    )
    if existing_config is not None and existing_config.get("backend") != spec.backend:
        raise RuntimeError(
            "A different scheduler backend is already configured; uninstall it first"
        )

    existing_crontab: str | None = None
    plist_preexisting = False
    if spec.backend == "windows":
        query = _query_windows_task(root)
        if query is not None and (
            existing_config is None
            or not _windows_task_matches(
                query.stdout,
                root,
                existing_command,
                existing_spec,
            )
        ):
            raise RuntimeError("Refusing to replace a Windows task not owned by this state root")
    elif spec.backend == "cron":
        existing_crontab = _read_crontab()
        marker = cron_marker(root)
        marked_lines = [
            line for line in existing_crontab.splitlines() if line.rstrip().endswith(marker)
        ]
        if marked_lines:
            if (
                existing_config is None
                or existing_command is None
                or existing_spec is None
                or marked_lines != [_cron_line(existing_command, existing_spec, root)]
            ):
                raise RuntimeError("Refusing to replace a cron entry not owned by this state root")
    else:
        plist_path = _launchd_path(root)
        loaded_before = _launchd_is_loaded(root)
        if loaded_before and not os.path.lexists(plist_path):
            raise RuntimeError("Refusing to replace a loaded LaunchAgent without an owned plist")
        if os.path.lexists(plist_path):
            plist_preexisting = True
            if existing_config is None or not _launchd_plist_matches(
                plist_path,
                root,
                existing_command,
                existing_spec,
            ):
                raise RuntimeError("Refusing to replace a LaunchAgent not owned by this state root")
            comparable_fields = (
                "every_weeks",
                "weekday",
                "at",
                "anchor_date",
                "providers",
                "include_user",
                "safe_cleanup",
                "retention_days",
            )
            expected = {
                **asdict(spec),
                "providers": list(spec.providers),
            }
            same_configuration = (
                all(
                    existing_config.get(field) == expected.get(field) for field in comparable_fields
                )
                and existing_command == plan["command"]
            )
            if same_configuration and loaded_before:
                return {
                    "installed": True,
                    "changed": False,
                    "backend": spec.backend,
                    "identity": schedule_identity(root),
                }
            if not same_configuration:
                raise RuntimeError(
                    "LaunchAgent updates require uninstalling the existing schedule first"
                )

    config_path = root / "schedule.json"
    previous_config = (
        json.dumps(
            existing_config,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
        if existing_config is not None
        else None
    )
    config_payload: dict[str, object] = {
        **asdict(spec),
        "providers": list(spec.providers),
        "state_root": str(root),
        "identity": schedule_identity(root),
        "command": plan["command"],
        "installed_at": datetime.now().astimezone().isoformat(),
    }
    if existing_config is not None:
        for key in ("last_run_date", "last_report"):
            if key in existing_config:
                config_payload[key] = existing_config[key]
    write_json(
        config_path,
        config_payload,
    )
    created_plist: Path | None = None
    retain_state = False
    try:
        if spec.backend == "windows":
            completed = subprocess.run(
                plan["install"],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                try:
                    post_failure = _query_windows_task(root)
                    if post_failure is None:
                        retain_state = False
                    elif _windows_task_matches(
                        post_failure.stdout,
                        root,
                        plan["command"],
                        spec,
                    ):
                        retain_state = True
                    elif existing_command is not None and _windows_task_matches(
                        post_failure.stdout,
                        root,
                        existing_command,
                        existing_spec,
                    ):
                        retain_state = False
                    else:
                        retain_state = True
                except (OSError, RuntimeError):
                    retain_state = True
                raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
            post_install = _query_windows_task(root)
            if post_install is None or not _windows_task_matches(
                post_install.stdout,
                root,
                plan["command"],
                spec,
            ):
                retain_state = post_install is not None
                raise RuntimeError("Windows task creation did not produce the expected safe task")
        elif spec.backend == "cron":
            assert existing_crontab is not None
            marker = cron_marker(root)
            existing = [
                line for line in existing_crontab.splitlines() if not line.rstrip().endswith(marker)
            ]
            existing.append(str(plan["material"]["cron_line"]))
            try:
                _write_crontab_if_unchanged(
                    existing_crontab,
                    "\n".join(existing).rstrip() + "\n",
                )
            except CrontabChangedError:
                retain_state = False
                raise
            except RuntimeError:
                try:
                    marked = [
                        line
                        for line in _read_crontab().splitlines()
                        if line.rstrip().endswith(marker)
                    ]
                    if not marked:
                        retain_state = False
                    elif str(plan["material"]["cron_line"]) in marked:
                        retain_state = True
                    else:
                        retain_state = previous_config is None
                except (OSError, RuntimeError):
                    retain_state = True
                raise
        else:
            plist_path = _launchd_path(root)
            plist_path.parent.mkdir(parents=True, exist_ok=True)
            write_atomic(plist_path, str(plan["material"]["plist"]))
            created_plist = plist_path
            retain_state = True
            completed = subprocess.run(
                plan["install"],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                try:
                    loaded = _launchd_is_loaded(root)
                except RuntimeError as exc:
                    retain_state = True
                    raise RuntimeError(
                        completed.stderr.strip()
                        or completed.stdout.strip()
                        or "Unable to load LaunchAgent"
                    ) from exc
                if not loaded:
                    retain_state = plist_preexisting
                raise RuntimeError(
                    completed.stderr.strip()
                    or completed.stdout.strip()
                    or "Unable to load LaunchAgent"
                )
            if not _launchd_is_loaded(root):
                retain_state = plist_preexisting
                raise RuntimeError(
                    "LaunchAgent bootstrap returned success but the job is not loaded"
                )
    except Exception:
        if retain_state:
            raise
        if created_plist is not None:
            created_plist.unlink(missing_ok=True)
        if previous_config is None:
            config_path.unlink(missing_ok=True)
        else:
            write_atomic(config_path, previous_config)
        raise
    return {
        "installed": True,
        "changed": True,
        "backend": spec.backend,
        "identity": schedule_identity(root),
    }


def schedule_status(root: Path) -> dict[str, object]:
    root = canonical_state_root(root)
    data = load_schedule_config(root, required=False)
    if data is None:
        backend = resolve_backend("auto")
        os_entry_present: bool | None = None
        os_entry_owned: bool | None = None
        os_entry_active: bool | None = None
        status_error: str | None = None
        try:
            if backend == "windows":
                completed = _query_windows_task(root)
                os_entry_present = completed is not None
                if completed is not None:
                    os_entry_owned = _windows_task_matches(
                        completed.stdout,
                        root,
                    )
                    os_entry_active = os_entry_owned and _windows_task_enabled(completed.stdout)
            elif backend == "cron":
                marker = cron_marker(root)
                os_entry_present = any(
                    line.rstrip().endswith(marker) for line in _read_crontab().splitlines()
                )
            else:
                plist_path = _launchd_path(root)
                loaded = _launchd_is_loaded(root)
                os_entry_present = os.path.lexists(plist_path) or loaded
                os_entry_active = loaded
                if os.path.lexists(plist_path):
                    os_entry_owned = _launchd_plist_matches(
                        plist_path,
                        root,
                    )
        except (OSError, RuntimeError, ValueError) as exc:
            status_error = type(exc).__name__
        return {
            "configured": False,
            "identity": schedule_identity(root),
            "backend": backend,
            "os_entry_present": os_entry_present,
            "os_entry_owned": os_entry_owned,
            "os_entry_active": os_entry_active,
            "orphaned": bool(os_entry_present),
            "status_error": status_error,
        }

    backend = str(data.get("backend"))
    configured_command = _configured_command(data, root)
    configured_spec = _validate_schedule_config(data)
    os_entry_present: bool | None = None
    os_entry_owned: bool | None = None
    os_entry_active: bool | None = None
    status_error: str | None = None
    try:
        _validate_backend_platform(backend)
        if backend == "windows":
            completed = _query_windows_task(root)
            os_entry_present = completed is not None
            os_entry_owned = (
                _windows_task_matches(
                    completed.stdout,
                    root,
                    configured_command,
                    configured_spec,
                )
                if completed is not None
                else None
            )
            os_entry_active = (
                bool(os_entry_owned) and _windows_task_enabled(completed.stdout)
                if completed is not None
                else None
            )
        elif backend == "cron":
            marker = cron_marker(root)
            marked_lines = [
                line for line in _read_crontab().splitlines() if line.rstrip().endswith(marker)
            ]
            os_entry_present = bool(marked_lines)
            expected_line = _cron_line(
                configured_command,
                configured_spec,
                root,
            )
            os_entry_owned = marked_lines == [expected_line] if marked_lines else None
            os_entry_active = os_entry_owned
        elif backend == "launchd":
            plist_path = _launchd_path(root)
            plist_present = os.path.lexists(plist_path)
            os_entry_active = _launchd_is_loaded(root)
            os_entry_present = plist_present or os_entry_active
            os_entry_owned = (
                _launchd_plist_matches(
                    plist_path,
                    root,
                    configured_command,
                    configured_spec,
                )
                if plist_present
                else None
            )
        else:
            status_error = "unknown-backend"
    except (OSError, RuntimeError, ValueError) as exc:
        status_error = type(exc).__name__
    return {
        "configured": True,
        "identity": schedule_identity(root),
        "backend": backend,
        "every_weeks": data.get("every_weeks"),
        "weekday": data.get("weekday"),
        "at": data.get("at"),
        "anchor_date": data.get("anchor_date"),
        "os_entry_present": os_entry_present,
        "os_entry_owned": os_entry_owned,
        "os_entry_active": os_entry_active,
        "status_error": status_error,
    }


def uninstall_schedule(root: Path) -> dict[str, object]:
    root = canonical_state_root(root)
    if not verify_state_root(root):
        return {"removed": False, "reason": "not-configured"}
    with RunLock(root):
        with _scheduler_mutation_lock():
            return _uninstall_schedule_locked(root)


def forget_orphaned_schedule(root: Path) -> dict[str, object]:
    root = canonical_state_root(root)
    if not verify_state_root(root):
        return {"forgotten": False, "reason": "not-configured"}
    with RunLock(root):
        with _scheduler_mutation_lock():
            config_path = root / "schedule.json"
            if not is_owned_regular_file(config_path):
                return {"forgotten": False, "reason": "not-configured"}
            payload = read_bounded_regular(config_path, 256 * 1024)
            if payload is None:
                raise RuntimeError("Schedule configuration is unreadable or too large")
            try:
                data = json.loads(payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise RuntimeError("Schedule configuration is invalid") from exc
            if (
                not isinstance(data, dict)
                or data.get("backend") not in {"windows", "cron", "launchd"}
                or not isinstance(data.get("identity"), str)
                or re.fullmatch(
                    r"[0-9a-f]{12,64}",
                    str(data.get("identity")),
                )
                is None
            ):
                raise RuntimeError("Schedule configuration is invalid")
            backend = str(data["backend"])
            stored_identity = str(data["identity"])
            compatible = True
            try:
                _validate_backend_platform(backend)
            except ValueError:
                compatible = False
            if compatible:
                if backend == "windows":
                    os_entry_present = (
                        _query_windows_task_by_name(task_name_for_identity(stored_identity))
                        is not None
                    )
                elif backend == "cron":
                    marker = cron_marker_for_identity(stored_identity)
                    os_entry_present = any(
                        line.rstrip().endswith(marker) for line in _read_crontab().splitlines()
                    )
                else:
                    os_entry_present = os.path.lexists(
                        _launchd_path_for_identity(stored_identity)
                    ) or _launchd_label_is_loaded(launchd_label_for_identity(stored_identity))
                if os_entry_present:
                    raise RuntimeError("Refusing to forget a schedule while its OS entry may exist")
            config_path.unlink()
            return {
                "forgotten": True,
                "backend": backend,
                "identity": stored_identity,
                "os_entry_removed": False,
                "reason": ("incompatible-backend" if not compatible else "verified-entry-absent"),
            }


def _uninstall_schedule_locked(root: Path) -> dict[str, object]:
    root = canonical_state_root(root)
    config_path = root / "schedule.json"
    data = load_schedule_config(root, required=False)
    if data is None:
        return {"removed": False, "reason": "not-configured"}
    backend = str(data["backend"])
    configured_command = _configured_command(data, root)
    configured_spec = _validate_schedule_config(data)
    _validate_backend_platform(backend)
    if backend == "windows":
        query = _query_windows_task(root)
        if query is None:
            config_path.unlink()
            return {
                "removed": True,
                "backend": backend,
                "identity": schedule_identity(root),
                "os_entry_present": False,
            }
        if not _windows_task_matches(
            query.stdout,
            root,
            configured_command,
            configured_spec,
        ):
            raise RuntimeError("Refusing to delete a Windows task not owned by this state root")
        completed = subprocess.run(
            ["schtasks.exe", "/Delete", "/TN", task_name(root), "/F"],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
        if _query_windows_task(root) is not None:
            raise RuntimeError("Windows task remained present after deletion; state was retained")
    elif backend == "cron":
        marker = cron_marker(root)
        current_text = _read_crontab()
        current = current_text.splitlines()
        marked = [line for line in current if line.rstrip().endswith(marker)]
        expected_line = _cron_line(
            configured_command,
            configured_spec,
            root,
        )
        if marked and marked != [expected_line]:
            raise RuntimeError("Refusing to delete a cron entry not owned by this state root")
        if marked:
            retained = [line for line in current if not line.rstrip().endswith(marker)]
            _write_crontab_if_unchanged(
                current_text,
                "\n".join(retained).rstrip() + ("\n" if retained else ""),
            )
    elif backend == "launchd":
        plist_path = _launchd_path(root)
        if not os.path.lexists(plist_path):
            if _launchd_is_loaded(root):
                raise RuntimeError(
                    "LaunchAgent is loaded but its owned plist is missing; state was retained"
                )
            config_path.unlink()
            return {
                "removed": True,
                "backend": backend,
                "identity": schedule_identity(root),
                "os_entry_present": False,
            }
        if not _launchd_plist_matches(
            plist_path,
            root,
            configured_command,
            configured_spec,
        ):
            raise RuntimeError("Refusing to delete a missing or foreign LaunchAgent")
        if _launchd_is_loaded(root):
            completed = subprocess.run(
                [
                    "launchctl",
                    "bootout",
                    f"gui/{_current_uid()}",
                    str(plist_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                raise RuntimeError(
                    completed.stderr.strip()
                    or completed.stdout.strip()
                    or "Unable to unload LaunchAgent"
                )
            if _launchd_is_loaded(root):
                raise RuntimeError("LaunchAgent remained loaded after bootout; state was retained")
        plist_path.unlink()
    else:
        raise RuntimeError(f"Unknown configured backend: {backend}")
    config_path.unlink()
    return {
        "removed": True,
        "backend": backend,
        "identity": schedule_identity(root),
    }


def schedule_is_due(config: dict[str, object], today: date | None = None) -> bool:
    current = today or date.today()
    weekday = str(config["weekday"])
    if weekday not in WEEKDAYS:
        raise ValueError(f"Unsupported weekday: {weekday}")
    every_weeks = int(config["every_weeks"])
    if not 1 <= every_weeks <= 52:
        raise ValueError("every_weeks must be between 1 and 52")
    anchor = date.fromisoformat(str(config["anchor_date"]))
    if anchor.isoweekday() != WEEKDAYS[weekday][0]:
        raise ValueError("anchor_date must fall on the selected weekday")
    if current < anchor or current.isoweekday() != WEEKDAYS[weekday][0]:
        return False
    elapsed_weeks = (current - anchor).days // 7
    return elapsed_weeks % every_weeks == 0
