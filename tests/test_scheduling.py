from __future__ import annotations

import os
import plistlib
import subprocess
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from agent_config_hygiene.fs_safety import current_principal_identifiers
from agent_config_hygiene.scheduling import (
    ScheduleSpec,
    _read_crontab,
    _scheduler_mutation_lock,
    _windows_task_enabled,
    _windows_task_matches,
    _write_crontab_if_unchanged,
    build_schedule_plan,
    cron_marker,
    cron_marker_for_identity,
    forget_orphaned_schedule,
    install_schedule,
    load_schedule_config,
    schedule_identity,
    schedule_is_due,
    scheduled_command,
    task_name,
    uninstall_schedule,
)
from agent_config_hygiene.state import RunLock, ensure_state_root, write_json


def windows_task_xml(
    command: list[str],
    spec: ScheduleSpec,
    *,
    run_level: str = "LeastPrivilege",
) -> str:
    arguments = subprocess.list2cmdline(command[1:])
    principal = sorted(current_principal_identifiers())[0]
    weekday = spec.weekday.title()
    return (
        "<Task>"
        "<Triggers><CalendarTrigger>"
        f"<StartBoundary>{spec.anchor_date}T{spec.at}:00</StartBoundary>"
        "<ScheduleByWeek><WeeksInterval>1</WeeksInterval>"
        f"<DaysOfWeek><{weekday} /></DaysOfWeek>"
        "</ScheduleByWeek></CalendarTrigger></Triggers>"
        "<Principals><Principal>"
        f"<UserId>{principal}</UserId>"
        "<LogonType>InteractiveToken</LogonType>"
        f"<RunLevel>{run_level}</RunLevel>"
        "</Principal></Principals>"
        "<Settings><Enabled>true</Enabled></Settings>"
        "<Actions><Exec>"
        f"<Command>{command[0]}</Command>"
        f"<Arguments>{arguments}</Arguments>"
        "</Exec></Actions>"
        "</Task>"
    )


class ScheduleTests(unittest.TestCase):
    def test_biweekly_anchor_is_enforced(self) -> None:
        config = {
            "anchor_date": "2026-09-14",
            "weekday": "monday",
            "every_weeks": 2,
        }
        self.assertTrue(schedule_is_due(config, date(2026, 9, 14)))
        self.assertFalse(schedule_is_due(config, date(2026, 9, 21)))
        self.assertTrue(schedule_is_due(config, date(2026, 9, 28)))
        self.assertFalse(schedule_is_due(config, date(2026, 9, 15)))

    def test_windows_plan_uses_argument_array_and_weekly_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spec = ScheduleSpec(
                backend="windows",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor", "claude", "codex"),
            )
            with patch(
                "agent_config_hygiene.scheduling.platform.system",
                return_value="Windows",
            ):
                plan = build_schedule_plan(spec, Path(directory))
            argv = plan["install"]
            self.assertEqual(argv[0], "schtasks.exe")
            self.assertIn("WEEKLY", argv)
            self.assertIn("MON", argv)
            self.assertIn("09:00", argv)
            self.assertIn("/IT", argv)
            self.assertIn("scheduled-run", " ".join(plan["command"]))

    def test_anchor_must_match_weekday(self) -> None:
        spec = ScheduleSpec(
            backend="cron",
            every_weeks=2,
            weekday="monday",
            at="09:00",
            anchor_date="2026-09-15",
            providers=("cursor",),
        )
        with self.assertRaises(ValueError):
            spec.validate()

    def test_due_check_rejects_invalid_interval(self) -> None:
        config = {
            "anchor_date": "2026-09-14",
            "weekday": "monday",
            "every_weeks": 0,
        }
        with self.assertRaises(ValueError):
            schedule_is_due(config, date(2026, 9, 14))

    def test_failed_windows_install_rolls_back_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            spec = ScheduleSpec(
                backend="windows",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            missing = CompletedProcess(
                args=["schtasks.exe"],
                returncode=0,
                stdout="",
                stderr="",
            )
            failed = CompletedProcess(
                args=["schtasks.exe"],
                returncode=1,
                stdout="",
                stderr="create failed",
            )
            with (
                patch(
                    "agent_config_hygiene.scheduling.platform.system",
                    return_value="Windows",
                ),
                patch(
                    "agent_config_hygiene.scheduling.subprocess.run",
                    side_effect=[missing, failed, missing],
                ),
            ):
                with self.assertRaises(RuntimeError):
                    install_schedule(spec, root)
            self.assertFalse((root / "schedule.json").exists())

    def test_launchd_weekdays_match_iso_weekdays(self) -> None:
        start = date(2026, 9, 14)
        weekdays = (
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        )
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch(
                    "agent_config_hygiene.scheduling.platform.system",
                    return_value="Darwin",
                ),
                patch(
                    "agent_config_hygiene.scheduling.os.getuid",
                    return_value=501,
                    create=True,
                ),
            ):
                for offset, weekday in enumerate(weekdays):
                    spec = ScheduleSpec(
                        backend="launchd",
                        every_weeks=2,
                        weekday=weekday,
                        at="09:00",
                        anchor_date=(start + timedelta(days=offset)).isoformat(),
                        providers=("cursor",),
                    )
                    plan = build_schedule_plan(spec, Path(directory))
                    payload = plistlib.loads(plan["material"]["plist"].encode("utf-8"))
                    expected = (offset + 1) % 7
                    self.assertEqual(
                        payload["StartCalendarInterval"]["Weekday"],
                        expected,
                    )

    def test_incompatible_backend_is_rejected_cleanly(self) -> None:
        spec = ScheduleSpec(
            backend="launchd",
            every_weeks=2,
            weekday="monday",
            at="09:00",
            anchor_date="2026-09-14",
            providers=("cursor",),
        )
        with patch(
            "agent_config_hygiene.scheduling.platform.system",
            return_value="Windows",
        ):
            with self.assertRaisesRegex(ValueError, "requires macOS"):
                build_schedule_plan(spec, Path("state"))

    def test_scheduler_identities_are_scoped_to_canonical_state_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            first = base / "one"
            second = base / "two"
            self.assertNotEqual(task_name(first), task_name(second))
            self.assertNotEqual(cron_marker(first), cron_marker(second))
            self.assertEqual(
                task_name(base / "nested" / ".." / "one"),
                task_name(first),
            )

    def test_relative_state_root_is_canonicalized_in_command(self) -> None:
        spec = ScheduleSpec(
            backend="windows",
            every_weeks=2,
            weekday="monday",
            at="09:00",
            anchor_date="2026-09-14",
            providers=("cursor",),
        )
        with patch(
            "agent_config_hygiene.scheduling.platform.system",
            return_value="Windows",
        ):
            plan = build_schedule_plan(spec, Path("relative-state"))
        self.assertTrue(Path(plan["command"][-1]).is_absolute())

    def test_scheduled_command_preserves_virtualenv_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            interpreter = base / "base-python"
            interpreter.write_bytes(b"")
            linked = base / "venv-python"
            try:
                linked.symlink_to(interpreter)
            except OSError as exc:
                self.skipTest(f"file symlinks unavailable: {exc}")

            with patch(
                "agent_config_hygiene.scheduling.sys.executable",
                str(linked),
            ):
                command = scheduled_command(base / "state")

            self.assertEqual(command[0], str(linked))

    def test_cron_rejects_percent_in_command_path(self) -> None:
        spec = ScheduleSpec(
            backend="cron",
            every_weeks=2,
            weekday="monday",
            at="09:00",
            anchor_date="2026-09-14",
            providers=("cursor",),
        )
        with (
            patch(
                "agent_config_hygiene.scheduling.platform.system",
                return_value="Linux",
            ),
            patch(
                "agent_config_hygiene.scheduling.sys.executable",
                r"/opt/python\%test/bin/python",
            ),
        ):
            with self.assertRaisesRegex(ValueError, "percent signs"):
                build_schedule_plan(spec, Path("state"))

    def test_crontab_permission_error_is_not_treated_as_empty(self) -> None:
        failed = CompletedProcess(
            args=["crontab", "-l"],
            returncode=1,
            stdout="",
            stderr="permission denied",
        )
        with patch(
            "agent_config_hygiene.scheduling.subprocess.run",
            return_value=failed,
        ):
            with self.assertRaisesRegex(RuntimeError, "permission denied"):
                _read_crontab()

    def test_crontab_change_aborts_before_write(self) -> None:
        changed = CompletedProcess(
            args=["crontab", "-l"],
            returncode=0,
            stdout="new entry\n",
            stderr="",
        )
        with patch(
            "agent_config_hygiene.scheduling.subprocess.run",
            return_value=changed,
        ) as run:
            with self.assertRaisesRegex(RuntimeError, "changed concurrently"):
                _write_crontab_if_unchanged(
                    "old entry\n",
                    "replacement\n",
                )
            self.assertEqual(run.call_count, 1)

    def test_scheduler_rejects_newlines_in_state_path(self) -> None:
        spec = ScheduleSpec(
            backend="cron",
            every_weeks=2,
            weekday="monday",
            at="09:00",
            anchor_date="2026-09-14",
            providers=("cursor",),
        )
        with patch(
            "agent_config_hygiene.scheduling.platform.system",
            return_value="Linux",
        ):
            with self.assertRaisesRegex(ValueError, "control characters"):
                build_schedule_plan(spec, Path("bad\nstate"))
            with self.assertRaisesRegex(ValueError, "control characters"):
                build_schedule_plan(spec, Path("bad\u202estate"))

    def test_windows_task_ownership_checks_action(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = scheduled_command(root)
            spec = ScheduleSpec(
                backend="windows",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            owned = windows_task_xml(expected, spec)
            foreign = owned.replace("scheduled-run", "foreign-command")
            multiple_actions = owned.replace(
                "</Actions>",
                "<Exec><Command>C:\\foreign.exe</Command>"
                "<Arguments>--run</Arguments></Exec></Actions>",
            )
            elevated = windows_task_xml(
                expected,
                spec,
                run_level="HighestAvailable",
            )
            wrong_day = owned.replace("<Monday />", "<Tuesday />")
            disabled = owned.replace(
                "<Enabled>true</Enabled>",
                "<Enabled>false</Enabled>",
            )
            self.assertTrue(_windows_task_matches(owned, root, expected, spec))
            self.assertFalse(_windows_task_matches(foreign, root, expected, spec))
            self.assertFalse(
                _windows_task_matches(
                    multiple_actions,
                    root,
                    expected,
                    spec,
                )
            )
            self.assertFalse(_windows_task_matches(elevated, root, expected, spec))
            self.assertFalse(_windows_task_matches(wrong_day, root, expected, spec))
            self.assertTrue(_windows_task_matches(disabled, root, expected, spec))
            self.assertFalse(_windows_task_enabled(disabled))

    def test_windows_task_enabled_uses_settings_value(self) -> None:
        self.assertTrue(_windows_task_enabled("<Task><Settings /></Task>"))
        self.assertTrue(
            _windows_task_enabled("<Task><Settings><Enabled>true</Enabled></Settings></Task>")
        )
        self.assertFalse(
            _windows_task_enabled("<Task><Settings><Enabled>false</Enabled></Settings></Task>")
        )
        self.assertFalse(
            _windows_task_enabled(
                "<Task><Triggers><CalendarTrigger>"
                "<Enabled>false</Enabled>"
                "</CalendarTrigger></Triggers><Settings /></Task>"
            )
        )

    def test_windows_install_refuses_foreign_fixed_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            spec = ScheduleSpec(
                backend="windows",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            with patch(
                "agent_config_hygiene.scheduling.platform.system",
                return_value="Windows",
            ):
                listing = CompletedProcess(
                    args=["schtasks.exe"],
                    returncode=0,
                    stdout=f'"\\{task_name(root)}","N/A","Ready"\n',
                    stderr="",
                )
                details = CompletedProcess(
                    args=["schtasks.exe"],
                    returncode=0,
                    stdout=(
                        "<Task><Actions><Exec>"
                        "<Command>C:\\foreign.exe</Command>"
                        "<Arguments>--delete</Arguments>"
                        "</Exec></Actions></Task>"
                    ),
                    stderr="",
                )
                with patch(
                    "agent_config_hygiene.scheduling.subprocess.run",
                    side_effect=[listing, details],
                ):
                    with self.assertRaisesRegex(RuntimeError, "not owned"):
                        install_schedule(spec, root)
            self.assertFalse((root / "schedule.json").exists())

    def test_windows_install_verifies_created_task(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            spec = ScheduleSpec(
                backend="windows",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            with patch(
                "agent_config_hygiene.scheduling.platform.system",
                return_value="Windows",
            ):
                plan = build_schedule_plan(spec, root)
                absent = CompletedProcess(
                    args=["schtasks.exe"],
                    returncode=0,
                    stdout="",
                    stderr="",
                )
                created = CompletedProcess(
                    args=["schtasks.exe"],
                    returncode=0,
                    stdout="SUCCESS",
                    stderr="",
                )
                present = CompletedProcess(
                    args=["schtasks.exe"],
                    returncode=0,
                    stdout=f'"\\{task_name(root)}","N/A","Ready"\n',
                    stderr="",
                )
                details = CompletedProcess(
                    args=["schtasks.exe"],
                    returncode=0,
                    stdout=windows_task_xml(plan["command"], spec),
                    stderr="",
                )
                with patch(
                    "agent_config_hygiene.scheduling.subprocess.run",
                    side_effect=[absent, created, present, details],
                ):
                    result = install_schedule(spec, root)

            self.assertTrue(result["installed"])
            self.assertTrue((root / "schedule.json").exists())

    def test_launchd_uninstall_retains_state_when_bootout_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "state"
            plist_path = base / "owned.plist"
            spec = ScheduleSpec(
                backend="launchd",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            with (
                patch(
                    "agent_config_hygiene.scheduling.platform.system",
                    return_value="Darwin",
                ),
                patch(
                    "agent_config_hygiene.scheduling.os.getuid",
                    return_value=501,
                    create=True,
                ),
                patch(
                    "agent_config_hygiene.scheduling._launchd_path",
                    return_value=plist_path,
                ),
            ):
                ensure_state_root(root)
                plan = build_schedule_plan(spec, root)
                plist_path.write_text(
                    plan["material"]["plist"],
                    encoding="utf-8",
                )
                write_json(
                    root / "schedule.json",
                    {
                        **plan["spec"],
                        "state_root": str(root.resolve()),
                        "identity": schedule_identity(root),
                        "command": scheduled_command(root),
                    },
                )
                loaded = CompletedProcess(
                    args=["launchctl", "print"],
                    returncode=0,
                    stdout="loaded",
                    stderr="",
                )
                failed = CompletedProcess(
                    args=["launchctl", "bootout"],
                    returncode=1,
                    stdout="",
                    stderr="denied",
                )
                with patch(
                    "agent_config_hygiene.scheduling.subprocess.run",
                    side_effect=[loaded, failed],
                ):
                    with self.assertRaisesRegex(RuntimeError, "denied"):
                        uninstall_schedule(root)
            self.assertTrue(plist_path.exists())
            self.assertTrue((root / "schedule.json").exists())

    def test_launchd_install_repairs_unloaded_owned_job(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "state"
            plist_path = base / "owned.plist"
            spec = ScheduleSpec(
                backend="launchd",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            with (
                patch(
                    "agent_config_hygiene.scheduling.platform.system",
                    return_value="Darwin",
                ),
                patch(
                    "agent_config_hygiene.scheduling.os.getuid",
                    return_value=501,
                    create=True,
                ),
                patch(
                    "agent_config_hygiene.scheduling._launchd_path",
                    return_value=plist_path,
                ),
            ):
                ensure_state_root(root)
                plan = build_schedule_plan(spec, root)
                plist_path.write_text(
                    plan["material"]["plist"],
                    encoding="utf-8",
                )
                write_json(
                    root / "schedule.json",
                    {
                        **plan["spec"],
                        "state_root": str(root.resolve()),
                        "identity": schedule_identity(root),
                        "command": scheduled_command(root),
                    },
                )
                not_loaded = CompletedProcess(
                    args=["launchctl", "print"],
                    returncode=1,
                    stdout="",
                    stderr="Could not find service",
                )
                installed = CompletedProcess(
                    args=["launchctl", "bootstrap"],
                    returncode=0,
                    stdout="",
                    stderr="",
                )
                loaded = CompletedProcess(
                    args=["launchctl", "print"],
                    returncode=0,
                    stdout="loaded",
                    stderr="",
                )
                with patch(
                    "agent_config_hygiene.scheduling.subprocess.run",
                    side_effect=[not_loaded, installed, loaded],
                ) as run:
                    result = install_schedule(spec, root)
                self.assertTrue(result["changed"])
                self.assertEqual(run.call_count, 3)

    def test_failed_new_launchd_install_rolls_back_when_not_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "state"
            plist_path = base / "owned.plist"
            spec = ScheduleSpec(
                backend="launchd",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            failed = CompletedProcess(
                args=["launchctl", "bootstrap"],
                returncode=1,
                stdout="",
                stderr="failed",
            )
            not_loaded = CompletedProcess(
                args=["launchctl", "print"],
                returncode=1,
                stdout="",
                stderr="Could not find service",
            )
            with (
                patch(
                    "agent_config_hygiene.scheduling.platform.system",
                    return_value="Darwin",
                ),
                patch(
                    "agent_config_hygiene.scheduling.os.getuid",
                    return_value=501,
                    create=True,
                ),
                patch(
                    "agent_config_hygiene.scheduling._launchd_path",
                    return_value=plist_path,
                ),
                patch(
                    "agent_config_hygiene.scheduling.subprocess.run",
                    side_effect=[not_loaded, failed, not_loaded],
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "failed"):
                    install_schedule(spec, root)
            self.assertFalse(plist_path.exists())
            self.assertFalse((root / "schedule.json").exists())

    def test_launchd_install_refuses_loaded_job_without_owned_plist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "state"
            plist_path = base / "missing.plist"
            spec = ScheduleSpec(
                backend="launchd",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            with (
                patch(
                    "agent_config_hygiene.scheduling.platform.system",
                    return_value="Darwin",
                ),
                patch(
                    "agent_config_hygiene.scheduling.os.getuid",
                    return_value=501,
                    create=True,
                ),
                patch(
                    "agent_config_hygiene.scheduling._launchd_path",
                    return_value=plist_path,
                ),
                patch(
                    "agent_config_hygiene.scheduling._launchd_is_loaded",
                    return_value=True,
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "without an owned plist",
                ):
                    install_schedule(spec, root)
            self.assertFalse((root / "schedule.json").exists())

    def test_cron_uninstall_refuses_forged_marker_line(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            spec = ScheduleSpec(
                backend="cron",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            with patch(
                "agent_config_hygiene.scheduling.platform.system",
                return_value="Linux",
            ):
                ensure_state_root(root)
                plan = build_schedule_plan(spec, root)
                write_json(
                    root / "schedule.json",
                    {
                        **plan["spec"],
                        "state_root": str(root.resolve()),
                        "identity": schedule_identity(root),
                        "command": scheduled_command(root),
                    },
                )
                forged = CompletedProcess(
                    args=["crontab", "-l"],
                    returncode=0,
                    stdout=f"* * * * * false {cron_marker(root)}\n",
                    stderr="",
                )
                with patch(
                    "agent_config_hygiene.scheduling.subprocess.run",
                    return_value=forged,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "not owned",
                    ):
                        uninstall_schedule(root)
            self.assertTrue((root / "schedule.json").exists())

    def test_backend_change_requires_explicit_uninstall(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            spec = ScheduleSpec(
                backend="windows",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            with patch(
                "agent_config_hygiene.scheduling.platform.system",
                return_value="Windows",
            ):
                ensure_state_root(root)
                write_json(
                    root / "schedule.json",
                    {
                        "backend": "cron",
                        "every_weeks": 2,
                        "weekday": "monday",
                        "at": "09:00",
                        "anchor_date": "2026-09-14",
                        "providers": ["cursor"],
                        "include_user": True,
                        "safe_cleanup": False,
                        "retention_days": 90,
                        "state_root": str(root.resolve()),
                        "identity": schedule_identity(root),
                        "command": scheduled_command(root),
                    },
                )
                with patch("agent_config_hygiene.scheduling.subprocess.run") as run:
                    with self.assertRaisesRegex(RuntimeError, "different scheduler backend"):
                        install_schedule(spec, root)
                    run.assert_not_called()

    def test_forget_orphaned_schedule_allows_cross_platform_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            ensure_state_root(root)
            write_json(
                root / "schedule.json",
                {
                    "backend": "windows",
                    "every_weeks": 2,
                    "weekday": "monday",
                    "at": "09:00",
                    "anchor_date": "2026-09-14",
                    "providers": ["cursor"],
                    "include_user": True,
                    "safe_cleanup": False,
                    "retention_days": 90,
                    "state_root": r"C:\old-machine\state",
                    "identity": "aaaaaaaaaaaaaaaaaaaaaaaa",
                    "command": [
                        r"C:\old-machine\python.exe",
                        "-m",
                        "agent_config_hygiene",
                        "scheduled-run",
                        "--state-root",
                        r"C:\old-machine\state",
                    ],
                },
            )
            with patch(
                "agent_config_hygiene.scheduling.platform.system",
                return_value="Linux",
            ):
                result = forget_orphaned_schedule(root)

            self.assertTrue(result["forgotten"])
            self.assertEqual(result["reason"], "incompatible-backend")
            self.assertFalse((root / "schedule.json").exists())

    def test_forget_orphaned_schedule_checks_stored_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            stored_identity = "a" * 24
            ensure_state_root(root)
            write_json(
                root / "schedule.json",
                {
                    "backend": "cron",
                    "identity": stored_identity,
                },
            )
            old_marker = cron_marker_for_identity(stored_identity)
            with (
                patch(
                    "agent_config_hygiene.scheduling.platform.system",
                    return_value="Linux",
                ),
                patch(
                    "agent_config_hygiene.scheduling._read_crontab",
                    return_value=f"* * * * * command {old_marker}\n",
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "may exist"):
                    forget_orphaned_schedule(root)

            self.assertTrue((root / "schedule.json").exists())

    def test_schedule_install_uses_shared_run_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            spec = ScheduleSpec(
                backend="windows",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            ensure_state_root(root)
            with (
                patch(
                    "agent_config_hygiene.scheduling.platform.system",
                    return_value="Windows",
                ),
                patch("agent_config_hygiene.scheduling.subprocess.run") as run,
                RunLock(root),
            ):
                with self.assertRaisesRegex(RuntimeError, "active"):
                    install_schedule(spec, root)
                run.assert_not_called()

    @unittest.skipIf(os.name == "nt", "shared crontab lock is POSIX-only")
    def test_schedule_install_uses_cross_state_mutation_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            spec = ScheduleSpec(
                backend="windows",
                every_weeks=2,
                weekday="monday",
                at="09:00",
                anchor_date="2026-09-14",
                providers=("cursor",),
            )
            with (
                patch(
                    "agent_config_hygiene.scheduling.platform.system",
                    return_value="Windows",
                ),
                patch("agent_config_hygiene.scheduling.subprocess.run") as run,
                _scheduler_mutation_lock(),
            ):
                with self.assertRaisesRegex(RuntimeError, "active"):
                    install_schedule(spec, root)
                run.assert_not_called()

    def test_schedule_config_rejects_string_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            ensure_state_root(root)
            write_json(
                root / "schedule.json",
                {
                    "backend": "cron",
                    "every_weeks": 2,
                    "weekday": "monday",
                    "at": "09:00",
                    "anchor_date": "2026-09-14",
                    "providers": ["cursor"],
                    "include_user": True,
                    "safe_cleanup": "false",
                    "retention_days": 90,
                    "state_root": str(root.resolve()),
                    "identity": schedule_identity(root),
                    "command": scheduled_command(root),
                },
            )
            with self.assertRaisesRegex(RuntimeError, "must be boolean"):
                load_schedule_config(root)

    def test_schedule_config_rejects_hard_link(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "state"
            external = base / "external.json"
            external.write_text("{}\n", encoding="utf-8")
            ensure_state_root(root)
            try:
                (root / "schedule.json").hardlink_to(external)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")

            with self.assertRaisesRegex(RuntimeError, "missing or unsafe"):
                load_schedule_config(root)
            self.assertEqual(external.read_text(encoding="utf-8"), "{}\n")


if __name__ == "__main__":
    unittest.main()
