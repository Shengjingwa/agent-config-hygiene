from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from collections.abc import Sequence
from datetime import date, datetime, timedelta
from pathlib import Path

from . import __version__
from .audit import dedupe_plan, run_audit
from .cleanup import apply_cleanup, plan_cleanup
from .discovery import PROVIDERS
from .fs_safety import is_linklike
from .model import SEVERITY_RANK, AuditReport, Severity
from .reporting import render, write_atomic
from .scheduling import (
    ScheduleSpec,
    build_schedule_plan,
    forget_orphaned_schedule,
    install_schedule,
    load_schedule_config,
    resolve_backend,
    schedule_is_due,
    schedule_status,
    uninstall_schedule,
)
from .skill_install import install as install_skill
from .skill_install import plan_install as plan_skill_install
from .state import (
    RunLock,
    canonical_state_root,
    ensure_state_subdirectory,
    state_root,
    verify_state_root,
    write_json,
)


def _json(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _providers(value: str) -> tuple[str, ...]:
    return PROVIDERS if value == "all" else (value,)


def _projects(values: Sequence[str], include_user: bool) -> tuple[Path, ...]:
    paths = [Path(value).expanduser().absolute() for value in values]
    if not paths and not include_user:
        current = Path.cwd().resolve()
        paths = [
            next(
                (
                    candidate
                    for candidate in (current, *current.parents)
                    if (candidate / ".git").exists()
                ),
                current,
            )
        ]
    for path in paths:
        if is_linklike(path):
            raise ValueError(f"Project root cannot be a link: {path}")
        if not path.is_dir():
            raise ValueError(f"Project directory does not exist: {path}")
    return tuple(paths)


def _audit_from_args(args: argparse.Namespace):
    projects = _projects(args.projects, args.user)
    return run_audit(
        home=Path.home(),
        projects=projects,
        providers=_providers(args.provider),
        include_user=args.user,
    )


def _audit_exit(report: AuditReport, fail_on: str) -> int:
    if fail_on == "off":
        return 0
    threshold = SEVERITY_RANK[Severity(fail_on)]
    return int(any(SEVERITY_RANK[finding.severity] >= threshold for finding in report.findings))


def _write_or_print(content: str, output: str | None) -> None:
    if output:
        write_atomic(Path(output), content)
    else:
        sys.stdout.write(content)


def _render_plan(plans: list[dict[str, object]], output_format: str) -> str:
    if output_format == "json":
        return _json({"plans": plans, "mutations": False})
    if not plans:
        return "No duplicate Skill plan is needed.\n"
    lines = ["Skill de-duplication plan (no mutations)", ""]
    for plan in plans:
        lines.append(f"- {plan['name']}: {plan['classification']} ({plan['finding_id']})")
        for candidate in plan["candidates"]:
            lines.append(f"  - {candidate['path']} via {', '.join(candidate['routes'])}")
        lines.append("  - Action: manual choice required")
    return "\n".join(lines) + "\n"


def _next_anchor(weekday: str) -> str:
    target = {
        "monday": 1,
        "tuesday": 2,
        "wednesday": 3,
        "thursday": 4,
        "friday": 5,
        "saturday": 6,
        "sunday": 7,
    }[weekday]
    today = date.today()
    delta = (target - today.isoweekday()) % 7
    return (today + timedelta(days=delta)).isoformat()


def _schedule_spec(args: argparse.Namespace) -> ScheduleSpec:
    backend = resolve_backend(args.backend)
    return ScheduleSpec(
        backend=backend,
        every_weeks=args.every_weeks,
        weekday=args.weekday,
        at=args.at,
        anchor_date=args.anchor_date or _next_anchor(args.weekday),
        providers=_providers(args.provider),
        include_user=True,
        safe_cleanup=args.safe_cleanup,
        retention_days=args.retention_days,
    )


def _run_scheduled(root: Path) -> int:
    if not verify_state_root(root):
        raise RuntimeError("Scheduled state ownership is not verified")

    with RunLock(root):
        config = load_schedule_config(root)
        assert config is not None
        config_path = root / "schedule.json"
        if not schedule_is_due(config):
            sys.stdout.write(_json({"ran": False, "reason": "not-due"}))
            return 0
        today = date.today().isoformat()
        if config.get("last_run_date") == today:
            sys.stdout.write(_json({"ran": False, "reason": "already-ran"}))
            return 0

        report = run_audit(
            home=Path.home(),
            projects=(),
            providers=tuple(config.get("providers", PROVIDERS)),
            include_user=bool(config.get("include_user", True)),
        )
        report_root = ensure_state_subdirectory(root, "reports")
        report_path = report_root / (
            "audit-" + datetime.now().astimezone().strftime("%Y%m%d") + ".json"
        )
        write_atomic(report_path, render(report, "json"))

        config["last_run_date"] = today
        config["last_report"] = report_path.name
        write_json(config_path, config)

        cleanup_result: dict[str, object] | None = None
        if bool(config.get("safe_cleanup", False)):
            plan = plan_cleanup(root, int(config.get("retention_days", 90)))
            cleanup_result = apply_cleanup(root, plan)
    sys.stdout.write(
        _json(
            {
                "ran": True,
                "report": "<state>/reports/" + report_path.name,
                "findings": len(report.findings),
                "cleanup": cleanup_result,
            }
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ach",
        description=("Offline hygiene audits for Cursor, Claude Code, and Codex configuration."),
    )
    parser.add_argument("--version", action="version", version=__version__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    audit_parser = subcommands.add_parser("audit", help="Audit configuration")
    audit_parser.add_argument("projects", nargs="*")
    audit_parser.add_argument("--user", action="store_true")
    audit_parser.add_argument("--provider", choices=("all", *PROVIDERS), default="all")
    audit_parser.add_argument("--format", choices=("human", "json", "sarif"), default="human")
    audit_parser.add_argument("--output")
    audit_parser.add_argument(
        "--fail-on",
        choices=("off", "info", "low", "medium", "high"),
        default="off",
    )

    dedupe_parser = subcommands.add_parser("dedupe", help="Plan Skill de-duplication")
    dedupe_subcommands = dedupe_parser.add_subparsers(dest="dedupe_command", required=True)
    dedupe_plan_parser = dedupe_subcommands.add_parser("plan")
    dedupe_plan_parser.add_argument("projects", nargs="*")
    dedupe_plan_parser.add_argument("--user", action="store_true")
    dedupe_plan_parser.add_argument("--provider", choices=("all", *PROVIDERS), default="all")
    dedupe_plan_parser.add_argument("--format", choices=("human", "json"), default="human")
    dedupe_plan_parser.add_argument("--output")

    clean_parser = subcommands.add_parser("clean", help="Clean only owned tool state")
    clean_parser.add_argument("--retention-days", type=int, default=90)
    clean_parser.add_argument("--state-root")
    clean_parser.add_argument("--apply", action="store_true")
    clean_parser.add_argument("--safe-only", action="store_true")
    clean_parser.add_argument("--format", choices=("human", "json"), default="human")

    subcommands.add_parser("doctor", help="Check runtime and safety prerequisites")

    schedule_parser = subcommands.add_parser("schedule", help="Manage local scheduling")
    schedule_subcommands = schedule_parser.add_subparsers(dest="schedule_command", required=True)
    for name in ("plan", "install"):
        schedule_action = schedule_subcommands.add_parser(name)
        schedule_action.add_argument(
            "--backend",
            choices=("auto", "windows", "cron", "launchd"),
            default="auto",
        )
        schedule_action.add_argument("--every-weeks", type=int, default=2)
        schedule_action.add_argument(
            "--weekday",
            choices=(
                "monday",
                "tuesday",
                "wednesday",
                "thursday",
                "friday",
                "saturday",
                "sunday",
            ),
            default="monday",
        )
        schedule_action.add_argument("--at", default="09:00")
        schedule_action.add_argument("--anchor-date")
        schedule_action.add_argument("--provider", choices=("all", *PROVIDERS), default="all")
        schedule_action.add_argument("--safe-cleanup", action="store_true")
        schedule_action.add_argument("--retention-days", type=int, default=90)
        schedule_action.add_argument("--state-root")
        if name == "install":
            schedule_action.add_argument("--apply", action="store_true")
    schedule_status_parser = schedule_subcommands.add_parser("status")
    schedule_status_parser.add_argument("--state-root")
    schedule_uninstall_parser = schedule_subcommands.add_parser("uninstall")
    schedule_uninstall_parser.add_argument("--state-root")
    schedule_uninstall_parser.add_argument("--apply", action="store_true")
    schedule_uninstall_parser.add_argument(
        "--forget-orphaned",
        action="store_true",
    )

    skill_parser = subcommands.add_parser("skill", help="Plan or install the thin Skill")
    skill_subcommands = skill_parser.add_subparsers(dest="skill_command", required=True)
    for name in ("plan", "install"):
        skill_action = skill_subcommands.add_parser(name)
        skill_action.add_argument("--target", choices=("cursor", "claude", "codex"), required=True)
        skill_action.add_argument("--scope", choices=("user", "project"), default="user")
        skill_action.add_argument("--project")
        if name == "install":
            skill_action.add_argument("--apply", action="store_true")
            skill_action.add_argument("--allow-multipath", action="store_true")

    scheduled_parser = subcommands.add_parser(
        "scheduled-run",
        help="Run one scheduler-gated audit (used by installed jobs)",
    )
    scheduled_parser.add_argument("--state-root", required=True)
    return parser


def _doctor() -> dict[str, object]:
    root = state_root()
    return {
        "ok": True,
        "python": platform.python_version(),
        "platform": platform.system().lower(),
        "supported_python": sys.version_info >= (3, 10),
        "state": {
            "exists": root.exists(),
            "ownership_verified": verify_state_root(root) if root.exists() else False,
        },
        "network_required": False,
        "default_mutation_mode": "dry-run",
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "audit":
            report = _audit_from_args(args)
            _write_or_print(render(report, args.format), args.output)
            return _audit_exit(report, args.fail_on)

        if args.command == "dedupe":
            report = _audit_from_args(args)
            content = _render_plan(dedupe_plan(report), args.format)
            _write_or_print(content, args.output)
            return 0

        if args.command == "clean":
            if not 7 <= args.retention_days <= 3650:
                raise ValueError("retention-days must be between 7 and 3650")
            root = canonical_state_root(Path(args.state_root)) if args.state_root else state_root()
            plan = plan_cleanup(root, args.retention_days)
            payload: dict[str, object] = {"plan": plan.to_dict(), "applied": False}
            if args.apply:
                if not args.safe_only:
                    raise ValueError("--apply requires --safe-only")
                if not plan.state_verified:
                    raise RuntimeError("Refusing cleanup because state ownership is not verified")
                with RunLock(root):
                    plan = plan_cleanup(root, args.retention_days)
                    payload["plan"] = plan.to_dict()
                    payload["result"] = apply_cleanup(root, plan)
                payload["applied"] = True
            if args.format == "json":
                sys.stdout.write(_json(payload))
            else:
                sys.stdout.write(
                    f"Eligible owned files: {len(plan.candidates)}\n"
                    f"Eligible bytes: {sum(item.bytes for item in plan.candidates)}\n"
                    f"Applied: {payload['applied']}\n"
                )
            return 0

        if args.command == "doctor":
            sys.stdout.write(_json(_doctor()))
            return 0

        if args.command == "schedule":
            root = canonical_state_root(Path(args.state_root)) if args.state_root else state_root()
            if args.schedule_command in {"plan", "install"}:
                spec = _schedule_spec(args)
                plan = build_schedule_plan(spec, root)
                if args.schedule_command == "install" and args.apply:
                    plan["result"] = install_schedule(spec, root)
                    plan["applied"] = True
                else:
                    plan["applied"] = False
                sys.stdout.write(_json(plan))
                return 0
            if args.schedule_command == "status":
                sys.stdout.write(_json(schedule_status(root)))
                return 0
            if args.schedule_command == "uninstall":
                if args.apply:
                    result = (
                        forget_orphaned_schedule(root)
                        if args.forget_orphaned
                        else uninstall_schedule(root)
                    )
                else:
                    result = {
                        "applied": False,
                        "status": schedule_status(root),
                        "note": (
                            "Pass --apply to forget only after the OS entry is "
                            "gone or the backend is unavailable."
                            if args.forget_orphaned
                            else "Pass --apply to uninstall."
                        ),
                    }
                sys.stdout.write(_json(result))
                return 0

        if args.command == "skill":
            project = (
                Path(os.path.abspath(Path(args.project).expanduser())) if args.project else None
            )
            kwargs = {
                "target": args.target,
                "scope": args.scope,
                "home": Path.home(),
                "project": project,
            }
            if args.skill_command == "install" and args.apply:
                result = install_skill(
                    **kwargs,
                    allow_multipath=args.allow_multipath,
                )
            else:
                result = plan_skill_install(**kwargs)
            sys.stdout.write(_json(result))
            return 0

        if args.command == "scheduled-run":
            return _run_scheduled(canonical_state_root(Path(args.state_root)))
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        escaped = json.dumps(str(exc), ensure_ascii=True)[1:-1]
        sys.stderr.write(f"ach: {escaped}\n")
        return 2
    parser.error("unhandled command")
    return 64
