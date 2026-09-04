# Local scheduling

Cloud agents cannot inspect the current machine's user configuration. `ach`
therefore installs only local, current-user scheduling.

All scheduling commands are previews unless `--apply` is present.

## Common workflow

```console
ach schedule plan --every-weeks 2 --weekday monday --at 09:00 --anchor-date 2026-09-14
ach schedule install --every-weeks 2 --weekday monday --at 09:00 --anchor-date 2026-09-14 --apply

ach schedule status
```

Uninstallation is also two-step:

```console
ach schedule uninstall
ach schedule uninstall --apply
```

If a state directory was moved to an operating system that cannot manage the
recorded backend, `ach schedule uninstall --forget-orphaned --apply` removes only
the local configuration record. It never claims to remove the old machine's OS
entry. On a compatible system, this escape hatch works only after absence of the
OS entry is verified.

## Interval model

Task Scheduler, launchd, and cron differ in multi-week support. The installed OS
trigger runs once per selected weekday. `ach scheduled-run` checks the anchor
date and `every_weeks`, then skips non-due weeks.

The runner records the last local date and refuses a second run that day. An
OS-released advisory lock prevents overlap and does not become stale after a
crash. Reports use one deterministic filename per local day, so a retry after a
state-write failure replaces that day's report instead of creating duplicates.

Scheduler identities are derived from the canonical state-root path, so separate
state roots do not overwrite each other. Changing backend requires an explicit
uninstall first; replacement and deletion verify the stored identity and the OS
entry. Installer and uninstaller operations also share a per-user advisory lock,
preventing concurrent operations for different state roots from losing scheduler
changes.

## Backends

### Windows

Creates a current-user, limited Task Scheduler task named
`AgentConfigHygiene-<state-id>`. It invokes the exact Python executable that
installed the schedule, runs only while that user is logged on, and does not
store a password.

### macOS

Creates
`~/Library/LaunchAgents/dev.agent-config-hygiene.audit.<state-id>.plist` and
loads it in the current user's GUI domain. It never creates a LaunchDaemon.

### Linux

Adds one line carrying `# agent-config-hygiene:<state-id>` to the current user's
crontab. Installation preserves unrelated lines; uninstall removes only that
state root's marked line. Cron scheduling rejects executable or state paths that
contain `%`, because cron treats percent signs as command delimiters.

## Cleanup

Scheduled audit does not clean by default. `--safe-cleanup` enables rotation of
expired reports, temporary files, and quarantine files inside the verified
`~/.agent-config-hygiene` state root. It never expands cleanup to a provider
directory.
