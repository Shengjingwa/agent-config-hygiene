---
name: agent-config-hygiene
description: Audit coding-agent Rules, Skills, instructions, and Memory metadata without exposing content or deleting provider state.
disable-model-invocation: true
---

# Agent configuration hygiene

Use the `ach` CLI as the source of truth. Do not recreate its filesystem logic in
chat or shell snippets.

This skill is read-only unless the user has authorized the exact mutation. An
audit or dry-run plan does not itself authorize cleanup, scheduling, or moving a
Skill. Check authorization before the mutation; do not ask again when the
existing authorization clearly covers the same scope.

1. Run `ach doctor`.
2. Run `ach audit --user --format human` for user configuration, adding repository
   paths only when the user asks for project auditing.
3. For duplicate Skills, run `ach dedupe plan`; present the candidates and let the
   user choose the physical owner. Never delete or move a Rule, Skill, instruction,
   plugin, session, or Memory automatically.
4. `ach clean` is a dry run and only covers this tool's ownership-marked state
   directory. Show the plan before `ach clean --apply --safe-only`; apply it only
   when the user's authorization covers that exact cleanup.
5. Scheduling changes are also dry-run by default. Show `ach schedule plan` before
   any `ach schedule install --apply` or `uninstall --apply`, then check the same
   authorization boundary before applying it.

Auditing and planning are complete when their command output has been reported.
If an audit finds a boundary or an ambiguous ownership case, report it and keep
the provider state unchanged; do not wait for approval unless the user asked for
a mutation.

Treat `opaque`, `managed`, `sensitive-skipped`, permission errors, symlinks,
Windows junctions, and name collisions as review boundaries—not permission to
broaden cleanup.
