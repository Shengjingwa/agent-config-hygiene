---
name: agent-config-hygiene
description: Audit coding-agent Rules, Skills, instructions, and Memory metadata without exposing content or deleting provider state.
disable-model-invocation: true
---

# Agent configuration hygiene

Use the `ach` CLI as the source of truth. Do not recreate its filesystem logic in
chat or shell snippets.

1. Run `ach doctor`.
2. Run `ach audit --user --format human` for user configuration, adding repository
   paths only when the user asks for project auditing.
3. For duplicate Skills, run `ach dedupe plan`; present the candidates and let the
   user choose the physical owner. Never delete or move a Rule, Skill, instruction,
   plugin, session, or Memory automatically.
4. `ach clean` is a dry run and only covers this tool's ownership-marked state
   directory. Use `ach clean --apply --safe-only` only after showing the plan.
5. Scheduling changes are also dry-run by default. Show `ach schedule plan` before
   any `ach schedule install --apply` or `uninstall --apply`.

Treat `opaque`, `managed`, `sensitive-skipped`, permission errors, symlinks,
Windows junctions, and name collisions as review boundaries—not permission to
broaden cleanup.
