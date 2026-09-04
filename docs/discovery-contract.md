# Discovery contract

This document defines what version 1 scans. It is a compatibility contract, not
a claim that undocumented provider storage is safe to edit.

## Cursor

Cursor documents project and user Skills in `.cursor/skills` and
`.agents/skills`. For compatibility it also discovers `.claude/skills` and
`.codex/skills`, including user-level equivalents.

`ach` therefore models one physical Skill as potentially having several Cursor
discovery routes. Cursor does not document a cross-root same-name precedence or
a hidden-directory exclusion, so collisions are reported rather than resolved.

File-based Rules under `.cursor/rules` are parsed only through bounded
frontmatter. Personal Rules, Team Rules, and IDE Memory have no supported local
file interface in the public documentation; they are represented as opaque state.
Cursor-managed Skills, plugin caches, projects, and chats are counted as protected
state and never cleaned.

Sources:

- <https://cursor.com/docs/skills>
- <https://cursor.com/docs/rules>
- <https://cursor.com/help/customization/rules>

## Claude Code

Claude Code documents:

- user Skills at `~/.claude/skills`;
- project Skills at `.claude/skills`;
- user instructions at `~/.claude/CLAUDE.md` and `~/.claude/rules`;
- project instructions in `CLAUDE.md`, `.claude/CLAUDE.md`,
  `CLAUDE.local.md`, and `.claude/rules`;
- Auto Memory under `~/.claude/projects/<project>/memory`;
- agent Memory under user and project `agent-memory` directories.

Synced Skills and plugin caches are provider-managed. Memory is reported by
count, bytes, and modification time only. The scanner does not read Memory text,
plugin settings, or hook commands.

Sources:

- <https://code.claude.com/docs/en/skills>
- <https://code.claude.com/docs/en/memory>
- <https://code.claude.com/docs/en/settings>
- <https://code.claude.com/docs/en/plugins-reference>

## Codex

Codex documents `.agents/skills` as its current user and project Skill root. The
open-source implementation still supports `$CODEX_HOME/skills` and project
`.codex/skills` as legacy roots. Same-name Skills are not merged.

`ach` scans:

- `AGENTS.md` and `AGENTS.override.md`;
- `.agents/skills` as native Skills;
- `.codex/skills` as legacy Skills;
- `.codex/rules` and `$CODEX_HOME/rules`;
- Memory, thread, session, and archive directories as protected metadata.

`$CODEX_HOME/skills/.system` is provider-managed and never modified.

Sources:

- <https://developers.openai.com/codex/skills>
- <https://developers.openai.com/codex/guides/agents-md>
- <https://developers.openai.com/codex/rules>
- <https://developers.openai.com/codex/memories>
- <https://github.com/openai/codex/blob/main/codex-rs/ext/skills/src/host_roots.rs>

## Duplicate classification

Within one user or repository scope:

- `SKILL_ALIAS_DUPLICATE`: multiple paths resolve to one real directory.
- `SKILL_EXACT_DUPLICATE`: bounded directory fingerprints match.
- `SKILL_NAME_COLLISION`: names match but content differs or could not be fully
  fingerprinted.

The report never chooses a winner. A valid choice depends on which agents must
discover the Skill:

- Cursor-native owner: `.cursor/skills`
- Claude-native owner: `.claude/skills`
- Codex-native owner: `.agents/skills`

There is no single native root shared by all three. Cursor's compatibility scan
means that three physical copies are especially likely to create duplicate
discovery. `ach skill install` therefore installs one target at a time and blocks
multi-root copies by default.
