# agent-config-hygiene

`ach` is an offline, cross-platform hygiene auditor for Cursor, Claude Code, and
Codex configuration. It finds invalid metadata, oversized always-loaded rules,
legacy paths, unsafe links, and Skills discovered from multiple roots.

It does **not** let an AI decide what to delete.

## Safety model

- Audit is the default; provider configuration is read-only.
- Reports contain path aliases and bounded metadata, never absolute paths or
  configuration-body/free-text values.
- Provider credential stores, chats, sessions, internal databases, and Memory
  bodies are never opened.
- Rules, Skills, plugins, instructions, and provider Memory are never
  automatically deleted or moved.
- `ach clean --apply --safe-only` can remove only expired files inside this
  tool's own directory after verifying its ownership marker and filesystem
  owner.
- No telemetry, network calls, remote policy updates, or project hooks.

Read the [privacy policy](https://github.com/Shengjingwa/agent-config-hygiene/blob/main/PRIVACY.md)
and [security policy](https://github.com/Shengjingwa/agent-config-hygiene/blob/main/SECURITY.md)
before enabling a schedule.

## Install

Python 3.10 or newer is required.

```console
python -m pip install .
ach doctor
```

For an isolated CLI installation from GitHub:

```console
pipx install git+https://github.com/Shengjingwa/agent-config-hygiene.git
```

## Audit

Audit the current project:

```console
ach audit
```

Audit user configuration for all three agents:

```console
ach audit --user
```

Audit user configuration and selected repositories as JSON:

```console
ach audit --user --format json --output audit.json /path/to/repo
```

Produce SARIF and fail CI only on high-severity findings:

```console
ach audit --format sarif --output ach.sarif --fail-on high
```

Plan Skill de-duplication without changing files:

```console
ach dedupe plan --user
```

## Skill integration without three copies

Cursor discovers Skills from Cursor, Agents, Claude, and Codex roots. Installing
the same Skill separately for every agent can therefore make Cursor discover it
multiple times.

This repository ships one canonical, user-invoked Skill. Choose one integration:

```console
ach skill plan --target cursor
ach skill install --target cursor --apply
```

Supported targets are:

- `cursor`: `~/.cursor/skills`
- `claude`: `~/.claude/skills`
- `codex`: `~/.agents/skills`, the current documented Codex root

The installer refuses a second physical copy by default. The CLI remains usable
from all agents even when no Skill is installed for them.

## Local scheduling

Scheduling is also dry-run first:

```console
ach schedule plan --every-weeks 2 --weekday monday --at 09:00 --anchor-date 2026-09-14
```

Install only after reviewing the generated command:

```console
ach schedule install --every-weeks 2 --weekday monday --at 09:00 --anchor-date 2026-09-14 --apply
```

Backends:

- Windows: current-user Task Scheduler task
- macOS: user LaunchAgent
- Linux: marked user crontab entry

The operating-system trigger runs weekly. `scheduled-run` enforces the anchor and
multi-week interval, uses an OS-released advisory lock, and writes a redacted
JSON report.
Automatic cleanup remains disabled unless `--safe-cleanup` is explicitly added,
and even then it only rotates this tool's own state.

See the
[scheduling guide](https://github.com/Shengjingwa/agent-config-hygiene/blob/main/docs/scheduling.md)
for backend and uninstall details.

## What is inspected

- Cursor: file-based Rules, native and compatible Skills, managed-state metadata,
  and an opaque marker for UI-only Rules and Memories.
- Claude Code: `CLAUDE.md`, rules, Skills, plugin-cache metadata, and Memory
  directory metadata.
- Codex: `AGENTS.md`, command rules, native and legacy Skills, and
  Memory/session directory metadata.

Provider discovery details and source links are in the
[discovery contract](https://github.com/Shengjingwa/agent-config-hygiene/blob/main/docs/discovery-contract.md).

## 中文说明

`ach` 用于定期检查 Cursor、Claude Code 和 Codex 的规则、Skill、说明文件与 Memory
元数据。默认只读，不读取聊天、凭证或 Memory 正文，也不会自动删除 Agent 配置。

推荐流程：

1. `ach audit --user`
2. `ach dedupe plan --user`
3. 人工选择唯一 Skill 所有者并先归档
4. 重新审计并分别验证三个 Agent 的发现结果
5. 确认无误后再设置本地定时任务

## Development

```console
python -m unittest discover -s tests -p "test_*.py" -v
python -m compileall -q src tests
python -m build
python scripts/verify_distribution.py
```

The project has no runtime dependencies.

## License

Apache-2.0. See the
[license](https://github.com/Shengjingwa/agent-config-hygiene/blob/main/LICENSE).
