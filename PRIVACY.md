# Privacy contract

`agent-config-hygiene` is offline. It has no telemetry, update check, crash upload,
analytics endpoint, or network client.

## Data the auditor reads

- Up to 64 KiB from a Rule or `SKILL.md` to parse bounded frontmatter.
- Regular files in a Skill tree, up to 4 MiB per file and 32 MiB per tree, only
  to calculate an in-memory duplicate fingerprint.
- File metadata such as size, modification time, link status, and directory
  location.

Fingerprints are used only for comparison during that run. Raw fingerprints,
absolute paths, and configuration-body/free-text values are not written to
reports.

Reports do include sanitized relative filenames and validated Skill identifiers.
These identifiers support local correlation and are not an anonymity boundary.

## Data the auditor does not read

- documented provider credential stores, tokens, authentication files, or
  environment values;
- chats, session JSONL, checkpoints, threads, or internal databases;
- Cursor UI Rules or internal IDE Memory;
- Claude Code or Codex Memory bodies;
- plugin settings, hook commands, or project-provided executables.

An untrusted Skill directory can contain arbitrary filenames. Its regular files
may be read only for the bounded duplicate fingerprint described above, so do not
store credentials inside Skills. Memory and session directories are traversed for
file count, total bytes, and newest modification time; those files are not opened.

## Report paths

Paths under the home directory are written as `~/...`. Paths under an audited
repository are written as `<repo>/...`. Unknown external targets use a
pseudonymous identifier rather than an absolute path. Identifiers are for report
correlation, not anonymity.

SARIF omits virtual and external locations.

## Cleanup

Cleanup is limited to `~/.agent-config-hygiene` or `ACH_STATE_DIR`. The directory
must contain the exact ownership marker created by this tool. Before each unlink,
the tool rechecks:

- the target remains under the verified state root;
- it is a regular file, not a symlink or Windows junction;
- device, inode, size, and modification time still match the plan.

Provider files are outside this cleanup policy.

## Security reports

If a report unexpectedly contains private data, stop using it and follow
[SECURITY.md](SECURITY.md). Do not attach the report to a public issue.
