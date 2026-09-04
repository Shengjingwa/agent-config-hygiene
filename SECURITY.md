# Security policy

## Supported versions

Until 1.0, only the latest release receives security fixes.

## Threat model

Audited repositories and Agent configuration are untrusted input. A malicious
repository may contain oversized files, malformed frontmatter, links outside the
repository, hostile filenames, hooks, or executable Skill scripts.

The scanner:

- never executes audited files, hooks, plugins, or commands;
- does not load YAML through an object-deserializing parser;
- bounds frontmatter and fingerprint reads;
- does not follow filesystem symlinks or Windows junctions during discovery;
- reports links that escape an expected root;
- performs no network requests;
- defaults every mutating command to dry-run.

Cleanup has a smaller trust boundary: it only accepts files under the tool's own
verified state root and revalidates file identity, link count, owner, and parent
directories immediately before unlinking. State and scheduler files must be
single-link regular files owned by the current Unix user or Windows security
principal.

The state-root boundary assumes the host ACL does not grant write access to
untrusted principals. The ownership check is not a general-purpose Windows DACL
auditor; do not point `ACH_STATE_DIR` at a shared writable directory.

The tool does not claim to resist a malicious process already running as the
same operating-system account and racing filesystem mutations while a command is
in progress. Do not run audits or cleanup while an untrusted same-account
process can rewrite the selected repository or tool state.

## Reporting a vulnerability

Use GitHub private vulnerability reporting from the repository's **Security**
tab. Include the affected version, platform, reproduction, and expected safety
boundary. Do not put credentials, Memory text, chat content, or an unredacted
audit report in a public issue.

Public issues are appropriate for non-sensitive correctness bugs.
