# Contributing

Contributions are welcome when they preserve the safety boundary.

## Development

```console
python -m venv .venv
python -m pip install -e .
python -m unittest discover -s tests -p "test_*.py" -v
```

Use conventional commits.

## Required properties

Changes must keep these statements true:

- audit is offline and read-only for provider configuration;
- dry-run is the default for every mutation;
- no credential, chat, session, database, or Memory body is opened;
- reports contain no absolute paths or configuration-body/free-text values;
- cleanup is limited to verified tool-owned state;
- provider discovery claims cite primary documentation;
- unknown or partial coverage fails closed.

Add a regression test that goes red when a new guard is removed. Filesystem tests
must cover links, path replacement, unreadable input, and Unicode paths where
relevant.

## Pull requests

Explain:

1. the provider contract or safety issue;
2. the primary source or reproduction;
3. the new test;
4. whether report schema or cleanup policy changed.

Do not include real Agent configuration, credentials, chats, or Memory in fixtures.
