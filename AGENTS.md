# Agent guidance

`ach` audits coding-agent configuration without exposing its content or deleting
provider state.

Before changing discovery behavior, read `docs/discovery-contract.md`. Before
changing filesystem reads, reporting, cleanup, or scheduling, read `PRIVACY.md`
and `SECURITY.md`.

Keep the runtime dependency-free and compatible with Python 3.10. Run:

```console
python -m unittest discover -s tests -p "test_*.py" -v
python -m compileall -q src tests scripts
python -m build
python scripts/verify_distribution.py
```

Every new mutation must default to dry-run, operate only on tool-owned state, and
have a fail-closed regression test. Never use real credentials, chats, sessions,
or Memory text as fixtures.
