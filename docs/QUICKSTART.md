# LionLock 5-Minute Quickstart

This quickstart runs a local fixture set through the OSS flow:

1. Signal scoring (Module 02)
2. Gating decision (Module 05)
3. Public telemetry logging to the local SQLite file `logs/lionlock.db`
4. Trust Overlay record generation

## Run

```bash
PYTHONPATH=src python examples/quickstart.py
```

Expected output format:

```text
Quickstart summary: FLAGGED=<n> CLEAN=<n>
Telemetry log: logs/lionlock.db
```

## Look at the log

```bash
lionlock-telemetry status    # row counts and upload state (uploads are off by default)
lionlock-telemetry verify    # check the log's hash chains
lionlock-telemetry preview   # what an upload would contain, if you ever opt in
```

See [TELEMETRY.md](TELEMETRY.md) for the log format and the opt-in upload pipeline.

## Fixture dataset

Fixture data lives at:

- `tests/fixtures/sample_sessions.json`

Each record contains:

- `id`
- `text`
- `label` (`FLAGGED` or `CLEAN`)
- optional `notes`
