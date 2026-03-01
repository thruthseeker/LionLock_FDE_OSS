# LionLock 5-Minute Quickstart

This quickstart runs a local fixture set through the OSS flow:

1. Signal scoring (Module 02)
2. Gating decision (Module 05)
3. Public telemetry JSONL logging
4. Trust Overlay record generation

## Run

```bash
PYTHONPATH=src python examples/quickstart.py
```

Expected output format:

```text
Quickstart summary: FLAGGED=<n> CLEAN=<n>
```

## Fixture dataset

Fixture data lives at:

- `tests/fixtures/sample_sessions.json`

Each record contains:

- `id`
- `text`
- `label` (`FLAGGED` or `CLEAN`)
- optional `notes`
