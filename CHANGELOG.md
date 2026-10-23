# Changelog

## 1.0.0b2 — security and data-preservation fixes

Recommended for everyone on `1.0.0b1`. That release was published before everything below, so an
install pinned to it still fails open on the three settings in the first group.

**If you use the opt-in `sqlite:///...` telemetry sink with a customized schema, read the
Compatibility note before upgrading.**

### Fixed

- **The opt-in SQL telemetry sink could destroy existing tables on initialization.** The native
  `sqlite:///...` path rebuilt its tables, dropping and recreating them. Initialization now checks
  the existing `lionlock_sessions`, `lionlock_signals` and `lionlock_failsafe` objects against
  their roles first and **never rebuilds, drops or renames a table**. A keyed table missing
  `auth_token_id` and `auth_signature` is upgraded by adding those two nullable columns, preserving
  existing rows and keys, and a leftover `lionlock_signals_v2` is left untouched. The guard covers
  the native `sqlite:///...` path only; SQLAlchemy URI forms such as `sqlite+pysqlite:///...`,
  PostgreSQL and the Trust Overlay initializers are unchanged.
- **Uploads could switch themselves on.** `telemetry_upload.enabled` went through `bool()`, so a
  quoted `"false"`, `"no"`, `"0"` or `"off"` in a config file enabled uploads. Only a real boolean
  or a recognised true word enables them now; anything else leaves them off.
- **Pruning could switch itself off.** A negative `sqlite_max_rows` collapsed to `0`, which means
  "keep every row". `LogStore` now rejects a negative limit and `open_store` falls back to the
  default.
- **A receiver's upload rate limit could be reset at will.** In token mode the limit counts per
  token, so rotating an install id no longer clears it. Anonymous mode can only count per
  client-chosen install id, which is bypassable by design: require tokens on any internet-facing
  endpoint.
- `decide_gate` declares all five inputs it is missing for a metadata-free payload, not only the
  three fatigue inputs. Decisions themselves are unchanged.
- The README's quick-start example now runs as written, and the claim that logging happens
  automatically is corrected.

### Added

- An agent-agnostic development harness. `make verify` is one gate over tests, lint, type checks,
  determinism, privacy and file scope, and it behaves identically for every contributor.
- A runtime check that scoring and gating reach no network, rather than only a claim that they do
  not: the scoring path is imported in a child process with the socket layer patched, and the
  third-party compiled extensions it loads are pinned so that a new binary fails a test instead of
  arriving unnoticed.
- CI refuses an unapproved change to the harness contract lock, so a change cannot edit a protected
  file and then re-bless itself by regenerating the lock.
- Releases are built and uploaded by GitHub Actions through PyPI Trusted Publishing, so no API
  token has to be stored.

### Changed

- Two claims about the no-network guarantee were stronger than the evidence and have been narrowed
  to what is actually proved. Parsing imports cannot see a module reaching the network through a
  dependency it never names, and a third-party compiled extension *is* loaded on the scoring path
  (`pydantic_core`), which name-based audits cannot speak to either way. Both gaps are now stated
  as open, and the extension surface is pinned by a test.

### Compatibility

- **Extra custom columns on a telemetry table are now refused**, even where named-column inserts
  worked before. This can turn startup into a `RuntimeError` through `get_writer`. Review
  customized schemas and take a backup before upgrading: initialization will not remove columns or
  their data to make a schema fit, and unknown layouts need a separately reviewed manual migration.
- Receivers admit `1.0.0b2` as a public version label. **Upgrade a receiver before its clients**,
  because an older receiver rejects snapshots that carry the new label.

## 1.0.0b1 — first public beta

The first public beta of open-source LionLock. Interfaces may still change before 1.0.0.

- Local, hash-chained SQLite telemetry log, with opt-in uploads of allowlisted, pseudonymized
  fields to a receiver you run (`lionlock-telemetry`).
- Reference ingest server that validates every upload as untrusted input and stores only
  rebuilt, validated snapshots.
- `lionlock-telemetry bigquery-sync`: copies the receiver's warehouse into BigQuery. Each
  `events` and `trust_records` row is loaded exactly once, and `uploads` is replaced as a
  snapshot whenever it changes.
- `low_conf_halluc` no longer flags grounded answers, and the uncalibrated `fatigue_risk_index`
  no longer gates when its inputs are missing (signal schema `SE-0.4.0`).
- Receivers admit `1.0.0b1` as a public version label. Upgrade a receiver before its clients,
  because an older receiver rejects snapshots that carry the new label.

## 0.1.0

Initial open-source preview.
