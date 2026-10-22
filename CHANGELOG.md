# Changelog

## 1.0.0b2 — security fixes

Recommended for everyone on `1.0.0b1`. That release was published before the fixes below, so an
install pinned to it still fails open on the first three settings.

### Fixed

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
- Releases are built and uploaded by GitHub Actions through PyPI Trusted Publishing, so no API
  token is stored anywhere.

### Compatibility

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
