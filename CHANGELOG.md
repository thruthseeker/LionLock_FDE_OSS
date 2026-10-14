# Changelog

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
