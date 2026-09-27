# Audit Logging Canonical Surface

## Canonical audit stream

The canonical tamper-evident audit log in OSS LionLock is `TrustVaultLogger` (`src/lionlock/logger.py`).
Each entry includes `prev_hash` and `sha256` so records are chained in append order.

Use `TrustVaultLogger.verify_chain()` to validate the on-disk chain and detect tampering or truncation.

## Public telemetry stream

`src/lionlock/logging/event_log.py` writes sanitized public telemetry events for analysis. By
default they go to the local SQLite log `logs/lionlock.db`, which also holds Trust Overlay
records. Each table in that file is a per-table SHA-256 hash chain, checked with
`lionlock-telemetry verify` (see [TELEMETRY.md](TELEMETRY.md)). JSONL and SQL backends remain
available. This stream is privacy-focused and operational; `TrustVaultLogger` remains the
canonical audit chain.

## Verification coverage

Tamper and truncation checks are covered by `tests/test_logger.py`.
