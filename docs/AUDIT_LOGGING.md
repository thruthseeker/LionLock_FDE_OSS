# Audit Logging Canonical Surface

## Canonical audit stream

The canonical tamper-evident audit log in OSS LionLock is `TrustVaultLogger` (`src/lionlock/logger.py`).
Each entry includes `prev_hash` and `sha256` so records are chained in append order.

Use `TrustVaultLogger.verify_chain()` to validate the on-disk chain and detect tampering or truncation.

## Public telemetry stream

`src/lionlock/logging/event_log.py` writes sanitized public telemetry JSONL/SQL events for analysis.
This stream is privacy-focused and operational, but it is **not** the canonical tamper-evident audit chain.

## Verification coverage

Tamper and truncation checks are covered by `tests/test_logger.py`.
