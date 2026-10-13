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

## SQL sink delivery guarantees

The opt-in SQL sinks (`logging_sql` for public telemetry, `trust_overlay.sql` for Trust Overlay
records) queue events in memory and insert them in batches from a background thread. Both share
one delivery policy, `src/lionlock/utils/sql_batch_writer.py`:

- **Every accepted event is accounted for exactly once**, as `written`, `duplicates` (already
  stored: rejected by a UNIQUE or PRIMARY KEY constraint), `failed` (a write was attempted but
  the row was not persisted), `in_doubt` (the COMMIT failed without a known outcome, so the row
  may or may not be stored) or `dropped` (never attempted). Until then it is `pending`, so
  `enqueued == written + duplicates + failed + in_doubt + dropped + pending` always holds.
- **Shutdown flushes.** `stop_writer()`, which also runs at interpreter exit, writes everything
  still queued before returning, bounded by `stop_timeout_s`. Events it cannot start writing in
  time are counted as `dropped_on_stop`.
- **Transient errors are retried, not fatal.** Lock contention (`database is locked`) and lost
  connections are retried up to `max_retries` times with exponential backoff: `retry_backoff_ms`,
  doubling per retry, capped at 2 s, with no jitter. Write errors never disable the writer and
  never raise into `log_event()` or `append_trust_record()`.
- **No write is stored twice.** A write is retried only when it is known to have stored nothing.
  If the COMMIT itself fails without a known outcome, for example because the connection was
  lost, the rows may already be stored, so the write is not retried and its events are counted
  as `in_doubt`.
- **One bad row cannot sink its batch.** A non-transient batch error, such as a UNIQUE violation,
  rolls the batch back and re-inserts it row by row. True duplicates are skipped and counted as
  `duplicates`, other constraint failures are counted as `failed`, and every other row is written.
- **Overflow is reported.** When the queue (`max(100, 10 * batch_size)` events) is full, the
  oldest queued event is evicted to keep the newest data. Each eviction is counted as
  `dropped_queue_full` and logged as a warning at the 1st, 2nd, 4th, 8th, ... drop.

Startup failures differ by sink. For public telemetry, invalid configuration and startup failures
raise `RuntimeError` from `log_event()`, and the next call tries to start a writer again. Trust
Overlay never raises for SQL problems: if its SQL writer cannot start, `append_trust_record()`
still writes the JSONL record but nothing reaches SQL, and
`lionlock.trust_overlay.sql_sink.get_writer()` returns `None` until the `[trust_overlay.sql]`
configuration changes or `stop_writer()` is called.

Read the counters with `lionlock.logging.sql_telemetry.writer_stats()` or
`lionlock.trust_overlay.sql_sink.writer_stats()`. `stop_writer()` returns the counters when it
returns; they are final unless `pending` is non-zero, which means a write was still running at the
deadline. That write is not interrupted, and its outcome is logged as `sql_sink_late_outcome` when
it finishes. `writer.last_error` holds the most recent write error without data values: the error
type, its SQLite or SQLSTATE code when available, and the first line of the driver message cut at
the first quote.

Optional keys, accepted by both `[logging_sql]` and `[trust_overlay.sql]`:

| Key | Default | Meaning |
| --- | --- | --- |
| `max_retries` | `5` | Retries per write after a transient error. |
| `retry_backoff_ms` | `50` | First retry delay; doubles per retry, capped at 2 s. |
| `stop_timeout_s` | `2.0` | Upper bound on the flush done by `stop_writer()` and at exit. |

## Verification coverage

Tamper and truncation checks are covered by `tests/test_logger.py`.

SQL sink delivery guarantees are covered by `tests/test_sql_writer_reliability.py` (both sinks,
via sqlite3 and, when installed, SQLAlchemy), `tests/test_public_telemetry_persistence.py` and
`tests/test_trust_overlay_sql.py`.
