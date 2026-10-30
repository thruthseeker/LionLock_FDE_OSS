# Audit Logging Canonical Surface

## Canonical audit stream

The canonical tamper-evident audit log in OSS LionLock is `TrustVaultLogger` (`src/lionlock/logger.py`).
Each entry includes `prev_hash` and `sha256` so records are chained in append order.

Use `TrustVaultLogger.verify_chain()` to validate the on-disk chain. It detects entries that were
edited, inserted, reordered or removed from the start or middle. Appends are serialized across
threads and, on POSIX, across processes; a damaged last entry (for example from a crash mid-write)
stops further writes instead of silently starting a new chain.

A self-contained hash chain cannot detect that its newest entries were removed, or that the whole
log was rewritten with freshly computed hashes. To detect those, record `TrustVaultLogger.head()`
(entry count and last hash) somewhere the log's writer cannot change, and later pass it back:

```python
count, head = logger.head()          # store these elsewhere
logger.verify_chain(expected_head=head, expected_count=count)
```

A log that has grown since the head was recorded still verifies, as long as the recorded head is
still in it.

## Public telemetry stream

`src/lionlock/logging/event_log.py` writes sanitized public telemetry events for analysis. By
default they go to the local SQLite log `logs/lionlock.db`, which also holds Trust Overlay
records. Each table in that file is a per-table SHA-256 hash chain, checked with
`lionlock-telemetry verify` (see [TELEMETRY.md](TELEMETRY.md)). JSONL and SQL backends remain
available. This stream is privacy-focused and operational; `TrustVaultLogger` remains the
canonical audit chain.

## SQL sink delivery guarantees

### Native SQLite initialization and preservation

For the opt-in SQL telemetry sink, `sqlite:///...` initialization checks all existing
`lionlock_sessions`, `lionlock_signals` and `lionlock_failsafe` objects before creating or
altering any requested table. The table names must match their roles. Views, virtual tables,
`WITHOUT ROWID`/`STRICT` tables, and unknown column layouts are refused. Column names, normalized
declared types, primary keys and hidden/generated columns are checked through SQLite metadata;
column order is immaterial. Extra CHECK/UNIQUE constraints, indexes and triggers are retained.
These checks require SQLite 3.37 or newer (`table_list` and `table_xinfo`); an older engine is
refused before schema changes. A matching layout establishes structural compatibility, not
database ownership or the authenticity of its contents.

All three canonical tables are checked even when the operation requests only one or two. An
incompatible, unrequested failsafe table can therefore prevent writer startup or session writes.
**Upgrade compatibility:** extra custom columns are refused, even on a telemetry table that worked
previously with named-column inserts. This can turn startup into a `RuntimeError` through
`get_writer`. Review customized schemas and backups before upgrading; initialization does not
remove those columns or their data to make the schema fit.

The supported older layout is the initial OSS signals schema, which has `event_pk` and
`session_pk` but lacks `auth_token_id` and `auth_signature`. It is upgraded by adding those two
nullable columns, preserving the existing rows and keys. Initialization never rebuilds, drops
or renames a table. Unknown layouts, including unkeyed partial tables, need a separately reviewed
manual migration. A leftover `lionlock_signals_v2` table is left untouched, even if the original
signals table is absent; initialization does not recover its rows automatically.

Native initialization uses one connection, explicit `BEGIN IMMEDIATE`, and one commit or rollback.
Schema validation and requested DDL share that transaction. Session begin/update and failsafe
inserts validate under the same write lock as their DML. The connection timeout bounds startup
lock waits (five seconds by default; writer startup uses `connect_timeout_s`). Another writer can
therefore cause a startup refusal on timeout. No claim of power-loss durability follows from
transaction rollback tests, and running background batches do not revalidate a schema changed by
another actor after startup.
Session anomaly updates now initialize a missing sessions table, database file and parent
directory before the update; the previous bare update did not create that schema.

Refusals preserve the existing API contracts: `init_db` returns `(False, message)` and SQL writer
startup records its error, which `get_writer` propagates as `RuntimeError`. `begin_session` returns
`None` and `update_session_anomalies` returns silently, so their callers cannot distinguish a schema
refusal from other caught failures through the return value. A rejected `write_failsafe_blob`
returns `(False, message)` and does **not** persist the new blob. Callers must handle these outcomes;
unhandled telemetry startup errors can interrupt a caller even though scoring/gating are unchanged.

This preservation guard applies to the native `sqlite:///...` path. SQLAlchemy URI forms such as
`sqlite+pysqlite:///...`, PostgreSQL, and the separate Trust Overlay/Module 04 schema initializers
retain their existing behavior and are outside this guard. Existing production databases are not
migrated by installing this code; initialization runs only when invoked.
Relative file paths remain supported. `:memory:` initialization remains ephemeral; sessions and
failsafe writes do not report those connection-local records as persisted across calls.

### Delivery policy

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

Tamper and truncation checks are covered by `tests/test_logger.py` and
`tests/test_logger_integrity.py` (concurrent writers, damaged last entry, truncation and rewrite
against a recorded head).

SQL sink delivery guarantees are covered by `tests/test_sql_writer_reliability.py` (both sinks,
via sqlite3 and, when installed, SQLAlchemy), `tests/test_public_telemetry_persistence.py` and
`tests/test_trust_overlay_sql.py`.
