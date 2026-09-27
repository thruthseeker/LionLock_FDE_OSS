"""Delivery guarantees shared by both opt-in SQL sinks.

``SQLTelemetryWriter`` and ``TrustOverlaySQLWriter`` delegate delivery to
``lionlock.utils.sql_batch_writer.SQLBatchWriter``. Every test below runs against
a real SQLite database for both sinks (and through SQLAlchemy when installed).
Faults are injected deterministically by wrapping ``_write_batch``, and each
test checks the conservation law
``enqueued == written + duplicates + failed + dropped + pending``.
"""

from __future__ import annotations

import importlib.util
import logging
import sqlite3
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List

import pytest

from lionlock.logging.sql_telemetry import PUBLIC_SIGNALS_COLUMNS, SQLTelemetryWriter
from lionlock.trust_overlay.sql_sink import TRUST_OVERLAY_COLUMNS, TrustOverlaySQLWriter
from lionlock.utils.sql_batch_writer import (
    MAX_RETRY_BACKOFF_S,
    SQLBatchWriter,
    describe_error,
    is_duplicate_error,
    is_transient_error,
)

HAS_SQLALCHEMY = importlib.util.find_spec("sqlalchemy") is not None
requires_sqlalchemy = pytest.mark.skipif(not HAS_SQLALCHEMY, reason="SQLAlchemy not installed")

SINK_KINDS = [
    pytest.param(("telemetry", "sqlite3"), id="telemetry-sqlite3"),
    pytest.param(("trust_overlay", "sqlite3"), id="trust_overlay-sqlite3"),
    pytest.param(("telemetry", "sqlalchemy"), id="telemetry-sqlalchemy", marks=requires_sqlalchemy),
    pytest.param(
        ("trust_overlay", "sqlalchemy"), id="trust_overlay-sqlalchemy", marks=requires_sqlalchemy
    ),
]
# family -> (table, key column, column definitions)
SCHEMAS = {
    "telemetry": ("lionlock_signals", "request_id", PUBLIC_SIGNALS_COLUMNS),
    "trust_overlay": ("trust_overlay_records", "session_id", TRUST_OVERLAY_COLUMNS),
}


@dataclass
class Sink:
    writer: SQLBatchWriter
    family: str
    backend: str
    db_path: Path
    table: str
    key_column: str

    def event(self, key: str) -> Dict[str, Any]:
        if self.family == "telemetry":
            return {
                "timestamp_utc": "2025-12-19T00:00:00Z",
                "request_id": key,
                "decision": "ALLOW",
                "severity": "green",
                "reason_code": "ok",
                "aggregate_score": 0.1,
                "signal_scores": {"repetition_loopiness": 0.1},
                "config_hash": "hash",
                "duration_ms": 1,
            }
        return {
            "timestamp": "2025-12-19T00:00:00Z",
            "session_id": key,
            "turn_index": 1,
            "model_id": "model-1",
            "prompt_type": "qa",
            "trust_score": 0.9,
            "trust_label": "TRUSTED",
        }

    def keys(self) -> List[str]:
        """Keys of the stored rows, in insertion order."""
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute(
                f"SELECT {self.key_column} FROM {self.table} ORDER BY rowid"
            ).fetchall()
        return [row[0] for row in rows]

    def insert_existing(self, key: str) -> None:
        with closing(sqlite3.connect(self.db_path)) as conn:
            with conn:
                conn.execute(f"INSERT INTO {self.table} ({self.key_column}) VALUES (?)", (key,))

    def transient_error(self) -> Exception:
        """What a driver raises for "database is locked" on this sink's backend."""
        locked = sqlite3.OperationalError("database is locked")
        if self.backend == "sqlalchemy":
            from sqlalchemy import exc

            return exc.OperationalError("INSERT", {}, locked)
        return locked


@pytest.fixture(params=SINK_KINDS)
def make_sink(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Callable[..., Sink]]:
    family, backend = request.param
    writers: List[SQLBatchWriter] = []

    def factory(table_constraint: str = "", **options: Any) -> Sink:
        db_path = tmp_path / "sink.db"
        table, key_column, columns = SCHEMAS[family]
        if table_constraint:
            # Pre-create the table; the writer's CREATE TABLE IF NOT EXISTS keeps it.
            definitions = [f"{name} {col_type}" for name, col_type in columns]
            definitions.append(table_constraint.format(key=key_column))
            with closing(sqlite3.connect(db_path)) as conn:
                conn.execute(f"CREATE TABLE {table} ({', '.join(definitions)})")
        # By default nothing flushes until the batch fills or the test stops the writer.
        settings: Dict[str, Any] = {
            "batch_size": 1000,
            "flush_interval_ms": 60_000,
            "retry_backoff_ms": 1,
        }
        settings.update(options)
        writer: SQLBatchWriter
        if family == "telemetry":
            scheme = "sqlite" if backend == "sqlite3" else "sqlite+pysqlite"
            writer = SQLTelemetryWriter(
                f"{scheme}:///{db_path}",
                table,
                "lionlock_sessions",
                connect_timeout_s=1,
                **settings,
            )
        else:
            writer = TrustOverlaySQLWriter(
                backend=backend,
                dsn=f"sqlite:///{db_path}" if backend == "sqlalchemy" else "",
                sqlite_path=str(db_path) if backend == "sqlite3" else None,
                table=table,
                connect_timeout_s=1,
                **settings,
            )
        assert writer.available, writer.error
        writers.append(writer)
        return Sink(writer, family, backend, db_path, table, key_column)

    yield factory
    for writer in writers:
        writer.stop(timeout_s=5)


def wrap_writes(
    monkeypatch: pytest.MonkeyPatch,
    writer: SQLBatchWriter,
    before: Callable[[int, List[Dict[str, Any]]], None],
) -> List[float]:
    """Run ``before(call_number, events)`` ahead of every real write (it may raise
    or block). Returns the monotonic start time of each write call."""
    real_write = writer._write_batch
    starts: List[float] = []

    def write(events: List[Dict[str, Any]]) -> None:
        starts.append(time.monotonic())
        before(len(starts), events)
        real_write(events)

    monkeypatch.setattr(writer, "_write_batch", write)
    return starts


def wait_for(predicate: Callable[[], bool], timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached before timeout")
        time.sleep(0.01)


def assert_conserved(stats: Dict[str, int]) -> None:
    """Every accepted event is accounted for exactly once."""
    accounted = sum(
        stats[name] for name in ("written", "duplicates", "failed", "dropped", "pending")
    )
    assert stats["enqueued"] == accounted, stats


def test_stop_flushes_the_last_partial_batch(make_sink: Callable[..., Sink]) -> None:
    sink = make_sink(batch_size=10)
    keys = [f"evt-{i:02d}" for i in range(25)]
    for key in keys:
        assert sink.writer.enqueue(sink.event(key))

    # 25 events with batch_size=10: at most two full batches can flush on their own;
    # the last five are only written because stop() flushes before returning.
    sink.writer.stop()

    assert sink.keys() == keys
    assert sink.writer.thread is not None and not sink.writer.thread.is_alive()
    stats = sink.writer.stats()
    assert (stats["written"], stats["dropped"], stats["failed"], stats["pending"]) == (25, 0, 0, 0)
    assert_conserved(stats)
    assert sink.writer.enqueue(sink.event("after-stop")) is False


def test_stop_is_time_bounded_when_a_write_hangs(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(batch_size=2)
    writer = sink.writer
    entered, release = threading.Event(), threading.Event()

    def hang_first_write(call: int, events: List[Dict[str, Any]]) -> None:
        if call == 1:
            entered.set()
            release.wait(timeout=30)  # A database call that hangs.

    wrap_writes(monkeypatch, writer, hang_first_write)
    keys = [f"evt-{i}" for i in range(5)]
    try:
        for key in keys:
            assert writer.enqueue(sink.event(key))
        assert entered.wait(timeout=10)  # The worker is stuck inside batch [evt-0, evt-1].

        started = time.monotonic()
        writer.stop(timeout_s=0.2)
        elapsed = time.monotonic() - started

        assert elapsed < 2.0  # Nominally 0.2s; the hung write cannot hold stop() hostage.
        stats = writer.stats()
        assert stats["dropped_on_stop"] == 3  # evt-2..4 could not start before the deadline.
        assert stats["pending"] == 2  # The hung batch is still in flight, not lost.
        assert_conserved(stats)
    finally:
        release.set()

    assert writer.thread is not None
    writer.thread.join(timeout=10)
    assert not writer.thread.is_alive()
    assert sink.keys() == keys[:2]
    final = writer.stats()
    assert (final["written"], final["dropped"], final["pending"]) == (2, 3, 0)
    assert_conserved(final)


def test_stop_deadline_ends_retries_of_a_persistent_failure(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(batch_size=1, max_retries=1_000_000, retry_backoff_ms=100)
    writer = sink.writer

    def always_locked(call: int, events: List[Dict[str, Any]]) -> None:
        raise sink.transient_error()

    wrap_writes(monkeypatch, writer, always_locked)
    assert writer.enqueue(sink.event("a"))
    assert writer.enqueue(sink.event("b"))
    wait_for(lambda: writer.stats()["retries"] >= 1)

    started = time.monotonic()
    writer.stop(timeout_s=0.3)
    assert time.monotonic() - started < 2.0

    # Only the deadline ends the retries (max_retries is effectively unlimited).
    assert writer.thread is not None
    writer.thread.join(timeout=10)
    assert not writer.thread.is_alive()
    final = writer.stats()
    assert final["written"] == 0
    assert final["failed"] >= 1  # "a" was attempted; "b" was attempted or dropped.
    assert final["failed"] + final["dropped"] == 2
    assert final["pending"] == 0
    assert_conserved(final)


def test_unique_violation_skips_only_true_duplicates(make_sink: Callable[..., Sink]) -> None:
    sink = make_sink(batch_size=5, table_constraint="UNIQUE ({key})")
    sink.insert_existing("dup")
    # One row that already exists and one duplicate inside the batch itself.
    for key in ["a", "dup", "b", "a", "c"]:
        assert sink.writer.enqueue(sink.event(key))

    sink.writer.stop()

    assert sink.keys() == ["dup", "a", "b", "c"]
    stats = sink.writer.stats()
    assert (stats["written"], stats["duplicates"], stats["failed"]) == (3, 2, 0)
    assert sink.writer.last_error is None  # Duplicates are expected, not errors.
    assert_conserved(stats)


def test_other_constraint_failures_fail_only_the_offending_row(
    make_sink: Callable[..., Sink],
) -> None:
    sink = make_sink(batch_size=3, table_constraint="CHECK ({key} <> 'poison')")
    writer = sink.writer
    for key in ["a", "poison", "b"]:
        assert writer.enqueue(sink.event(key))
    wait_for(lambda: writer.stats()["pending"] == 0)

    # A CHECK failure is not a duplicate: it is counted as failed, not skipped.
    stats = writer.stats()
    assert (stats["written"], stats["duplicates"], stats["failed"]) == (2, 0, 1)
    assert "CHECK constraint failed" in (writer.last_error or "")
    assert writer.available and writer.error is None
    assert writer.enqueue(sink.event("c"))  # The writer stays in service.

    writer.stop()

    assert sink.keys() == ["a", "b", "c"]
    final = writer.stats()
    assert (final["written"], final["failed"], final["pending"]) == (3, 1, 0)
    assert_conserved(final)


def test_transient_errors_are_retried_with_backoff(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(batch_size=3, retry_backoff_ms=20)
    writer = sink.writer

    def locked_three_times(call: int, events: List[Dict[str, Any]]) -> None:
        if call <= 3:
            raise sink.transient_error()

    starts = wrap_writes(monkeypatch, writer, locked_three_times)
    for key in ["a", "b", "c"]:
        assert writer.enqueue(sink.event(key))
    wait_for(lambda: writer.stats()["written"] == 3)

    assert sink.keys() == ["a", "b", "c"]
    stats = writer.stats()
    assert (stats["retries"], stats["failed"]) == (3, 0)
    assert writer.available and writer.error is None
    # Each retry started no earlier than its scheduled backoff (20ms, 40ms, 80ms).
    gaps = [later - earlier for earlier, later in zip(starts, starts[1:])]
    assert len(gaps) == 3
    for attempt, gap in enumerate(gaps, start=1):
        assert gap >= writer.retry_delay_s(attempt)
    writer.stop()
    assert_conserved(writer.stats())


def test_exhausted_retries_count_failed_and_writer_keeps_running(
    make_sink: Callable[..., Sink], monkeypatch: pytest.MonkeyPatch
) -> None:
    sink = make_sink(batch_size=2, max_retries=2)
    writer = sink.writer
    healthy = threading.Event()

    def locked_until_healthy(call: int, events: List[Dict[str, Any]]) -> None:
        if not healthy.is_set():
            raise sink.transient_error()

    wrap_writes(monkeypatch, writer, locked_until_healthy)
    assert writer.enqueue(sink.event("lost-1"))
    assert writer.enqueue(sink.event("lost-2"))
    wait_for(lambda: writer.stats()["failed"] == 2)

    stats = writer.stats()
    assert stats["retries"] == 2
    assert writer.available and writer.error is None  # Not disabled.
    assert "database is locked" in (writer.last_error or "")

    healthy.set()
    assert writer.enqueue(sink.event("ok-1"))
    assert writer.enqueue(sink.event("ok-2"))
    wait_for(lambda: writer.stats()["written"] == 2)
    writer.stop()

    assert sink.keys() == ["ok-1", "ok-2"]
    final = writer.stats()
    assert (final["written"], final["failed"], final["dropped"], final["pending"]) == (2, 2, 0, 0)
    assert_conserved(final)


def test_full_queue_evicts_oldest_and_counts_every_drop(
    make_sink: Callable[..., Sink],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger="lionlock.utils.sql_batch_writer")
    sink = make_sink(batch_size=10)
    writer = sink.writer
    assert writer.max_queue_size == 100
    entered, release = threading.Event(), threading.Event()

    def hold_first_batch(call: int, events: List[Dict[str, Any]]) -> None:
        if call == 1:
            entered.set()
            release.wait(timeout=30)

    wrap_writes(monkeypatch, writer, hold_first_batch)
    keys = [f"evt-{i:03d}" for i in range(117)]
    try:
        for key in keys[:10]:
            assert writer.enqueue(sink.event(key))
        assert entered.wait(timeout=10)  # evt-000..009 are in flight; the queue is empty.
        for key in keys[10:]:  # 107 events into a 100-slot queue.
            assert writer.enqueue(sink.event(key))

        stats = writer.stats()
        assert stats["dropped_queue_full"] == 7
        assert stats["pending"] == 110
        assert_conserved(stats)
    finally:
        release.set()
    writer.stop(timeout_s=30)

    assert sink.keys() == keys[:10] + keys[17:]  # The 7 oldest queued events were evicted.
    final = writer.stats()
    assert (final["written"], final["dropped"], final["pending"]) == (110, 7, 0)
    assert_conserved(final)
    # Reported, with logarithmic volume: warnings at the 1st, 2nd and 4th drop.
    warnings = [r for r in caplog.records if "sql_sink_queue_full" in r.getMessage()]
    assert len(warnings) == 3


def test_retry_backoff_schedule_is_deterministic_and_capped() -> None:
    writer = SQLBatchWriter(batch_size=1, flush_interval_ms=10, retry_backoff_ms=50)
    delays = [writer.retry_delay_s(attempt) for attempt in range(1, 9)]
    assert delays == pytest.approx([0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 2.0, 2.0])
    assert writer.retry_delay_s(10_000) == MAX_RETRY_BACKOFF_S


def _real_sqlite_errors(tmp_path: Path) -> Dict[str, sqlite3.Error]:
    """Trigger each error class for real, so Python 3.11+ error codes are exercised."""
    db_path = tmp_path / "classify.db"
    with closing(sqlite3.connect(db_path)) as conn:
        conn.execute(
            "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, "
            "score REAL CHECK (score >= 0))"
        )
        conn.execute("INSERT INTO t VALUES (1, 'taken', 1.0)")
        conn.commit()

    def error_of(sql: str, timeout: float = 5.0) -> sqlite3.Error:
        with closing(sqlite3.connect(db_path, timeout=timeout)) as conn:
            with pytest.raises(sqlite3.Error) as info:
                conn.execute(sql)
        return info.value

    errors = {
        "unique": error_of("INSERT INTO t VALUES (2, 'taken', 1.0)"),
        "primary_key": error_of("INSERT INTO t VALUES (1, 'other', 1.0)"),
        "check": error_of("INSERT INTO t VALUES (3, 'x', -1.0)"),
        "not_null": error_of("INSERT INTO t VALUES (4, NULL, 1.0)"),
        "missing_table": error_of("INSERT INTO missing VALUES (1)"),
    }
    with closing(sqlite3.connect(db_path, isolation_level=None)) as locker:
        locker.execute("BEGIN EXCLUSIVE")
        errors["busy"] = error_of("INSERT INTO t VALUES (5, 'y', 1.0)", timeout=0)
        locker.execute("ROLLBACK")
    return errors


def test_error_classification_on_real_sqlite_errors(tmp_path: Path) -> None:
    errors = _real_sqlite_errors(tmp_path)
    duplicates = {name for name, exc in errors.items() if is_duplicate_error(exc)}
    transient = {name for name, exc in errors.items() if is_transient_error(exc)}
    assert duplicates == {"unique", "primary_key"}
    assert transient == {"busy"}
    # Python 3.10 has no sqlite_errorcode; the message fallback must agree.
    assert is_transient_error(sqlite3.OperationalError("database is locked"))
    assert not is_transient_error(sqlite3.OperationalError("no such table: t"))
    assert is_duplicate_error(sqlite3.IntegrityError("UNIQUE constraint failed: t.name"))
    assert not is_duplicate_error(sqlite3.IntegrityError("CHECK constraint failed: score >= 0"))
    # Only database errors are candidates for retry or duplicate handling.
    assert not is_transient_error(ValueError("database is locked"))
    assert not is_duplicate_error(ValueError("UNIQUE constraint failed"))


@requires_sqlalchemy
def test_error_classification_through_sqlalchemy(tmp_path: Path) -> None:
    from sqlalchemy import exc

    errors = _real_sqlite_errors(tmp_path)
    assert is_duplicate_error(exc.IntegrityError("INSERT", {}, errors["unique"]))
    assert not is_duplicate_error(exc.IntegrityError("INSERT", {}, errors["check"]))
    assert is_transient_error(exc.OperationalError("INSERT", {}, errors["busy"]))
    assert not is_transient_error(exc.OperationalError("INSERT", {}, errors["missing_table"]))
    assert is_transient_error(exc.TimeoutError("QueuePool limit reached"))
    # Recorded errors carry the driver message only, never SQL text or bound values.
    wrapped = exc.IntegrityError("INSERT INTO t VALUES (?)", ("secret-value",), errors["unique"])
    assert describe_error(wrapped) == "IntegrityError: UNIQUE constraint failed: t.name"
