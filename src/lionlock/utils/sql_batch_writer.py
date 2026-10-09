"""Background batch writer shared by LionLock's opt-in SQL sinks.

``lionlock.logging.sql_telemetry`` and ``lionlock.trust_overlay.sql_sink`` queue
events in memory and insert them from a daemon thread. This module owns that
delivery policy so both sinks give the same guarantees:

* Every accepted event ends in exactly one terminal counter of ``stats()``:
  ``written``; ``duplicates`` (rejected by a UNIQUE or PRIMARY KEY constraint,
  i.e. already stored); ``failed`` (a write was attempted but the row could not
  be persisted); ``in_doubt`` (the COMMIT failed without a known outcome, so the
  row may or may not be stored); or ``dropped`` (never attempted: evicted from a
  full queue, or still queued when the stop deadline expired). Until then it is
  ``pending``.
* Transient errors (lock contention, lost connections) are retried with
  deterministic exponential backoff. Write errors never disable the writer.
* A write is replayed only when it is known to have stored nothing. A COMMIT that
  fails without a known outcome is never retried, so no row is stored twice.
* A non-transient batch error, such as a single UNIQUE violation, rolls the
  batch back; its rows are then inserted one by one so only the offending rows
  are skipped (duplicates) or failed.
* ``stop()`` flushes everything still queued, bounded by a deadline.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Mapping
from typing import Any, Callable, Dict, List

_LOGGER = logging.getLogger(__name__)

DEFAULT_MAX_RETRIES = 5
DEFAULT_RETRY_BACKOFF_MS = 50
DEFAULT_STOP_TIMEOUT_S = 2.0
MAX_RETRY_BACKOFF_S = 2.0

# SQLite result codes: https://www.sqlite.org/rescode.html
_SQLITE_BUSY = 5
_SQLITE_LOCKED = 6
_SQLITE_CONSTRAINT_PRIMARYKEY = 1555
_SQLITE_CONSTRAINT_UNIQUE = 2067
# PostgreSQL SQLSTATEs: unique_violation, and class 40 (transaction rollback).
_PG_UNIQUE_VIOLATION = "23505"
_PG_TRANSACTION_ROLLBACK_CLASS = "40"

_QUOTE = re.compile(r"[\"'`]")

_OUTCOMES = ("written", "duplicates", "failed", "in_doubt")
_COUNTERS = ("enqueued", *_OUTCOMES, "dropped_queue_full", "dropped_on_stop", "retries")


class CommitOutcomeUnknown(Exception):
    """The COMMIT failed without a known outcome (for example the connection was
    lost), so the rows may already be stored. Such a write is never retried."""


def _load_sqlalchemy_exc() -> Any:
    try:
        from sqlalchemy import exc
    except Exception:
        return None
    return exc


_SA_EXC: Any = _load_sqlalchemy_exc()


def _driver_error(exc: BaseException) -> BaseException:
    """The DB-API exception wrapped by SQLAlchemy, or ``exc`` itself."""
    orig = getattr(exc, "orig", None)
    return orig if isinstance(orig, BaseException) else exc


def _sqlstate(driver_exc: BaseException) -> str | None:
    """SQLSTATE of a PostgreSQL driver error (psycopg2 ``pgcode``, psycopg ``sqlstate``)."""
    sqlstate = getattr(driver_exc, "pgcode", None) or getattr(driver_exc, "sqlstate", None)
    return sqlstate if isinstance(sqlstate, str) and sqlstate else None


def _is_sqlite_busy(exc: BaseException) -> bool:
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    code = getattr(exc, "sqlite_errorcode", None)  # Python 3.11+
    if isinstance(code, int):
        return (code & 0xFF) in (_SQLITE_BUSY, _SQLITE_LOCKED)
    message = str(exc).lower()
    return "locked" in message or "busy" in message


def _is_integrity_error(exc: BaseException) -> bool:
    return isinstance(_driver_error(exc), sqlite3.IntegrityError) or (
        _SA_EXC is not None and isinstance(exc, _SA_EXC.IntegrityError)
    )


def is_transient_error(exc: BaseException) -> bool:
    """True when retrying may succeed: lock contention or a lost connection."""
    if isinstance(exc, sqlite3.Error):
        return _is_sqlite_busy(exc)
    if _SA_EXC is None:
        return False
    if isinstance(exc, (_SA_EXC.TimeoutError, _SA_EXC.DisconnectionError)):
        return True
    if not isinstance(exc, _SA_EXC.DBAPIError):
        return False
    if exc.connection_invalidated:
        return True
    if isinstance(exc.orig, sqlite3.Error):
        return _is_sqlite_busy(exc.orig)
    return isinstance(exc, _SA_EXC.OperationalError)


def is_duplicate_error(exc: BaseException) -> bool:
    """True when ``exc`` is a UNIQUE or PRIMARY KEY violation (the row already exists)."""
    if not _is_integrity_error(exc):
        return False
    driver_exc = _driver_error(exc)
    code = getattr(driver_exc, "sqlite_errorcode", None)  # Python 3.11+
    if isinstance(code, int):
        return code in (_SQLITE_CONSTRAINT_UNIQUE, _SQLITE_CONSTRAINT_PRIMARYKEY)
    sqlstate = _sqlstate(driver_exc)
    if sqlstate is not None:
        return sqlstate == _PG_UNIQUE_VIOLATION
    return "unique" in str(driver_exc).lower()


def commit_stored_nothing(exc: BaseException) -> bool:
    """True when a COMMIT that raised ``exc`` is known to have stored nothing.

    SQLite keeps the transaction open, uncommitted, after SQLITE_BUSY or
    SQLITE_LOCKED; a constraint violation (for example a deferred one) commits
    nothing; and PostgreSQL SQLSTATE class 40 (serialization failure, deadlock)
    means the server rolled back. Any other failure, notably a lost connection,
    leaves the outcome unknown.
    """
    driver_exc = _driver_error(exc)
    if _is_sqlite_busy(driver_exc) or _is_integrity_error(exc):
        return True
    sqlstate = _sqlstate(driver_exc)
    return sqlstate is not None and sqlstate.startswith(_PG_TRANSACTION_ROLLBACK_CLASS)


def describe_error(exc: BaseException) -> str:
    """A diagnostic that carries no data values.

    It holds the driver error's type, its SQLite or SQLSTATE code when the driver
    provides one, and the first line of its message cut at the first quote.
    Drivers quote offending values (PostgreSQL: ``invalid input syntax for type
    integer: "..."``), so quoted text, SQL text and later lines are never kept.
    """
    driver_exc = _driver_error(exc)
    label = type(driver_exc).__name__
    code = getattr(driver_exc, "sqlite_errorname", None) or _sqlstate(driver_exc)
    if isinstance(code, str) and code:
        label = f"{label} [{code}]"
    lines = str(driver_exc).splitlines()
    detail = lines[0].strip() if lines else ""
    quote = _QUOTE.search(detail)
    if quote:
        detail = f"{detail[: quote.start()].rstrip()} <redacted>".lstrip()
    return f"{label}: {detail}" if detail else label


def _crossed_power_of_two(before: int, after: int) -> bool:
    """True when a counter reached 1, 2, 4, 8, ...; keeps warnings to O(log n) lines."""
    return after.bit_length() > before.bit_length()


class SQLBatchWriter:
    """Queue events in memory and insert them in batches from a daemon thread.

    Subclasses implement ``_write_batch(events)``, which must insert every event
    in one transaction and raise, with nothing committed, on failure; it commits
    through ``_commit()`` so a COMMIT with an unknown outcome is never replayed.
    They call ``_start()`` once their tables exist, or ``_disable()`` when they
    cannot.
    """

    sink_name = "sql"

    def __init__(
        self,
        *,
        batch_size: int,
        flush_interval_ms: int,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_backoff_ms: int = DEFAULT_RETRY_BACKOFF_MS,
        stop_timeout_s: float = DEFAULT_STOP_TIMEOUT_S,
    ) -> None:
        self.batch_size = max(1, batch_size)
        self.flush_interval = max(10, flush_interval_ms) / 1000.0
        self.max_queue_size = max(100, self.batch_size * 10)
        self.max_retries = max(0, max_retries)
        self.retry_backoff_s = max(0, retry_backoff_ms) / 1000.0
        self.stop_timeout_s = max(0.0, stop_timeout_s)
        self.stop_event = threading.Event()
        self.available = True
        # Fatal: the writer could not start. Write errors only set last_error.
        self.error: str | None = None
        # Most recent write error (see describe_error); the writer keeps running.
        self.last_error: str | None = None
        self.engine: Any = None
        self.thread: threading.Thread | None = None
        self._cond = threading.Condition()
        self._queue: deque[Dict[str, Any]] = deque()
        self._in_flight = 0
        self._deadline: float | None = None
        # Set when stop() returned while a write was still running.
        self._stopped_early = False
        self._counts: Dict[str, int] = dict.fromkeys(_COUNTERS, 0)

    def _disable(self, error: str) -> None:
        self.available = False
        self.error = error

    def _start(self) -> None:
        self.thread = threading.Thread(
            target=self._run, name=f"lionlock-{self.sink_name}-writer", daemon=True
        )
        self.thread.start()

    def _write_batch(self, events: List[Dict[str, Any]]) -> None:
        raise NotImplementedError

    def _commit(self, commit: Callable[[], Any]) -> None:
        """Run ``commit``. If it fails and the rows may already be stored, raise
        ``CommitOutcomeUnknown`` so the write is counted as ``in_doubt``, not replayed."""
        try:
            commit()
        except Exception as exc:
            if commit_stored_nothing(exc):
                raise
            raise CommitOutcomeUnknown(f"commit outcome unknown: {describe_error(exc)}") from exc

    def enqueue(self, event: Dict[str, Any]) -> bool:
        """Queue ``event``; False when the writer is stopped or unavailable.

        A full queue evicts its oldest event so the newest data is kept. Each
        eviction is counted as ``dropped_queue_full`` and reported as a warning.
        """
        if not isinstance(event, Mapping):
            return False
        with self._cond:
            if not self.available or self.stop_event.is_set():
                return False
            evicted = len(self._queue) >= self.max_queue_size
            if evicted:
                self._queue.popleft()
                self._counts["dropped_queue_full"] += 1
            dropped = self._counts["dropped_queue_full"]
            self._queue.append(dict(event))
            self._counts["enqueued"] += 1
            if len(self._queue) in (1, self.batch_size):
                self._cond.notify()
        if evicted and _crossed_power_of_two(dropped - 1, dropped):
            _LOGGER.warning(
                "sql_sink_queue_full sink=%s max_queue_size=%d dropped_total=%d",
                self.sink_name,
                self.max_queue_size,
                dropped,
            )
        return True

    def stats(self) -> Dict[str, int]:
        """Snapshot of the delivery counters.

        ``pending`` is measured (queued plus in-flight events), so the invariant
        ``enqueued == written + duplicates + failed + in_doubt + dropped + pending``
        is a real consistency check, with ``dropped = dropped_queue_full +
        dropped_on_stop``.
        """
        with self._cond:
            counts = dict(self._counts)
            counts["pending"] = len(self._queue) + self._in_flight
        counts["dropped"] = counts["dropped_queue_full"] + counts["dropped_on_stop"]
        return counts

    def retry_delay_s(self, attempt: int) -> float:
        """Delay before retry ``attempt`` (1-based): ``retry_backoff_ms`` doubled per
        retry, capped at ``MAX_RETRY_BACKOFF_S``. No jitter, so it is deterministic."""
        return min(self.retry_backoff_s * 2 ** min(attempt - 1, 30), MAX_RETRY_BACKOFF_S)

    def stop(self, timeout_s: float | None = None) -> None:
        """Stop accepting events and flush the queue within ``timeout_s`` seconds
        (default ``stop_timeout_s``).

        No batch is taken, and no retry or row-by-row attempt starts, after that
        deadline: events still queued are counted as ``dropped_on_stop`` and events
        whose write was cut short as ``failed``, never lost silently. A write that
        is already running is not interrupted: its events stay ``pending`` when
        this returns, and the counters are logged as ``sql_sink_late_outcome`` once
        it finishes.
        """
        bound = self.stop_timeout_s if timeout_s is None else max(0.0, timeout_s)
        with self._cond:
            if self.stop_event.is_set():
                return
            self.available = False
            deadline = time.monotonic() + bound
            self._deadline = deadline
            self.stop_event.set()
            self._cond.notify_all()
        thread = self.thread
        if thread is None:
            self._dispose_engine()
        elif thread is not threading.current_thread():
            thread.join(max(0.0, deadline - time.monotonic()))
        with self._cond:
            self._drop_queued()
            self._stopped_early = thread is not None and thread.is_alive()
        stats = self.stats()
        if stats["failed"] or stats["in_doubt"] or stats["dropped"] or stats["pending"]:
            self._log_summary("sql_sink_stopped_with_undelivered_events")

    def _log_summary(self, event: str) -> None:
        stats = self.stats()
        _LOGGER.warning(
            "%s sink=%s written=%d duplicates=%d failed=%d in_doubt=%d dropped=%d pending=%d",
            event,
            self.sink_name,
            stats["written"],
            stats["duplicates"],
            stats["failed"],
            stats["in_doubt"],
            stats["dropped"],
            stats["pending"],
        )

    def _past_deadline(self) -> bool:
        deadline = self._deadline
        return deadline is not None and time.monotonic() >= deadline

    def _drop_queued(self) -> None:
        # Caller holds self._cond.
        self._counts["dropped_on_stop"] += len(self._queue)
        self._queue.clear()

    def _dispose_engine(self) -> None:
        if self.engine is not None:
            try:
                self.engine.dispose()
            except Exception:
                pass

    def _run(self) -> None:
        last_flush = time.monotonic()
        while True:
            with self._cond:
                batch = self._next_batch(last_flush)
            if batch is None:
                # The worker owns the engine; release it even if stop() timed out.
                self._dispose_engine()
                return
            self._flush(batch)
            last_flush = time.monotonic()

    def _next_batch(self, last_flush: float) -> List[Dict[str, Any]] | None:
        """Wait (holding ``_cond``) until a batch is due; None tells the worker to exit."""
        while not self.stop_event.is_set():
            queued = len(self._queue)
            if queued >= self.batch_size:
                break
            timeout: float | None = None
            if queued:
                timeout = last_flush + self.flush_interval - time.monotonic()
                if timeout <= 0:
                    break
            self._cond.wait(timeout)
        if self.stop_event.is_set() and (not self._queue or self._past_deadline()):
            self._drop_queued()
            return None
        batch = [self._queue.popleft() for _ in range(min(self.batch_size, len(self._queue)))]
        self._in_flight = len(batch)
        return batch

    def _flush(self, batch: List[Dict[str, Any]]) -> None:
        """Insert ``batch``, recording each event in exactly one outcome counter."""
        outcome = dict.fromkeys(_OUTCOMES, 0)
        try:
            self._deliver(batch, outcome)
        except Exception as exc:  # Defensive: a bug here must not kill the worker.
            outcome["failed"] += len(batch) - sum(outcome.values())
            self.last_error = describe_error(exc)
        with self._cond:
            failed_before = self._counts["failed"]
            in_doubt_before = self._counts["in_doubt"]
            for name, count in outcome.items():
                self._counts[name] += count
            self._in_flight = 0
            failed_after = self._counts["failed"]
            in_doubt_after = self._counts["in_doubt"]
            finished_after_stop = self._stopped_early
        if _crossed_power_of_two(failed_before, failed_after):
            _LOGGER.warning(
                "sql_sink_write_failed sink=%s failed_total=%d last_error=%s",
                self.sink_name,
                failed_after,
                self.last_error,
            )
        if _crossed_power_of_two(in_doubt_before, in_doubt_after):
            _LOGGER.warning(
                "sql_sink_commit_outcome_unknown sink=%s in_doubt_total=%d last_error=%s",
                self.sink_name,
                in_doubt_after,
                self.last_error,
            )
        if finished_after_stop:
            # stop() already returned with this batch pending: report its outcome.
            self._log_summary("sql_sink_late_outcome")

    def _deliver(self, batch: List[Dict[str, Any]], outcome: Dict[str, int]) -> None:
        error = self._write_with_retry(batch)
        if error is None:
            outcome["written"] += len(batch)
            return
        if len(batch) == 1 or is_transient_error(error) or isinstance(error, CommitOutcomeUnknown):
            # Nothing to isolate; or retries ran out (or reached the stop deadline);
            # or the rows may already be stored, so inserting them again could
            # store them twice.
            outcome[self._outcome_of(error)] += len(batch)
            return
        # The failed batch was rolled back. Insert its rows one by one so a single
        # duplicate or invalid row cannot take the rest of the batch down with it.
        for index, event in enumerate(batch):
            if self._past_deadline():
                outcome["failed"] += len(batch) - index
                return
            row_error = self._write_with_retry([event])
            outcome["written" if row_error is None else self._outcome_of(row_error)] += 1

    def _outcome_of(self, error: Exception) -> str:
        """Final classification of a write error; duplicates are not errors."""
        if isinstance(error, CommitOutcomeUnknown):
            self.last_error = str(error)
            return "in_doubt"
        if is_duplicate_error(error):
            return "duplicates"
        self.last_error = describe_error(error)
        return "failed"

    def _write_with_retry(self, events: List[Dict[str, Any]]) -> Exception | None:
        """Write ``events`` in one transaction, retrying transient errors with
        backoff. Returns None on success, otherwise the final error."""
        attempt = 0
        while True:
            try:
                self._write_batch(events)
                return None
            except Exception as exc:
                if not is_transient_error(exc):
                    return exc
                self.last_error = describe_error(exc)
                if attempt >= self.max_retries:
                    return exc
                attempt += 1
                if not self._backoff(attempt):
                    return exc
                with self._cond:
                    self._counts["retries"] += 1

    def _backoff(self, attempt: int) -> bool:
        """Wait before retry ``attempt``; False when it could not start before the
        stop deadline (``stop()`` wakes this wait so the deadline applies at once)."""
        resume_at = time.monotonic() + self.retry_delay_s(attempt)
        with self._cond:
            while True:
                if self._deadline is not None and resume_at >= self._deadline:
                    return False
                remaining = resume_at - time.monotonic()
                if remaining <= 0:
                    return True
                self._cond.wait(remaining)
