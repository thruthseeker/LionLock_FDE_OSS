"""The Trust Overlay table name is interpolated into SQL and must be a plain identifier."""

from __future__ import annotations

from pathlib import Path

import pytest

from lionlock.trust_overlay import sql_sink

HOSTILE = "t (x int); DROP TABLE lionlock_signals; --"


def test_init_db_refuses_a_table_name_that_is_not_an_identifier(tmp_path: Path) -> None:
    db = tmp_path / "overlay.db"
    ok, message = sql_sink.init_db({"backend": "sqlite3", "sqlite_path": str(db), "table": HOSTILE})
    assert ok is False
    assert "Invalid SQL identifier" in message


def test_the_writer_refuses_a_table_name_that_is_not_an_identifier(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Invalid SQL identifier"):
        sql_sink.TrustOverlaySQLWriter(
            backend="sqlite3",
            dsn="",
            sqlite_path=str(tmp_path / "overlay.db"),
            table=HOSTILE,
            batch_size=1,
            flush_interval_ms=10,
            connect_timeout_s=1,
        )


def test_a_plain_table_name_still_works(tmp_path: Path) -> None:
    ok, _ = sql_sink.init_db(
        {"backend": "sqlite3", "sqlite_path": str(tmp_path / "o.db"), "table": "overlay_rows"}
    )
    assert ok is True
