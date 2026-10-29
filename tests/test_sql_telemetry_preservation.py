"""Synthetic preservation checks for the native SQLite telemetry initializer."""

import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from lionlock.logging import sql_telemetry as sql

# Frozen public schemas from the initial OSS revision, independent of production constants.
SESSIONS = """
session_pk INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT UNIQUE,
created_utc TEXT, closed_utc TEXT, lionlock_version TEXT, model TEXT, base_url TEXT,
config_hash TEXT, content_policy TEXT, has_anomalies INTEGER, anomaly_count INTEGER,
anomaly_severity_score REAL, anomaly_severity_tag TEXT
"""
SIGNALS = """
event_pk INTEGER PRIMARY KEY AUTOINCREMENT, session_pk INTEGER, timestamp_utc TEXT,
request_id TEXT, decision TEXT, severity TEXT, reason_code TEXT, aggregate_score REAL,
repetition_score REAL, novelty_score REAL, coherence_score REAL, context_score REAL,
hallucination_score REAL, duration_ms INTEGER, config_hash TEXT
"""
AUTH = """
auth_token_id TEXT CHECK (auth_token_id IS NULL OR length(auth_token_id) >= 12),
auth_signature TEXT CHECK (auth_signature IS NULL OR length(auth_signature) >= 64)
"""


def _execute(path: Path, script: str) -> None:
    with closing(sqlite3.connect(path)) as conn:
        conn.executescript(script)


def _state(path: Path) -> tuple:
    """Capture every schema object and every row, including sequence and unrelated tables."""
    with closing(sqlite3.connect(path)) as conn:
        schema = conn.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"
        ).fetchall()
        rows = {}
        for kind, name, _, _ in schema:
            if kind == "table":
                quoted = '"' + name.replace('"', '""') + '"'
                rows[name] = sorted(conn.execute(f"SELECT * FROM {quoted}").fetchall(), key=repr)
        return schema, rows


def _initialize(path: Path, **options) -> tuple[bool, str]:
    return sql.init_db(
        f"sqlite:///{path}",
        options.get("table", "lionlock_signals"),
        options.get("sessions_table", "lionlock_sessions"),
        options.get("failsafe_table"),
    )


def _known_database(path: Path, *, current: bool = False) -> None:
    columns = SIGNALS + ("," + AUTH if current else "")
    _execute(
        path,
        f"""
        CREATE TABLE lionlock_sessions ({SESSIONS});
        CREATE TABLE lionlock_signals ({columns});
        INSERT INTO lionlock_sessions (session_pk, session_id) VALUES (7, 'synthetic-session');
        INSERT INTO lionlock_signals (event_pk, session_pk, request_id, decision)
            VALUES (23, 7, 'synthetic-event', 'ALLOW');
        CREATE TABLE unrelated (value TEXT);
        INSERT INTO unrelated VALUES ('retain');
        CREATE INDEX signal_request_lookup ON lionlock_signals(request_id);
        CREATE TRIGGER retain_signal_trigger AFTER INSERT ON lionlock_signals
            BEGIN INSERT INTO unrelated VALUES ('trigger-fired'); END;
        """,
    )


@pytest.mark.parametrize("columns", ["unrelated_value TEXT", "request_id TEXT, extra_value TEXT"])
def test_foreign_signal_collision_is_refused_without_data_or_schema_changes(tmp_path, columns):
    path = tmp_path / "foreign.db"
    _execute(path, f"CREATE TABLE lionlock_signals ({columns});")
    with closing(sqlite3.connect(path)) as conn:
        count = len(conn.execute("PRAGMA table_info(lionlock_signals)").fetchall())
        conn.execute(
            "INSERT INTO lionlock_signals VALUES (" + ",".join("?" * count) + ")",
            ["retain"] * count,
        )
        conn.commit()
    before = _state(path)

    ok, message = _initialize(path)

    assert _state(path) == before
    assert not ok
    assert "incompatible" in message.lower()


@pytest.mark.parametrize(
    "definition",
    [
        SIGNALS.replace("event_pk INTEGER PRIMARY KEY AUTOINCREMENT", "event_pk INTEGER"),
        SIGNALS.replace("request_id TEXT", "request_id INTEGER"),
        SIGNALS + ", extra_value TEXT",
        SIGNALS + ", extra_value TEXT GENERATED ALWAYS AS (request_id) VIRTUAL",
    ],
)
def test_partial_or_foreign_keyed_schema_is_refused(tmp_path, definition):
    path = tmp_path / "partial.db"
    _execute(path, f"CREATE TABLE lionlock_signals ({definition});")
    before = _state(path)

    ok, _ = _initialize(path)

    assert _state(path) == before
    assert not ok


@pytest.mark.parametrize(
    "ddl",
    [
        "CREATE VIEW lionlock_signals AS SELECT 'retain' AS value",
        "CREATE TABLE lionlock_signals ("
        + SIGNALS.replace("PRIMARY KEY AUTOINCREMENT", "PRIMARY KEY")
        + ","
        + AUTH
        + ") WITHOUT ROWID",
        f"CREATE TABLE lionlock_signals ({SIGNALS},{AUTH}) STRICT",
        "CREATE VIRTUAL TABLE lionlock_signals USING fts5(value)",
    ],
)
def test_nonstandard_target_objects_are_refused_without_creating_other_tables(tmp_path, ddl):
    path = tmp_path / "object.db"
    _execute(path, ddl + ";")
    before = _state(path)

    ok, _ = _initialize(path)

    assert _state(path) == before
    assert not ok


@pytest.mark.parametrize("table", ["lionlock_sessions", "lionlock_failsafe"])
def test_incompatible_companion_table_is_checked_before_any_ddl(tmp_path, table):
    path = tmp_path / "companion.db"
    _execute(path, f"CREATE TABLE {table} (value TEXT); INSERT INTO {table} VALUES ('retain');")
    before = _state(path)

    ok, _ = _initialize(path, failsafe_table="lionlock_failsafe")

    assert _state(path) == before
    assert not ok


@pytest.mark.parametrize(
    "options",
    [
        {"table": "lionlock_sessions"},
        {"sessions_table": "lionlock_signals"},
        {"failsafe_table": "lionlock_signals"},
        {"table": "lionlock_sessions", "sessions_table": "lionlock_signals"},
    ],
)
def test_crossed_or_duplicate_roles_are_refused_before_mutation(tmp_path, options):
    path = tmp_path / "roles.db"
    _known_database(path)
    before = _state(path)

    ok, message = _initialize(path, **options)

    assert _state(path) == before
    assert not ok
    assert "role" in message.lower()


def test_pre_auth_upgrade_preserves_rows_keys_indexes_triggers_and_is_idempotent(tmp_path):
    path = tmp_path / "legacy.db"
    _known_database(path)
    before_schema, before_rows = _state(path)

    assert _initialize(path)[0]

    after_schema, after_rows = _state(path)
    assert after_rows["lionlock_signals"] == [(*before_rows["lionlock_signals"][0], None, None)]
    for name in before_rows.keys() - {"lionlock_signals"}:
        assert after_rows[name] == before_rows[name]
    assert [row for row in after_schema if row[0] in ("index", "trigger")] == [
        row for row in before_schema if row[0] in ("index", "trigger")
    ]
    with closing(sqlite3.connect(path)) as conn:
        names = {row[1] for row in conn.execute("PRAGMA table_info(lionlock_signals)")}
        assert {"auth_token_id", "auth_signature"} <= names
    upgraded = _state(path)
    assert _initialize(path)[0]
    assert _state(path) == upgraded


def test_current_schema_retains_authentication_values_and_sequence(tmp_path):
    path = tmp_path / "current.db"
    _known_database(path, current=True)
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "UPDATE lionlock_signals SET auth_token_id=?, auth_signature=?",
            ("a" * 12, "b" * 64),
        )
        conn.commit()
    before = _state(path)

    assert _initialize(path)[0]
    assert _initialize(path)[0]

    assert _state(path) == before


def test_equivalent_column_order_and_declared_type_case_are_accepted(tmp_path):
    path = tmp_path / "equivalent.db"
    # All statements address columns by name; ordering and declared-type case are immaterial.
    _execute(
        path,
        f"CREATE TABLE lionlock_sessions ({SESSIONS});"
        f"CREATE TABLE lionlock_signals ({AUTH}, {SIGNALS.lower()});"
        "INSERT INTO lionlock_signals (event_pk, request_id) VALUES (9, 'retain');",
    )
    before = _state(path)

    assert _initialize(path)[0]

    assert _state(path) == before


def test_existing_extra_constraints_remain_enforced(tmp_path):
    path = tmp_path / "constraints.db"
    _execute(
        path,
        f"CREATE TABLE lionlock_sessions ({SESSIONS});"
        f"CREATE TABLE lionlock_signals ({SIGNALS},{AUTH},"
        "UNIQUE(request_id), CHECK (decision <> 'reject'));"
        "INSERT INTO lionlock_signals (request_id, decision) VALUES ('retain', 'ALLOW');",
    )
    before = _state(path)

    assert _initialize(path)[0]
    assert _state(path) == before
    with closing(sqlite3.connect(path)) as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO lionlock_signals (request_id) VALUES ('retain')")
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO lionlock_signals (decision) VALUES ('reject')")


def test_uppercase_incompatible_table_name_is_not_treated_as_absent(tmp_path):
    path = tmp_path / "case.db"
    _execute(
        path,
        "CREATE TABLE LIONLOCK_SIGNALS (value TEXT);"
        "INSERT INTO LIONLOCK_SIGNALS VALUES ('retain');",
    )
    before = _state(path)

    ok, _ = _initialize(path)

    assert not ok
    assert _state(path) == before


@pytest.mark.parametrize("has_original", [True, False])
def test_leftover_staging_table_is_preserved_and_never_recovered_automatically(
    tmp_path, has_original
):
    path = tmp_path / "staging.db"
    if has_original:
        _known_database(path)
    _execute(
        path,
        "CREATE TABLE lionlock_signals_v2 (value TEXT);"
        "INSERT INTO lionlock_signals_v2 VALUES ('retain-staging');",
    )
    before = _state(path)

    assert _initialize(path)[0]

    schema, rows = _state(path)
    assert rows["lionlock_signals_v2"] == [("retain-staging",)]
    assert [row for row in schema if row[1] == "lionlock_signals_v2"] == [
        row for row in before[0] if row[1] == "lionlock_signals_v2"
    ]
    if not has_original:
        assert rows["lionlock_signals"] == []


@pytest.mark.parametrize("operation", ["create", "upgrade"])
def test_initialization_failure_rolls_back_the_entire_schema_transaction(
    tmp_path, monkeypatch, operation
):
    path = tmp_path / "rollback.db"
    if operation == "upgrade":
        _known_database(path)
    before = _state(path)
    real_connect = sqlite3.connect
    alters = 0

    def authorize(action, name, _second, _database, _source):
        nonlocal alters
        if action == sqlite3.SQLITE_ALTER_TABLE:
            alters += 1
            if operation == "upgrade" and alters == 2:
                return sqlite3.SQLITE_DENY
        if (
            operation == "create"
            and action == sqlite3.SQLITE_CREATE_TABLE
            and name == "lionlock_signals"
        ):
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    class ControlledConnection(sqlite3.Connection):
        def close(self):
            self.set_authorizer(None)
            super().close()

    def connect(*args, **kwargs):
        conn = real_connect(*args, **kwargs, factory=ControlledConnection)
        conn.set_authorizer(authorize)
        return conn

    with monkeypatch.context() as patch:
        patch.setattr(sqlite3, "connect", connect)
        ok, _ = _initialize(path)

    assert not ok
    assert _state(path) == before
    if operation == "upgrade":
        assert alters == 2


def test_writer_startup_refuses_foreign_schema_without_mutation(tmp_path):
    path = tmp_path / "writer.db"
    _execute(
        path,
        "CREATE TABLE lionlock_signals (value TEXT);"
        "INSERT INTO lionlock_signals VALUES ('retain');",
    )
    before = _state(path)

    writer = sql.SQLTelemetryWriter(
        f"sqlite:///{path}", "lionlock_signals", "lionlock_sessions", 10, 1000, 1
    )
    try:
        assert not writer.available
        assert "incompatible" in (writer.error or "").lower()
    finally:
        writer.stop()
    assert _state(path) == before


def test_session_begin_refuses_incompatible_collision(tmp_path):
    path = tmp_path / "session.db"
    _execute(
        path,
        "CREATE TABLE lionlock_signals (value TEXT);"
        "INSERT INTO lionlock_signals VALUES ('retain');",
    )
    before = _state(path)

    result = sql.begin_session(
        {"uri": f"sqlite:///{path}"},
        "synthetic-session",
        "2026-01-01",
        "test",
        "test",
        "",
        "test",
        "signals_only",
    )

    assert result is None
    assert _state(path) == before


def test_session_update_refuses_partial_foreign_schema(tmp_path):
    path = tmp_path / "session-update.db"
    _execute(
        path,
        "CREATE TABLE lionlock_sessions (session_id TEXT, has_anomalies INTEGER,"
        "anomaly_count INTEGER, anomaly_severity_score REAL, anomaly_severity_tag TEXT);"
        "INSERT INTO lionlock_sessions VALUES ('synthetic-session',0,0,0.0,'retain');",
    )
    before = _state(path)

    sql.update_session_anomalies(
        {"uri": f"sqlite:///{path}"}, "synthetic-session", None, 3, 0.8, "changed"
    )

    assert _state(path) == before


def test_failsafe_refuses_a_crossed_role_and_does_not_insert(tmp_path):
    path = tmp_path / "failsafe.db"
    _known_database(path, current=True)
    before = _state(path)

    ok, message = sql.write_failsafe_blob(
        {"uri": f"sqlite:///{path}", "sql_table": "lionlock_signals"},
        "2026-01-01",
        "synthetic-event",
        "synthetic-blob",
    )

    assert _state(path) == before
    assert not ok
    assert "role" in message.lower()


def test_fresh_and_relative_path_initialization(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert sql.init_db("sqlite:///relative.db", "lionlock_signals", "lionlock_sessions")[0]
    assert _initialize(tmp_path / "fresh.db", failsafe_table="lionlock_failsafe")[0]
    assert sql.init_db("sqlite:///:memory:", "lionlock_signals", "lionlock_sessions")[0]


def test_memory_sessions_and_failsafe_do_not_report_ephemeral_records_as_persisted():
    config = {"uri": "sqlite:///:memory:"}

    assert (
        sql.begin_session(
            config, "synthetic-session", "2026-01-01", "test", "test", "", "test", "signals_only"
        )
        is None
    )
    assert not sql.write_failsafe_blob(config, "2026-01-01", "synthetic-event", "blob")[0]
