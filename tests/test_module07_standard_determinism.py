import hashlib
import sqlite3
from pathlib import Path

from lionlock.sim import reporting, runner


def _run_sim(tmp_path: Path, label: str) -> runner.SimResult:
    out_dir = tmp_path / label
    db_path = tmp_path / f"{label}.db"
    return runner.run_simulation(
        profile="standard",
        turns=100,
        seed=123,
        output_dir=str(out_dir),
        db_url=f"sqlite:///{db_path}",
        schema="main",
        policy_version="dev-local",
        policy_registry_path=None,
        append_run=False,
    )


def _db_counts(db_path: Path) -> tuple[int, int, int, int]:
    conn = sqlite3.connect(db_path)
    try:
        event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        missed_count = conn.execute("SELECT COUNT(*) FROM missed_signal_events").fetchone()[0]
        refresh_count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE gating_decision='REFRESH'"
        ).fetchone()[0]
        warn_count = conn.execute(
            "SELECT COUNT(*) FROM events WHERE gating_decision='WARN'"
        ).fetchone()[0]
    finally:
        conn.close()
    return event_count, missed_count, refresh_count, warn_count


def test_module07_standard_determinism(tmp_path: Path) -> None:
    first = _run_sim(tmp_path, "run1")
    second = _run_sim(tmp_path, "run2")

    assert first.run_id == second.run_id

    report_first = first.report
    report_second = second.report
    assert report_first == report_second

    report_json_first = Path(first.output_paths["report_json"]).read_text(encoding="utf-8")
    report_json_second = Path(second.output_paths["report_json"]).read_text(encoding="utf-8")
    assert report_json_first == report_json_second

    labels_first = Path(first.output_paths["labels_jsonl"]).read_bytes()
    labels_second = Path(second.output_paths["labels_jsonl"]).read_bytes()
    assert labels_first == labels_second

    labels_sha = hashlib.sha256(labels_first).hexdigest()
    assert report_first["labels_sha256"] == labels_sha
    assert report_first["report_json_sha256"] == reporting.report_json_hash(report_first)

    event_count_1, missed_count_1, refresh_count_1, warn_count_1 = _db_counts(
        Path(first.db_uri[len("sqlite:///") :])
    )
    event_count_2, missed_count_2, refresh_count_2, warn_count_2 = _db_counts(
        Path(second.db_uri[len("sqlite:///") :])
    )
    assert event_count_1 == event_count_2
    assert missed_count_1 == missed_count_2

    assert report_first["missed"]["rate"] <= 0.05
    assert report_first["missed"]["count"] >= 1
    assert report_first["coverage"]["fatigue_high"] is True
    assert report_first["coverage"]["low_conf_halluc"] is True
    assert report_first["coverage"]["congestion_high"] is True
    assert report_first["coverage"]["expected_block"] is True
    assert refresh_count_1 >= 1 and refresh_count_2 >= 1
    assert warn_count_1 == 0 and warn_count_2 == 0


def test_offline_fallback_selects_sqlite(monkeypatch) -> None:
    def _fail_connect(uri: str, *, timeout_s: float = 1.0) -> None:
        raise RuntimeError("connect failed")

    def _offline(*, timeout_s: float = 0.3) -> bool:
        return True

    monkeypatch.setattr(runner, "_test_postgres_connection", _fail_connect)
    monkeypatch.setattr(runner, "_detect_offline", _offline)

    target = runner._resolve_db_target(
        explicit_db=None,
        env_db=None,
        schema_override=None,
    )
    assert target.engine == "sqlite"
    assert target.db_source == "offline_fallback"
    assert target.offline_fallback_engaged is True
    assert target.schema == "main"
    assert target.uri.startswith("sqlite:///")
