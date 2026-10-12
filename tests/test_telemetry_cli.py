import importlib.util
import json
import sqlite3
from pathlib import Path

from lionlock.telemetry.cli import main
from lionlock.telemetry.store import LogStore

REPO = Path(__file__).resolve().parents[1]


def _run(capsys, *argv: str) -> tuple[int, dict]:
    code = main(list(argv))
    return code, json.loads(capsys.readouterr().out)


def _run_quickstart() -> dict:
    spec = importlib.util.spec_from_file_location("quickstart", REPO / "examples" / "quickstart.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run_quickstart(REPO / "tests" / "fixtures" / "sample_sessions.json")


def test_quickstart_runs_end_to_end_into_the_sqlite_log(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    for name in ("LIONLOCK_GATING_ENABLED", "LIONLOCK_TELEMETRY_DB_URI", "DO_NOT_TRACK"):
        monkeypatch.delenv(name, raising=False)
    summary = _run_quickstart()
    assert summary["FLAGGED"] + summary["CLEAN"] == 5
    capsys.readouterr()

    store = LogStore(tmp_path / "logs" / "lionlock.db")
    assert store.counts() == {"events": 5, "trust_records": 5}
    assert all(status.ok for status in store.verify().values())

    code, status = _run(capsys, "status")
    assert code == 0
    assert status["rows"] == {"events": 5, "trust_records": 5}
    assert status["upload"]["allowed"] is False

    code, verified = _run(capsys, "verify")
    assert code == 0 and verified["ok"] is True

    code, preview = _run(capsys, "preview", "--out", str(tmp_path / "preview"), "--rows", "1")
    assert code == 0 and preview["valid"] is True
    assert preview["row_counts"] == {"events": 5, "trust_records": 5}
    assert set(preview["sample_rows"]["events"][0]) >= {"decision", "signal_bundle_json"}
    code, again = _run(capsys, "preview", "--out", str(tmp_path / "preview"))
    assert again["meta"]["content_digest"] == preview["meta"]["content_digest"]

    # Previewing consumed nothing: the real export seals the identical snapshot.
    code, exported = _run(capsys, "export", "--out", str(tmp_path / "sealed"))
    assert code == 0 and len(exported["exported"]) == 1
    assert exported["exported"][0]["content_digest"] == preview["meta"]["content_digest"]
    snapshot = tmp_path / "sealed" / exported["exported"][0]["file"]
    code, inspected = _run(capsys, "inspect", str(snapshot), "--rows", "0")
    assert code == 0 and inspected["meta"] == preview["meta"]

    code, nothing = _run(capsys, "preview", "--out", str(tmp_path / "preview"))
    assert nothing["preview"] is None

    code, status = _run(capsys, "status")
    assert status["install_id"] == preview["meta"]["install_id"]

    code, refused = _run(capsys, "upload")
    assert code == 2 and "opt-in" in refused["reason"]


def test_verify_reports_tampering(tmp_path, monkeypatch, capsys) -> None:
    monkeypatch.chdir(tmp_path)
    store = LogStore(tmp_path / "logs" / "lionlock.db")
    for i in range(3):
        store.append_event({"timestamp_utc": "2026-09-27T10:00:00Z", "decision": "ALLOW"})
    import sqlite3

    with sqlite3.connect(tmp_path / "logs" / "lionlock.db") as conn:
        conn.execute("UPDATE events SET decision = 'BLOCK' WHERE seq = 1")
    code, verified = _run(capsys, "verify")
    assert code == 1
    assert verified["tables"]["events"]["first_bad_seq"] == 1


def test_serve_refuses_a_warehouse_with_an_older_layout(tmp_path, capsys) -> None:
    data_dir = tmp_path / "server"
    data_dir.mkdir()
    with sqlite3.connect(data_dir / "warehouse.db") as conn:
        conn.execute("CREATE TABLE uploads (file_sha256 TEXT PRIMARY KEY NOT NULL)")
    config = str(tmp_path / "absent.toml")
    code, out = _run(
        capsys, "--config", config, "serve", "--data-dir", str(data_dir), "--port", "0"
    )
    assert code == 1
    assert out["ok"] is False and "new data directory" in out["error"]
