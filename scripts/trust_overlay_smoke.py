#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import sqlite3
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from lionlock.trust_overlay.logger import append_trust_record, build_trust_record  # noqa: E402
from lionlock.trust_overlay.sql_sink import stop_writer  # noqa: E402


def _wait_for_row(db_path: Path, table: str, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if db_path.exists():
            try:
                with sqlite3.connect(db_path) as conn:
                    row = conn.execute(f"SELECT * FROM {table}").fetchone()
            except sqlite3.OperationalError:
                time.sleep(0.05)
                continue
            if row:
                return True
        time.sleep(0.05)
    return False


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Trust Overlay smoke harness (JSONL + sqlite3 SQL)."
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=2.0,
        help="Seconds to wait for SQL row insertion.",
    )
    parser.add_argument(
        "--table",
        default="trust_overlay_records",
        help="SQL table name.",
    )
    parser.add_argument(
        "--db-path",
        default=str(ROOT / "logs" / "trust_overlay_smoke.db"),
        help="SQLite DB path.",
    )
    parser.add_argument(
        "--jsonl-dir",
        default=str(ROOT / "logs" / "trust_overlay_smoke"),
        help="Directory for JSONL trust overlay output.",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    db_path = Path(args.db_path)
    jsonl_dir = Path(args.jsonl_dir)
    table = args.table

    db_path.parent.mkdir(parents=True, exist_ok=True)
    jsonl_dir.mkdir(parents=True, exist_ok=True)

    config = {
        "trust_overlay": {
            "sql": {
                "enabled": True,
                "backend": "sqlite3",
                "sqlite_path": str(db_path),
                "table": table,
                "batch_size": 1,
                "flush_interval_ms": 10,
                "connect_timeout_s": 1,
            }
        }
    }

    response_hash = hashlib.sha256(b"trust-overlay-smoke").hexdigest()
    record = build_trust_record(
        session_id="smoke-session",
        turn_index=0,
        model_id="smoke-model",
        prompt_type="qa",
        derived_signals={"overall_risk": 0.2},
        aggregate_score=0.2,
        response_text=None,
        response_hash=response_hash,
        score_history=[],
        timestamps=[],
        config=config,
        user_id=None,
    )

    try:
        path = append_trust_record(record, base_dir=jsonl_dir, config=config)
        sql_ok = _wait_for_row(db_path, table, timeout_s=args.timeout_s)

        if not path.exists():
            sys.stderr.write("Trust overlay smoke failed: JSONL output missing.\n")
            return 1
        if not sql_ok:
            sys.stderr.write("Trust overlay smoke failed: SQL row missing.\n")
            return 1

        sys.stdout.write("Trust overlay smoke ok.\n")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Trust overlay smoke failed: {exc}\n")
        return 1
    finally:
        stop_writer()


if __name__ == "__main__":
    raise SystemExit(main())
