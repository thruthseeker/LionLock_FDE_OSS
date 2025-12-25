#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from lionlock.config import load_config  # noqa: E402
from lionlock.logging import sql_telemetry  # noqa: E402
from lionlock.trust_overlay.config import resolve_trust_overlay_sql_config  # noqa: E402
from lionlock.trust_overlay.sql_sink import init_db as init_trust_overlay_db  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize LionLock SQL telemetry tables.")
    parser.add_argument("--config", default="lionlock.toml", help="Path to config TOML.")
    parser.add_argument("--uri", default="", help="SQL URI (overrides config).")
    parser.add_argument("--table", default="", help="Signals table name (overrides config).")
    parser.add_argument(
        "--failsafe-table",
        default="",
        help="Failsafe table name (overrides config when storage=sql).",
    )
    parser.add_argument(
        "--include-failsafe",
        action="store_true",
        help="Create failsafe table when storage=sql.",
    )
    parser.add_argument(
        "--include-trust-overlay",
        action="store_true",
        help="Create Trust Overlay SQL table.",
    )
    parser.add_argument(
        "--trust-overlay-dsn",
        default="",
        help="Trust Overlay SQL DSN (overrides config).",
    )
    parser.add_argument(
        "--trust-overlay-sqlite-path",
        default="",
        help="Trust Overlay sqlite path (overrides config).",
    )
    parser.add_argument(
        "--trust-overlay-table",
        default="",
        help="Trust Overlay table name (overrides config).",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    sql_cfg = config.get("logging_sql", {})
    failsafe_cfg = config.get("failsafe", {})
    telemetry_cfg = config.get("telemetry", {})

    uri = args.uri or str(sql_cfg.get("uri", "")).strip()
    table = args.table or str(sql_cfg.get("table", "lionlock_signals")).strip()
    sessions_table = str(telemetry_cfg.get("sessions_table", "lionlock_sessions")).strip()
    failsafe_table = args.failsafe_table or str(failsafe_cfg.get("sql_table", "")).strip()

    include_failsafe = args.include_failsafe or failsafe_cfg.get("storage") == "sql"
    if not include_failsafe:
        failsafe_table = ""

    ok, message = sql_telemetry.init_db(
        uri, table, sessions_table, failsafe_table=failsafe_table or None
    )
    messages = [message]
    overall_ok = ok

    if args.include_trust_overlay:
        overlay_sql_cfg = resolve_trust_overlay_sql_config(config)
        if args.trust_overlay_dsn:
            overlay_sql_cfg["dsn"] = args.trust_overlay_dsn
        if args.trust_overlay_sqlite_path:
            overlay_sql_cfg["sqlite_path"] = args.trust_overlay_sqlite_path
        if args.trust_overlay_table:
            overlay_sql_cfg["table"] = args.trust_overlay_table
        overlay_ok, overlay_message = init_trust_overlay_db(overlay_sql_cfg)
        messages.append(overlay_message)
        if not overlay_ok:
            overall_ok = False

    stream = sys.stdout if overall_ok else sys.stderr
    stream.write("\n".join(messages) + "\n")
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
