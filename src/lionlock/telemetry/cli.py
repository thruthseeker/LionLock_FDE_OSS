"""``lionlock-telemetry``: inspect, verify, export, and upload the local SQLite log.

Every command prints JSON. Only ``upload`` touches the network, and only when uploads are
enabled; ``serve`` runs the reference ingest server. ``preview`` shows exactly what the next
upload would contain without consuming anything.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence
from urllib.parse import urlsplit

from lionlock.config import load_config

from .export import export_all, export_snapshot, pending_snapshots
from .snapshot import COLUMNS, SnapshotError, SnapshotInfo, validate_snapshot
from .store import LogStore, StoreError, open_store, resolve_sqlite_path
from .upload import (
    DELIVERED_STATUSES,
    UploadDisabledError,
    export_and_upload,
    resolve_upload_settings,
)


def _print(payload: Any) -> None:
    sys.stdout.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _existing_store(config: Dict[str, Any]) -> LogStore | None:
    path = resolve_sqlite_path(config)
    return open_store(config) if path.exists() else None


def _cmd_status(config: Dict[str, Any], _args: argparse.Namespace) -> int:
    settings = resolve_upload_settings(config)
    store = _existing_store(config)
    status: Dict[str, Any] = {
        "log_path": str(resolve_sqlite_path(config)),
        "log_exists": store is not None,
        "rows": store.counts() if store else {},
        "upload": {
            "allowed": settings.allowed,
            "blocked_reason": settings.blocked_reason,
            "endpoint_host": urlsplit(settings.endpoint).hostname if settings.endpoint else None,
            "token_configured": bool(settings.token),
            "outbox_dir": str(settings.outbox_dir),
            "pending_snapshots": len(pending_snapshots(settings.outbox_dir)),
        },
    }
    if store is not None:
        # install_id is what an operator needs to delete this install's uploaded data.
        status["install_id"] = store.get_meta("install_id").get("install_id")
        status["export"] = store.get_meta(
            "export:segment_index", "export:last_seq:events", "export:last_seq:trust_records"
        )
    _print(status)
    return 0


def _cmd_verify(config: Dict[str, Any], _args: argparse.Namespace) -> int:
    store = _existing_store(config)
    if store is None:
        _print({"ok": False, "error": f"no log file at {resolve_sqlite_path(config)}"})
        return 1
    results = store.verify()
    ok = all(result.ok for result in results.values())
    _print(
        {
            "ok": ok,
            "tables": {
                table: {
                    "ok": result.ok,
                    "rows_checked": result.rows_checked,
                    "first_bad_seq": result.first_bad_seq,
                    "reason": result.reason,
                }
                for table, result in results.items()
            },
        }
    )
    return 0 if ok else 1


def _cmd_export(config: Dict[str, Any], args: argparse.Namespace) -> int:
    store = _existing_store(config)
    if store is None:
        _print({"exported": [], "note": "no log file yet"})
        return 0
    settings = resolve_upload_settings(config)
    out_dir = Path(args.out).expanduser() if args.out else settings.outbox_dir
    results = export_all(store, out_dir, rows_per_snapshot=settings.rows_per_snapshot)
    _print(
        {
            "outbox_dir": str(out_dir),
            "exported": [result.as_dict() for result in results],
            "more_pending": results.more_pending,
        }
    )
    return 1 if results.more_pending else 0


def _describe(info: SnapshotInfo, rows: int) -> Dict[str, Any]:
    limit = max(0, int(rows))
    samples: Dict[str, List[Dict[str, Any]]] = {
        table: [dict(zip(COLUMNS[table], row)) for row in table_rows[:limit]]
        for table, table_rows in info.rows.items()
    }
    return {
        "valid": True,
        "meta": info.meta,
        "row_counts": {table: len(table_rows) for table, table_rows in info.rows.items()},
        "sample_rows": samples,
    }


def _cmd_preview(config: Dict[str, Any], args: argparse.Namespace) -> int:
    store = _existing_store(config)
    if store is None:
        _print({"preview": None, "note": "no log file yet"})
        return 0
    settings = resolve_upload_settings(config)
    out_dir = (
        Path(args.out).expanduser() if args.out else resolve_sqlite_path(config).parent / "preview"
    )
    result = export_snapshot(
        store, out_dir, rows_per_snapshot=settings.rows_per_snapshot, dry_run=True
    )
    if result is None:
        _print({"preview": None, "note": "nothing new to export"})
        return 0
    _print({"preview": str(result.path), **_describe(validate_snapshot(result.path), args.rows)})
    return 0


def _cmd_inspect(_config: Dict[str, Any], args: argparse.Namespace) -> int:
    try:
        info = validate_snapshot(Path(args.snapshot))
    except (OSError, SnapshotError) as exc:
        _print({"valid": False, "error": str(exc)})
        return 1
    _print(_describe(info, args.rows))
    return 0


def _cmd_upload(config: Dict[str, Any], _args: argparse.Namespace) -> int:
    try:
        summary = export_and_upload(config)
    except UploadDisabledError as exc:
        _print({"uploaded": False, "reason": str(exc)})
        return 2
    _print(summary)
    delivered = all(upload["status"] in DELIVERED_STATUSES for upload in summary["uploads"])
    finished = summary["pending"] == 0 and not summary["more_pending"]
    return 0 if delivered and finished else 1


def _cmd_reset_identity(config: Dict[str, Any], _args: argparse.Namespace) -> int:
    identity = open_store(config).reset_identity()
    _print({"install_id": identity.install_id, "note": "export identity rotated"})
    return 0


def _cmd_serve(_config: Dict[str, Any], args: argparse.Namespace) -> int:
    from .receiver import ReceiverConfig, WarehouseVersionError, load_token_hashes, make_server

    try:
        token_hashes = load_token_hashes(args.token_hashes_file) if args.token_hashes_file else None
    except (OSError, ValueError) as exc:
        _print({"ok": False, "error": f"token hash file: {exc}"})
        return 1
    receiver_config = ReceiverConfig(
        data_dir=Path(args.data_dir).expanduser(),
        token_hashes=token_hashes or frozenset(),
        max_body_bytes=int(args.max_body_mb) * 1024 * 1024,
    )
    try:
        server = make_server(receiver_config, host=args.host, port=args.port)
    except WarehouseVersionError as exc:
        _print({"ok": False, "error": str(exc)})
        return 1
    mode = "token" if token_hashes else "anonymous"
    sys.stderr.write(
        f"lionlock-telemetry receiver on http://{args.host}:{server.server_port} ({mode} uploads)\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lionlock-telemetry",
        description="Inspect, verify, export, and upload the local LionLock SQLite log.",
    )
    parser.add_argument("--config", default="lionlock.toml", help="Path to lionlock.toml")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="Show the log, export, and upload state")
    sub.add_parser("verify", help="Verify the log's hash chains")
    preview_parser = sub.add_parser(
        "preview", help="Show exactly what the next upload would contain, without consuming it"
    )
    preview_parser.add_argument("--out", help="Directory for the preview snapshot")
    preview_parser.add_argument("--rows", type=int, default=5, help="Sample rows per table")
    export_parser = sub.add_parser("export", help="Seal new rows into snapshot files")
    export_parser.add_argument("--out", help="Directory for snapshots (default: the outbox)")
    inspect_parser = sub.add_parser("inspect", help="Validate a snapshot and show its contents")
    inspect_parser.add_argument("snapshot")
    inspect_parser.add_argument("--rows", type=int, default=5, help="Sample rows per table")
    sub.add_parser("upload", help="Export and upload (requires uploads to be enabled)")
    sub.add_parser("reset-identity", help="Rotate the export identity")
    serve_parser = sub.add_parser("serve", help="Run the reference ingest server")
    serve_parser.add_argument("--data-dir", required=True)
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8787)
    serve_parser.add_argument(
        "--token-hashes-file", help="Require bearer tokens whose SHA-256 is listed in this file"
    )
    serve_parser.add_argument("--max-body-mb", type=int, default=16)
    return parser


_COMMANDS = {
    "status": _cmd_status,
    "verify": _cmd_verify,
    "preview": _cmd_preview,
    "export": _cmd_export,
    "inspect": _cmd_inspect,
    "upload": _cmd_upload,
    "reset-identity": _cmd_reset_identity,
    "serve": _cmd_serve,
}


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    try:
        return _COMMANDS[args.command](config, args)
    except StoreError as exc:
        _print({"ok": False, "error": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
