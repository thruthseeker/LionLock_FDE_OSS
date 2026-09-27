"""Reference ingest server for LionLock telemetry snapshots (standard library only).

Run it on infrastructure you control, behind a TLS-terminating reverse proxy::

    lionlock-telemetry serve --data-dir /var/lib/lionlock-telemetry --port 8787

Every upload is treated as hostile input. The body is size-capped before and after gzip
decompression, checked against its declared SHA-256, and written to a quarantine directory.
The file is then opened read-only with SQLite's hardening options. It must match the snapshot
schema exactly, pass ``PRAGMA quick_check``, reproduce its content digest, and come through a
re-run of the export policy unchanged before any row reaches the warehouse. Uploads are
idempotent, and client IP addresses are never logged or stored.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
import zlib
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Tuple

from lionlock.logging.token_auth import hash_token

from .snapshot import (
    COLUMNS,
    DATA_TABLES,
    DEFAULT_MAX_SNAPSHOT_BYTES,
    SnapshotError,
    SnapshotInfo,
    validate_snapshot,
)
from .upload import CONTENT_TYPE, UPLOAD_PATH

_LOGGER = logging.getLogger(__name__)

DEFAULT_MAX_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_UPLOADS_PER_HOUR = 120
DEFAULT_MAX_CONCURRENT_UPLOADS = 4

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

WAREHOUSE_DDL: Tuple[str, ...] = (
    "CREATE TABLE IF NOT EXISTS uploads ("
    "file_sha256 TEXT PRIMARY KEY NOT NULL, "
    "install_id TEXT NOT NULL, "
    "segment_index INTEGER NOT NULL, "
    "content_digest TEXT NOT NULL, "
    "prev_segment_digest TEXT NOT NULL, "
    "chain_status TEXT NOT NULL, "
    "received_hour TEXT NOT NULL, "
    "lionlock_version TEXT NOT NULL, "
    "python TEXT NOT NULL, "
    "platform TEXT NOT NULL, "
    "events_rows INTEGER NOT NULL, "
    "events_pruned_before_export INTEGER NOT NULL, "
    "trust_records_rows INTEGER NOT NULL, "
    "trust_records_pruned_before_export INTEGER NOT NULL, "
    "UNIQUE (install_id, segment_index))",
    "CREATE TABLE IF NOT EXISTS events ("
    "install_id TEXT NOT NULL, "
    "seq INTEGER NOT NULL, "
    "ts_hour TEXT, "
    "decision TEXT NOT NULL, "
    "severity TEXT, "
    "reason_code TEXT, "
    "aggregate_score REAL, "
    "signal_scores_json TEXT NOT NULL, "
    "signal_bundle_json TEXT, "
    "duration_ms INTEGER, "
    "config_hash TEXT, "
    "PRIMARY KEY (install_id, seq))",
    "CREATE TABLE IF NOT EXISTS trust_records ("
    "install_id TEXT NOT NULL, "
    "seq INTEGER NOT NULL, "
    "ts_hour TEXT, "
    "session_key TEXT NOT NULL, "
    "turn_index INTEGER, "
    "model_family TEXT NOT NULL, "
    "prompt_type TEXT, "
    "trust_score REAL NOT NULL, "
    "trust_label TEXT NOT NULL, "
    "badge TEXT, "
    "volatility REAL, "
    "drift_detected INTEGER, "
    "trigger_flags_json TEXT NOT NULL, "
    "detail_json TEXT NOT NULL, "
    "PRIMARY KEY (install_id, seq))",
)


@dataclass(frozen=True)
class ReceiverConfig:
    data_dir: Path
    # SHA-256 hashes of accepted bearer tokens; empty means anonymous uploads are accepted.
    token_hashes: frozenset[str] = frozenset()
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES
    max_snapshot_bytes: int = DEFAULT_MAX_SNAPSHOT_BYTES
    uploads_per_hour: int = DEFAULT_UPLOADS_PER_HOUR
    max_concurrent_uploads: int = DEFAULT_MAX_CONCURRENT_UPLOADS


@dataclass(frozen=True)
class IngestResult:
    status: int
    body: Dict[str, Any]
    headers: Dict[str, str] = field(default_factory=dict)


def load_token_hashes(path: str | Path) -> frozenset[str]:
    """Read one SHA-256 token hash per line (``#`` comments allowed); raw tokens are refused."""
    hashes = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = line.strip().lower()
        if not stripped or stripped.startswith("#"):
            continue
        if not _HEX64.fullmatch(stripped):
            raise ValueError("token hash file must contain only 64-hex SHA-256 hashes")
        hashes.add(stripped)
    return frozenset(hashes)


def gunzip_capped(data: bytes, limit: int) -> bytes:
    """Decompress a single gzip member, refusing output larger than ``limit`` bytes."""
    decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)
    output = bytearray()
    pending = data
    try:
        while pending and not decompressor.eof:
            output += decompressor.decompress(pending, 1 << 16)
            if len(output) > limit:
                raise ValueError("decompressed body exceeds the size limit")
            pending = decompressor.unconsumed_tail
    except zlib.error as exc:
        raise ValueError("body is not valid gzip") from exc
    if not decompressor.eof:
        raise ValueError("gzip body is truncated")
    if decompressor.unused_data:
        raise ValueError("gzip body has trailing data")
    return bytes(output)


def init_warehouse(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None)
    try:
        for ddl in WAREHOUSE_DDL:
            conn.execute(ddl)
    finally:
        conn.close()


def _error(status: int, message: str, headers: Dict[str, str] | None = None) -> IngestResult:
    return IngestResult(status, {"status": "error", "error": message}, dict(headers or {}))


def _current_hour() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:00:00Z")


class Receiver:
    """Validation and storage for uploaded snapshots, independent of the HTTP layer."""

    def __init__(self, config: ReceiverConfig) -> None:
        self.config = config
        self.quarantine_dir = config.data_dir / "quarantine"
        self.accepted_dir = config.data_dir / "accepted"
        self.rejected_dir = config.data_dir / "rejected"
        self.warehouse_path = config.data_dir / "warehouse.db"
        for directory in (self.quarantine_dir, self.accepted_dir, self.rejected_dir):
            directory.mkdir(parents=True, exist_ok=True)
        init_warehouse(self.warehouse_path)
        self._ingest_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._rate: Dict[str, Tuple[int, int]] = {}
        self._slots = threading.BoundedSemaphore(max(1, config.max_concurrent_uploads))

    def authorize(self, header: str | None) -> bool:
        if not self.config.token_hashes:
            return True
        if not header or not header.startswith("Bearer "):
            return False
        token = header[len("Bearer ") :].strip()
        return bool(token) and hash_token(token) in self.config.token_hashes

    @contextmanager
    def upload_slot(self) -> Iterator[bool]:
        """Reserve one of ``max_concurrent_uploads`` slots before reading a request body."""
        acquired = self._slots.acquire(blocking=False)
        try:
            yield acquired
        finally:
            if acquired:
                self._slots.release()

    def handle_upload(self, headers: Mapping[str, str], body: bytes) -> IngestResult:
        lowered = {key.lower(): value for key, value in headers.items()}
        if lowered.get("content-type", "").split(";")[0].strip() != CONTENT_TYPE:
            return _error(415, "unsupported content type")
        encoding = lowered.get("content-encoding", "identity").strip().lower()
        limit = self.config.max_snapshot_bytes
        if encoding == "gzip":
            try:
                data = gunzip_capped(body, limit)
            except ValueError as exc:
                return _error(413 if "limit" in str(exc) else 400, str(exc))
        elif encoding in ("", "identity"):
            data = body
            if len(data) > limit:
                return _error(413, "snapshot exceeds the size limit")
        else:
            return _error(415, "unsupported content encoding")

        file_sha = hashlib.sha256(data).hexdigest()
        if lowered.get("x-lionlock-file-sha256", "").strip().lower() != file_sha:
            return _error(400, "X-LionLock-File-SHA256 does not match the body")
        install_id = lowered.get("x-lionlock-install-id", "").strip().lower()
        if not _HEX32.fullmatch(install_id):
            return _error(400, "missing or malformed X-LionLock-Install-Id")
        if (self.accepted_dir / f"{file_sha}.db").exists():
            return IngestResult(200, {"status": "duplicate", "file_sha256": file_sha})
        if not self._within_rate(install_id):
            return _error(429, "upload rate limit exceeded", {"Retry-After": "3600"})

        quarantined = self.quarantine_dir / f"{file_sha}-{uuid.uuid4().hex}.db"
        quarantined.write_bytes(data)
        try:
            info = validate_snapshot(quarantined, max_bytes=limit)
            self._check_headers(lowered, info)
        except SnapshotError as exc:
            self._reject(quarantined, file_sha, str(exc))
            return _error(422, str(exc))

        outcome = self._ingest(file_sha, info)
        if outcome == "conflict":
            message = "segment was already received with different content"
            self._reject(quarantined, file_sha, message)
            return _error(409, message)
        os.replace(quarantined, self.accepted_dir / f"{file_sha}.db")
        body_out = {
            "status": outcome,
            "file_sha256": file_sha,
            "install_id": info.install_id,
            "segment_index": info.segment_index,
        }
        return IngestResult(201 if outcome == "created" else 200, body_out)

    def _check_headers(self, headers: Mapping[str, str], info: SnapshotInfo) -> None:
        declared = (
            headers.get("x-lionlock-install-id", "").strip().lower(),
            headers.get("x-lionlock-segment", "").strip(),
            headers.get("x-lionlock-content-digest", "").strip().lower(),
        )
        if declared != (info.install_id, str(info.segment_index), info.content_digest):
            raise SnapshotError("upload headers do not match the snapshot metadata")

    def _within_rate(self, install_id: str) -> bool:
        if self.config.uploads_per_hour <= 0:
            return True
        hour = int(time.time() // 3600)
        with self._rate_lock:
            if len(self._rate) > 100_000:
                self._rate.clear()
            bucket_hour, count = self._rate.get(install_id, (hour, 0))
            if bucket_hour != hour:
                count = 0
            if count >= self.config.uploads_per_hour:
                return False
            self._rate[install_id] = (hour, count + 1)
        return True

    def _reject(self, quarantined: Path, file_sha: str, reason: str) -> None:
        target = self.rejected_dir / f"{file_sha}.db"
        os.replace(quarantined, target)
        target.with_name(target.name + ".reason.txt").write_text(reason + "\n", encoding="utf-8")

    def _ingest(self, file_sha: str, info: SnapshotInfo) -> str:
        meta = info.meta
        with self._ingest_lock:
            conn = sqlite3.connect(str(self.warehouse_path), timeout=30, isolation_level=None)
            try:
                conn.execute("BEGIN IMMEDIATE")
                existing = conn.execute(
                    "SELECT file_sha256 FROM uploads WHERE file_sha256 = ? "
                    "OR (install_id = ? AND segment_index = ?)",
                    (file_sha, info.install_id, info.segment_index),
                ).fetchone()
                if existing is not None:
                    conn.execute("ROLLBACK")
                    return "duplicate" if existing[0] == file_sha else "conflict"
                conn.execute(
                    "INSERT INTO uploads VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        file_sha,
                        info.install_id,
                        info.segment_index,
                        info.content_digest,
                        meta["prev_segment_digest"],
                        self._chain_status(conn, info),
                        _current_hour(),
                        meta["lionlock_version"],
                        meta["python"],
                        meta["platform"],
                        int(meta["events_rows"]),
                        int(meta["events_pruned_before_export"]),
                        int(meta["trust_records_rows"]),
                        int(meta["trust_records_pruned_before_export"]),
                    ),
                )
                for table in DATA_TABLES:
                    columns = ("install_id", *COLUMNS[table])
                    placeholders = ",".join("?" for _ in columns)
                    conn.executemany(
                        f"INSERT OR IGNORE INTO {table} ({','.join(columns)}) "
                        f"VALUES ({placeholders})",
                        [(info.install_id, *row) for row in info.rows[table]],
                    )
                conn.execute("COMMIT")
                return "created"
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
            finally:
                conn.close()

    @staticmethod
    def _chain_status(conn: sqlite3.Connection, info: SnapshotInfo) -> str:
        prev_digest = info.meta["prev_segment_digest"]
        if info.segment_index == 1:
            return "ok" if prev_digest == "" else "broken"
        row = conn.execute(
            "SELECT content_digest FROM uploads WHERE install_id = ? AND segment_index = ?",
            (info.install_id, info.segment_index - 1),
        ).fetchone()
        if row is None:
            return "gap"
        return "ok" if row[0] == prev_digest else "broken"


class _Handler(BaseHTTPRequestHandler):
    server_version = "lionlock-receiver"
    sys_version = ""
    timeout = 30

    def log_message(self, format: str, *args: Any) -> None:
        # Deliberately omits the client address: the receiver never records IP addresses.
        _LOGGER.info(format, *args)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._reply(200, {"status": "ok"})
        else:
            self._reply(404, {"status": "error", "error": "not found"})

    def do_POST(self) -> None:
        receiver: Receiver = self.server.receiver  # type: ignore[attr-defined]
        if self.path != UPLOAD_PATH:
            self._reply(404, {"status": "error", "error": "not found"})
            return
        if not receiver.authorize(self.headers.get("Authorization")):
            self._reply(
                401, {"status": "error", "error": "unauthorized"}, {"WWW-Authenticate": "Bearer"}
            )
            return
        try:
            length = int(self.headers.get("Content-Length") or "")
        except ValueError:
            self._reply(411, {"status": "error", "error": "Content-Length is required"})
            return
        if length <= 0 or length > receiver.config.max_body_bytes:
            self._reply(413, {"status": "error", "error": "body size is out of range"})
            return
        with receiver.upload_slot() as acquired:
            if not acquired:
                result = _error(503, "receiver is busy; retry later", {"Retry-After": "30"})
                self._reply(result.status, result.body, result.headers)
                return
            body = self.rfile.read(length)
            if len(body) != length:
                self._reply(400, {"status": "error", "error": "incomplete body"})
                return
            try:
                result = receiver.handle_upload(dict(self.headers.items()), body)
            except Exception:  # noqa: BLE001 - never leak internals to the client
                _LOGGER.exception("snapshot ingest failed")
                result = _error(500, "internal error")
        self._reply(result.status, result.body, result.headers)

    def _reply(
        self, status: int, payload: Dict[str, Any], headers: Dict[str, str] | None = None
    ) -> None:
        data = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)


class ReceiverServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: Tuple[str, int], receiver: Receiver) -> None:
        super().__init__(address, _Handler)
        self.receiver = receiver


def make_server(
    config: ReceiverConfig, host: str = "127.0.0.1", port: int = 8787
) -> ReceiverServer:
    return ReceiverServer((host, port), Receiver(config))
