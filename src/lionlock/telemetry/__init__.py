"""Local SQLite telemetry log with opt-in, privacy-preserving uploads.

- ``store``: the append-only, hash-chained local log file (never leaves the machine).
- ``policy``: the allowlist that decides exactly which values may be exported.
- ``export``: seals new rows into deterministic snapshot files in an outbox.
- ``upload``: opt-in HTTPS upload of sealed snapshots to an endpoint you control.
- ``receiver``: reference ingest server that validates snapshots as untrusted input.
"""

from .export import ExportResult, export_all, export_snapshot, pending_snapshots
from .store import Identity, LogStore, StoreError, open_store, sqlite_logging_enabled
from .upload import (
    UploadDisabledError,
    maybe_export_and_upload,
    resolve_upload_settings,
    upload_pending,
)

__all__ = [
    "ExportResult",
    "Identity",
    "LogStore",
    "StoreError",
    "UploadDisabledError",
    "export_all",
    "export_snapshot",
    "maybe_export_and_upload",
    "open_store",
    "pending_snapshots",
    "resolve_upload_settings",
    "sqlite_logging_enabled",
    "upload_pending",
]
