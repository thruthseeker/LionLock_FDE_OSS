"""Seal not-yet-exported log rows into upload snapshots (a store-and-forward outbox).

Export needs no network and works whether or not uploads are enabled, so anyone can produce a
snapshot and inspect exactly what an upload would contain before opting in.
"""

from __future__ import annotations

import json
import platform
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Tuple

from lionlock.versioning import get_lionlock_version

from . import policy
from .snapshot import SNAPSHOT_FORMAT, SNAPSHOT_SCHEMA_VERSION, write_snapshot
from .store import LOG_TABLES, LogStore

DEFAULT_ROWS_PER_SNAPSHOT = 20_000
MAX_SEGMENTS_PER_RUN = 1_000
SNAPSHOT_NAME = re.compile(r"^lionlock-([0-9a-f]{8})-([0-9]{6,})\.db$")


@dataclass(frozen=True)
class ExportResult:
    path: Path
    install_id: str
    segment_index: int
    content_digest: str
    file_sha256: str
    rows: Dict[str, int]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "file": self.path.name,
            "install_id": self.install_id,
            "segment_index": self.segment_index,
            "content_digest": self.content_digest,
            "file_sha256": self.file_sha256,
            "rows": dict(self.rows),
        }


def _int(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def _parse_json(value: Any) -> Any:
    if not isinstance(value, str):
        return None
    try:
        return json.loads(value)
    except ValueError:
        return None


def _event_row(row: Mapping[str, Any], offset: int) -> Tuple[Any, ...] | None:
    return policy.event_row(
        seq=int(row["seq"]) - offset,
        ts=row["ts_utc"],
        decision=row["decision"],
        severity=row["severity"],
        reason_code=row["reason_code"],
        aggregate_score=row["aggregate_score"],
        scores=_parse_json(row["signal_scores_json"]),
        bundle=_parse_json(row["signal_bundle_json"]),
        duration_ms=row["duration_ms"],
        config_hash=row["config_hash"],
    )


def _trust_row(row: Mapping[str, Any], offset: int, export_key: str) -> Tuple[Any, ...] | None:
    record = _parse_json(row["record_json"])
    record = record if isinstance(record, dict) else {}
    drift = record.get("drift")
    return policy.trust_row(
        seq=int(row["seq"]) - offset,
        ts=row["ts_utc"],
        session_key=policy.rekey(export_key, "session", str(row["session_id"])),
        turn_index=row["turn_index"],
        model=row["model_id"],
        prompt_type=row["prompt_type"],
        trust_score=row["trust_score"],
        trust_label=row["trust_label"],
        badge=row["badge"],
        volatility=row["volatility"],
        drift_detected=drift.get("drift_detected") if isinstance(drift, dict) else None,
        flags=record.get("trigger_flags"),
        detail=policy.trust_detail_from_record(record),
    )


def snapshot_name(install_id: str, segment_index: int) -> str:
    return f"lionlock-{install_id[:8]}-{segment_index:06d}.db"


def export_snapshot(
    store: LogStore,
    outbox_dir: str | Path,
    *,
    rows_per_snapshot: int = DEFAULT_ROWS_PER_SNAPSHOT,
    dry_run: bool = False,
) -> ExportResult | None:
    """Seal the next segment into ``outbox_dir``; return None if nothing new was logged.

    Deterministic: the same log contents and identity always yield the same content digest.
    Runs under the log's write lock, so the segment and its watermark advance atomically.
    With ``dry_run`` the snapshot is written but the export state is left untouched, so the
    next real export seals the same rows with the same content digest.
    """
    limit = max(1, int(rows_per_snapshot))
    with store.exclusive() as session:
        identity = session.identity()
        state = session.meta(
            "export:segment_index",
            "export:last_digest",
            *(f"export:last_seq:{table}" for table in LOG_TABLES),
            *(f"export:seq_offset:{table}" for table in LOG_TABLES),
        )
        rows: Dict[str, List[Tuple[Any, ...]]] = {}
        watermarks: Dict[str, str] = {}
        pruned: Dict[str, int] = {}
        for table in LOG_TABLES:
            last_seq = _int(state.get(f"export:last_seq:{table}"))
            offset = _int(state.get(f"export:seq_offset:{table}"))
            source = session.rows(table, after_seq=last_seq, limit=limit)
            pruned[table] = int(source[0]["seq"]) - last_seq - 1 if source else 0
            watermarks[f"export:last_seq:{table}"] = str(
                int(source[-1]["seq"]) if source else last_seq
            )
            if table == "events":
                converted = [_event_row(row, offset) for row in source]
            else:
                converted = [_trust_row(row, offset, identity.export_key) for row in source]
            rows[table] = [row for row in converted if row is not None]

        if all(
            watermarks[f"export:last_seq:{t}"] == str(_int(state.get(f"export:last_seq:{t}")))
            for t in LOG_TABLES
        ):
            return None
        if not any(rows.values()):
            # Only rows the policy refused; advance past them without sealing an empty segment.
            if not dry_run:
                session.set_meta(watermarks)
            return None

        segment_index = _int(state.get("export:segment_index")) + 1
        meta = {
            "format": SNAPSHOT_FORMAT,
            "schema_version": str(SNAPSHOT_SCHEMA_VERSION),
            "install_id": identity.install_id,
            "segment_index": str(segment_index),
            "prev_segment_digest": state.get("export:last_digest", ""),
            "lionlock_version": policy.package_version_label(get_lionlock_version({})),
            "python": policy.python_label(platform.python_version()),
            "platform": policy.platform_label(platform.system()),
        }
        for table in LOG_TABLES:
            meta[f"{table}_rows"] = str(len(rows[table]))
            meta[f"{table}_pruned_before_export"] = str(pruned[table])

        path = Path(outbox_dir).expanduser() / snapshot_name(identity.install_id, segment_index)
        content_digest, file_sha = write_snapshot(path, meta, rows)
        if not dry_run:
            session.set_meta(
                {
                    **watermarks,
                    "export:segment_index": str(segment_index),
                    "export:last_digest": content_digest,
                }
            )
    return ExportResult(
        path=path,
        install_id=identity.install_id,
        segment_index=segment_index,
        content_digest=content_digest,
        file_sha256=file_sha,
        rows={table: len(table_rows) for table, table_rows in rows.items()},
    )


class ExportBatch(List[ExportResult]):
    """The segments one ``export_all`` run sealed. ``more_pending`` is True when the run stopped
    at ``MAX_SEGMENTS_PER_RUN`` with logged rows still unexported."""

    more_pending: bool = False


def has_unexported_rows(store: LogStore) -> bool:
    """Whether any table holds rows past its export watermark."""
    with store.exclusive() as session:
        state = session.meta(*(f"export:last_seq:{table}" for table in LOG_TABLES))
        return any(
            session.rows(table, after_seq=_int(state.get(f"export:last_seq:{table}")), limit=1)
            for table in LOG_TABLES
        )


def export_all(
    store: LogStore,
    outbox_dir: str | Path,
    *,
    rows_per_snapshot: int = DEFAULT_ROWS_PER_SNAPSHOT,
) -> ExportBatch:
    results = ExportBatch()
    for _ in range(MAX_SEGMENTS_PER_RUN):
        result = export_snapshot(store, outbox_dir, rows_per_snapshot=rows_per_snapshot)
        if result is None:
            break
        results.append(result)
    else:
        results.more_pending = has_unexported_rows(store)
    return results


def pending_snapshots(outbox_dir: str | Path) -> List[Path]:
    """Sealed snapshots waiting in the outbox, oldest segment first."""
    directory = Path(outbox_dir).expanduser()
    if not directory.is_dir():
        return []
    found: List[Tuple[str, int, Path]] = []
    for path in directory.iterdir():
        match = SNAPSHOT_NAME.fullmatch(path.name)
        if match and path.is_file():
            found.append((match.group(1), int(match.group(2)), path))
    return [path for _, _, path in sorted(found)]
