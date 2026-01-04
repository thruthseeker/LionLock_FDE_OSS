from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

try:
    from sqlalchemy import create_engine, text
except Exception:
    create_engine = None  # type: ignore[assignment]
    text = None  # type: ignore[assignment]

from lionlock.core.models import canonical_gating_decision
from lionlock.logging.privacy import find_forbidden_content, scrub_forbidden_keys
from lionlock.logging.connection import validate_identifier


ALLOWED_DECISIONS = {"ALLOW", "REFRESH", "BLOCK"}


@dataclass(frozen=True)
class LabelRecord:
    session_id: str
    turn_index: int
    replay_id: str | None
    expected_decision: str
    actual_failure_type: str | None = None
    response_hash: str | None = None


def _sqlite_path_from_uri(uri: str) -> str | None:
    prefix = "sqlite:///"
    if not uri.startswith(prefix):
        return None
    return uri[len(prefix) :]


def _label_key(
    session_id: str,
    turn_index: int,
    replay_id: str | None,
    response_hash: str | None,
) -> tuple[str, int, str | None, str | None]:
    return (session_id, turn_index, replay_id, response_hash)


def _normalize_decision(value: Any) -> str | None:
    if value is None:
        return None
    canonical = canonical_gating_decision(str(value))
    if canonical not in ALLOWED_DECISIONS:
        return None
    return canonical


def _build_record(payload: Dict[str, Any]) -> LabelRecord:
    ok, cleaned, message = scrub_forbidden_keys(payload, mode="reject")
    if not ok:
        raise ValueError(message or "labels contain forbidden keys")
    payload = cleaned
    found = find_forbidden_content(payload)
    if found:
        raise ValueError(f"labels contain forbidden content at {found}")
    session_id = str(payload.get("session_id") or "").strip()
    if not session_id:
        raise ValueError("labels.session_id is required")
    turn_index_raw = payload.get("turn_index")
    try:
        turn_index = int(turn_index_raw)
    except Exception:
        raise ValueError("labels.turn_index must be an integer") from None
    if turn_index < 0:
        raise ValueError("labels.turn_index must be non-negative")
    replay_id_raw = payload.get("replay_id")
    replay_id = str(replay_id_raw).strip() if replay_id_raw is not None else None
    if replay_id == "":
        replay_id = None
    if replay_id is None:
        raise ValueError("labels.replay_id is required")
    expected = _normalize_decision(payload.get("expected_decision"))
    if expected is None:
        raise ValueError("labels.expected_decision must be ALLOW/REFRESH/BLOCK")
    actual_failure_type = payload.get("actual_failure_type")
    if actual_failure_type is not None:
        actual_failure_type = str(actual_failure_type).strip() or None
    response_hash = payload.get("response_hash")
    if response_hash is not None:
        response_hash = str(response_hash).strip() or None
    return LabelRecord(
        session_id=session_id,
        turn_index=turn_index,
        replay_id=replay_id,
        expected_decision=expected,
        actual_failure_type=actual_failure_type,
        response_hash=response_hash,
    )


def load_labels(
    source: str,
    *,
    table: str = "evaluation_labels",
    schema: str = "public",
) -> Dict[tuple[str, int, str | None, str | None], LabelRecord]:
    if "://" in source:
        return _load_labels_from_db(source, table=table, schema=schema)
    return _load_labels_from_file(source)


def _load_labels_from_file(path: str) -> Dict[tuple[str, int, str | None, str | None], LabelRecord]:
    label_path = Path(path)
    if not label_path.exists():
        raise FileNotFoundError(f"labels file not found: {label_path}")
    if label_path.suffix.lower() != ".jsonl":
        raise ValueError("labels file must be JSONL")
    records: Dict[tuple[str, int, str | None, str | None], LabelRecord] = {}
    with label_path.open("r", encoding="utf-8") as handle:
        for line_num, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                payload = json.loads(stripped)
            except Exception as exc:
                raise ValueError(f"labels JSON parse error on line {line_num}") from exc
            if not isinstance(payload, dict):
                raise ValueError(f"labels line {line_num} must be an object")
            record = _build_record(payload)
            key = _label_key(
                record.session_id,
                record.turn_index,
                record.replay_id,
                record.response_hash,
            )
            if key in records:
                raise ValueError(f"duplicate label for {key}")
            records[key] = record
    return records


def _load_labels_from_db(
    uri_or_dsn: str,
    *,
    table: str,
    schema: str,
) -> Dict[tuple[str, int, str | None, str | None], LabelRecord]:
    sqlite_path = _sqlite_path_from_uri(uri_or_dsn)
    validate_identifier(table, "table")
    if sqlite_path is not None:
        conn = None
        try:
            if sqlite_path != ":memory:":
                db_path = Path(sqlite_path)
                if not db_path.exists():
                    raise ValueError(f"labels sqlite database not found: {db_path}")
                conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            else:
                conn = sqlite3.connect(sqlite_path)
            rows = conn.execute(
                (
                    "SELECT session_id, turn_index, replay_id, expected_decision, "
                    f"actual_failure_type FROM {table}"
                )
            ).fetchall()
        except Exception as exc:
            raise ValueError(f"labels sqlite read failed: {exc}") from exc
        finally:
            if conn is not None:
                conn.close()
    else:
        if create_engine is None or text is None:
            raise ValueError("SQLAlchemy not installed; cannot read labels table.")
        validate_identifier(schema, "schema")
        table_name = f"{schema}.{table}" if schema else table
        engine = None
        try:
            engine = create_engine(uri_or_dsn)
            stmt = text(
                (
                    f"SELECT session_id, turn_index, replay_id, expected_decision, "
                    f"actual_failure_type FROM {table_name}"
                )
            )
            with engine.begin() as conn:
                rows = conn.execute(stmt).fetchall()
        except Exception as exc:
            raise ValueError(f"labels SQL read failed: {exc}") from exc
        finally:
            if engine is not None:
                try:
                    engine.dispose()
                except Exception:
                    pass
    records: Dict[tuple[str, int, str | None, str | None], LabelRecord] = {}
    for row in rows:
        payload = {
            "session_id": row[0],
            "turn_index": row[1],
            "replay_id": row[2],
            "expected_decision": row[3],
            "actual_failure_type": row[4],
        }
        record = _build_record(payload)
        key = _label_key(
            record.session_id,
            record.turn_index,
            record.replay_id,
            record.response_hash,
        )
        if key in records:
            raise ValueError(f"duplicate label for {key}")
        records[key] = record
    return records
