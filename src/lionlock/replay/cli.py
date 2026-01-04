from __future__ import annotations

import argparse
import sys
from typing import Iterable

from lionlock.logging import missed_signal_sql

from . import evaluation_labels, policy_registry, reporting, replay_engine, sql_reader


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lionlock-replay",
        description="LionLock Module 06 replay and evaluation (OSS-safe).",
    )
    parser.add_argument("--db", required=True, help="SQL URI/DSN for telemetry (read-only).")
    parser.add_argument("--policy", required=True, help="Policy version identifier.")
    parser.add_argument(
        "--policy-registry",
        default="policies.toml",
        help="Policy registry TOML file path.",
    )
    parser.add_argument("--labels", help="Labels source (JSONL file or labels DB URI).")
    parser.add_argument("--schema", default="public", help="Postgres schema (default: public).")
    parser.add_argument("--where", help="Session filter (exact session_id).")
    parser.add_argument("--session", help="Session filter (alias for --where).")
    parser.add_argument("--limit", type=int, help="Limit number of events.")
    parser.add_argument(
        "--out",
        "--output-dir",
        dest="output_dir",
        default="replay_out",
        help="Output directory for reports.",
    )
    parser.add_argument(
        "--write-back",
        action="store_true",
        help="Write missed_signal_events (requires explicit acknowledgement).",
    )
    parser.add_argument(
        "--i-understand-write-back",
        action="store_true",
        help="Required acknowledgement flag to enable --write-back.",
    )
    return parser


def _apply_writeback(
    uri_or_dsn: str,
    proposals: Iterable[dict],
    *,
    schema: str,
) -> tuple[int, list[str]]:
    failures: list[str] = []
    count = 0
    for proposal in proposals:
        ok, message = missed_signal_sql.record_missed_signal_event(
            uri_or_dsn=uri_or_dsn,
            record=proposal,
            schema=schema,
        )
        if not ok:
            failures.append(message)
        else:
            count += 1
    return count, failures


def run(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    session_filter = args.session or args.where

    try:
        policy_bundle = policy_registry.resolve_policy(
            args.policy,
            registry_path=args.policy_registry,
        )
    except (ValueError, FileNotFoundError, KeyError) as exc:
        print(f"policy error: {exc}", file=sys.stderr)
        return 2

    if args.write_back and not args.labels:
        print("write-back requires --labels source.", file=sys.stderr)
        return 2

    if args.write_back and not args.i_understand_write_back:
        print(
            "write-back requires --i-understand-write-back acknowledgement.",
            file=sys.stderr,
        )
        return 2

    try:
        events = sql_reader.read_events(
            args.db,
            session_id=session_filter,
            limit=args.limit,
            schema=args.schema,
        )
    except sql_reader.ReadError as exc:
        print(f"db read failed: {exc}", file=sys.stderr)
        return 3

    labels = None
    if args.labels:
        try:
            labels = evaluation_labels.load_labels(args.labels, schema=args.schema)
        except Exception as exc:
            print(f"labels error: {exc}", file=sys.stderr)
            return 4

    result = replay_engine.replay(events, policy_bundle, labels=labels)
    reporting.write_outputs(args.output_dir, result)

    if args.write_back:
        print(
            "WARNING: write-back enabled; inserting missed_signal_events.",
            file=sys.stderr,
        )
        count, failures = _apply_writeback(
            args.db,
            result.proposed_missed_signal_events,
            schema=args.schema,
        )
        if failures:
            print(f"write-back failures: {len(failures)}", file=sys.stderr)
            return 3
        print(f"write-back inserted: {count}", file=sys.stderr)

    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
