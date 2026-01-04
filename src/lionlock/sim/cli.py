from __future__ import annotations

import argparse
import sys

from . import runner


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lionlock-sim",
        description=(
            "LionLock Module 07 simulation harness (Postgres-first; sqlite only by "
            "explicit opt-in or offline fallback)."
        ),
    )
    subparsers = parser.add_subparsers(dest="command")
    run_parser = subparsers.add_parser("run", help="Run a deterministic simulation profile.")
    run_parser.add_argument("--profile", default=runner.DEFAULT_PROFILE, help="Profile name.")
    run_parser.add_argument("--turns", type=int, default=runner.DEFAULT_TURNS, help="Turn count.")
    run_parser.add_argument("--seed", type=int, default=runner.DEFAULT_SEED, help="Seed value.")
    run_parser.add_argument(
        "--out-dir",
        default="sim_out",
        help="Output directory for report and labels.",
    )
    run_parser.add_argument(
        "--db",
        help="SQL URI/DSN for telemetry (writes). Postgres is default; sqlite is opt-in.",
    )
    run_parser.add_argument("--schema", help="Postgres schema or sqlite schema name.")
    run_parser.add_argument("--policy", default="dev-local", help="Policy version identifier.")
    run_parser.add_argument("--policy-registry", help="Policy registry TOML file path.")
    run_parser.add_argument(
        "--append-run",
        action="store_true",
        help="Always create a new run_id (no idempotent wipe).",
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command != "run":
        parser.print_help()
        return 2
    try:
        result = runner.run_simulation(
            profile=args.profile,
            turns=args.turns,
            seed=args.seed,
            output_dir=args.out_dir,
            db_url=args.db,
            schema=args.schema,
            policy_version=args.policy,
            policy_registry_path=args.policy_registry,
            append_run=args.append_run,
        )
        warnings = result.report.get("logging", {}).get("warnings", [])
        if isinstance(warnings, list):
            for warning in warnings:
                print(f"WARNING: {warning}", file=sys.stderr)
    except Exception as exc:
        print(f"sim error: {exc}", file=sys.stderr)
        return 1
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
