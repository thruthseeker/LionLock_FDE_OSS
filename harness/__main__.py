"""Command line entry point: ``python -m harness <command>``.

Agents only ever need ``verify``. The ``product`` command exists so the determinism check can run a
spec's product in a fresh process. ``baseline``, ``lock`` and ``golden`` are maintainer actions and
are named as such in AGENTS.md.
"""

from __future__ import annotations

import argparse
import sys

from harness import verify as verify_module


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m harness")
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser(
        "verify", help="run every check and write harness/out/verify_report.json"
    )
    run.add_argument("--spec", default=None, help="block on this spec and check scope against it")
    run.add_argument(
        "--changed-since",
        default=None,
        help="also block on every open spec whose allowed_paths cover a file changed since REF",
    )

    product = commands.add_parser("product", help="print a spec's canonical product JSON")
    product.add_argument("--spec", required=True)

    commands.add_parser("baseline", help="maintainer: record current lint/type findings")
    commands.add_parser("lock", help="maintainer: record hashes of the protected files")

    golden = commands.add_parser("golden", help="maintainer: record a spec's expected product")
    golden.add_argument("--spec", required=True)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "verify":
        return verify_module.verify(args.spec, changed_since=args.changed_since)
    if args.command == "product":
        specs = {
            spec.spec_id: spec for spec in verify_module.discover_specs(verify_module.SPECS_DIR)
        }
        if args.spec not in specs:
            print(f"unknown spec {args.spec!r}", file=sys.stderr)
            return 2
        print(verify_module.product_text(specs[args.spec]))
        return 0
    if args.command == "baseline":
        return verify_module.write_baseline()
    if args.command == "lock":
        return verify_module.write_lock()
    if args.command == "golden":
        return verify_module.write_golden(args.spec)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
