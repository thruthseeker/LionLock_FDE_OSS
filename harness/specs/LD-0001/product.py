"""LD-0001 product: run-003 vs run-004 reproducibility, as text-free aggregates.

This is the private tier. It reads real calibration output from ``LIONLOCK_DATA_DIR`` and is the
proof that "same end product" holds on real data, not only on a synthetic corpus.

What this deliberately does **not** emit: prompt ids, request ids, completion hashes, prompt or
response text, file paths, hostnames or model names. The product is counts, distribution summaries
and one aggregate fingerprint. The fingerprint is computed over per-pair identifiers internally and
only its digest leaves this function, so the output can be compared across agents without carrying
anything that identifies a request.

The dataset is read-only. Nothing here writes to ``LIONLOCK_DATA_DIR``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from harness.fingerprint import fingerprint

# Only the columns the aggregates need, so no response-bearing column is ever loaded.
CONSOLIDATED_COLUMNS = (
    "prompt_id",
    "completion_sha256",
    "completion_char_len",
    "completion_byte_len",
    "status",
    "http_status",
)
RUNNER_COLUMNS = (
    "request_id",
    "completion_sha256",
    "t_prompt_submitted_monotonic_raw_ns",
    "t_response_complete_monotonic_raw_ns",
)

RUNS = ("run-003", "run-004")


class DataUnavailable(RuntimeError):
    """The private dataset or its reader is not present. Callers turn this into SKIP, not FAIL."""


def data_dir() -> Path:
    raw = os.environ.get("LIONLOCK_DATA_DIR")
    if not raw:
        raise DataUnavailable("LIONLOCK_DATA_DIR is not set")
    path = Path(raw)
    if not path.is_dir():
        raise DataUnavailable("LIONLOCK_DATA_DIR does not point at a directory")
    return path


def _find_one(root: Path, pattern: str) -> Path:
    matches = sorted(root.glob(pattern))
    if not matches:
        raise DataUnavailable(f"no file matching {pattern}")
    # Sorted, so a directory holding more than one part file still resolves deterministically.
    return matches[0]


def _read_table(path: Path, columns: tuple[str, ...]) -> dict[str, list[Any]]:
    try:
        import pyarrow.parquet as pq
    except ImportError as error:  # pragma: no cover - environment-dependent
        raise DataUnavailable(
            "pyarrow is not installed; see harness/env/requirements-private.in"
        ) from error
    table = pq.read_table(path, columns=list(columns))
    return {name: table.column(name).to_pylist() for name in columns}


def _summary(values: list[float]) -> dict[str, Any]:
    """Count, min, max, mean and quartiles. Deterministic: sorted, no sampling."""
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    size = len(ordered)

    def percentile(fraction: float) -> float:
        # Nearest-rank on a sorted list: no interpolation, so no float drift between machines.
        index = min(size - 1, max(0, int(round(fraction * (size - 1)))))
        return float(ordered[index])

    return {
        "count": size,
        "min": float(ordered[0]),
        "max": float(ordered[-1]),
        "mean": sum(ordered) / size,
        "p25": percentile(0.25),
        "p50": percentile(0.50),
        "p75": percentile(0.75),
    }


def product() -> dict[str, Any]:
    root = data_dir()

    consolidated: dict[str, dict[str, list[Any]]] = {}
    runner: dict[str, dict[str, list[Any]]] = {}
    for run in RUNS:
        consolidated[run] = _read_table(
            _find_one(root, f"**/lionlock-cal-*-{run}_consolidated/*.parquet"),
            CONSOLIDATED_COLUMNS,
        )
        runner[run] = _read_table(
            _find_one(root, f"**/lionlock-cal-*-{run}_runner/*.parquet"), RUNNER_COLUMNS
        )

    # prompt_id -> completion hash, per run. Sorted keys only; never emitted.
    by_prompt = {
        run: dict(
            zip(consolidated[run]["prompt_id"], consolidated[run]["completion_sha256"], strict=True)
        )
        for run in RUNS
    }
    shared = sorted(set(by_prompt[RUNS[0]]) & set(by_prompt[RUNS[1]]))

    identical = sum(1 for key in shared if by_prompt[RUNS[0]][key] == by_prompt[RUNS[1]][key])

    latencies: dict[str, dict[str, Any]] = {}
    for run in RUNS:
        spans = [
            (end - start) / 1_000_000.0
            for start, end in zip(
                runner[run]["t_prompt_submitted_monotonic_raw_ns"],
                runner[run]["t_response_complete_monotonic_raw_ns"],
                strict=True,
            )
            if isinstance(start, int) and isinstance(end, int) and end >= start
        ]
        latencies[run] = _summary(spans)

    return {
        "spec": "LD-0001",
        "runs": list(RUNS),
        "rows": {
            run: {
                "consolidated": len(consolidated[run]["prompt_id"]),
                "runner": len(runner[run]["request_id"]),
            }
            for run in RUNS
        },
        "pairs": len(shared),
        "identical_completion_hash": identical,
        "differing_completion_hash": len(shared) - identical,
        "status_counts": {
            run: {
                str(key): count
                for key, count in sorted(
                    {
                        str(value): consolidated[run]["status"].count(value)
                        for value in set(consolidated[run]["status"])
                    }.items()
                )
            }
            for run in RUNS
        },
        "http_status_counts": {
            run: {
                str(key): consolidated[run]["http_status"].count(key)
                for key in sorted(set(consolidated[run]["http_status"]), key=str)
            }
            for run in RUNS
        },
        "completion_char_len": {
            run: _summary(consolidated[run]["completion_char_len"]) for run in RUNS
        },
        "completion_byte_len": {
            run: _summary(consolidated[run]["completion_byte_len"]) for run in RUNS
        },
        "latency_ms": latencies,
        # One digest over the sorted (prompt, hash-agreement) pairs. Two agents on the same data get
        # the same value; the pairs themselves never leave this function.
        "pair_fingerprint": fingerprint(
            [[key, by_prompt[RUNS[0]][key] == by_prompt[RUNS[1]][key]] for key in shared]
        ),
    }
