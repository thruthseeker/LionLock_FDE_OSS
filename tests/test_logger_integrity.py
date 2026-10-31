"""TrustVaultLogger: concurrent appends, damaged tails and truncation against a recorded head."""

from __future__ import annotations

import json
import multiprocessing
import threading
from pathlib import Path

import pytest

from lionlock import TrustVaultLogger
from lionlock.utils.chain_verifier import GENESIS_HASH, TamperDetectedError, entry_hash


def _write_many(path: str, tag: str, count: int) -> None:
    logger = TrustVaultLogger(path)
    for index in range(count):
        logger.record(event="detect", payload={"writer": tag, "n": index})


def test_concurrent_threads_and_processes_keep_one_valid_chain(tmp_path: Path) -> None:
    path = tmp_path / "trustvault.log"
    threads = [
        threading.Thread(target=_write_many, args=(str(path), f"t{i}", 40)) for i in range(6)
    ]
    context = multiprocessing.get_context("spawn")
    processes = [
        context.Process(target=_write_many, args=(str(path), f"p{i}", 40)) for i in range(3)
    ]
    for worker in [*threads, *processes]:
        worker.start()
    for worker in [*threads, *processes]:
        worker.join(timeout=120)
    assert all(process.exitcode == 0 for process in processes)

    logger = TrustVaultLogger(path)
    logger.verify_chain()
    count, _ = logger.head()
    assert count == 9 * 40


def test_a_damaged_last_line_stops_writes_instead_of_restarting_the_chain(
    tmp_path: Path,
) -> None:
    path = tmp_path / "trustvault.log"
    logger = TrustVaultLogger(path)
    logger.record(event="detect", payload={"n": 1})
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"ts": "2026-10-30T00:00:00Z", "event": "det')  # crash mid-write
    before = path.read_bytes()

    with pytest.raises(TamperDetectedError, match="damaged"):
        logger.record(event="detect", payload={"n": 2})
    assert path.read_bytes() == before
    assert GENESIS_HASH.encode() not in before.splitlines()[-1]


def test_removing_the_newest_entries_is_caught_against_a_recorded_head(tmp_path: Path) -> None:
    path = tmp_path / "trustvault.log"
    logger = TrustVaultLogger(path)
    for index in range(5):
        logger.record(event="detect", payload={"n": index})
    count, head = logger.head()
    assert count == 5

    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:3]) + "\n", encoding="utf-8")

    logger.verify_chain()  # a self-contained chain cannot see this on its own
    with pytest.raises(TamperDetectedError, match="truncated"):
        logger.verify_chain(expected_count=count)
    with pytest.raises(TamperDetectedError, match="head"):
        logger.verify_chain(expected_head=head)


def test_a_log_that_grew_after_the_head_was_recorded_still_verifies(tmp_path: Path) -> None:
    path = tmp_path / "trustvault.log"
    logger = TrustVaultLogger(path)
    for index in range(3):
        logger.record(event="detect", payload={"n": index})
    count, head = logger.head()
    for index in range(3, 6):
        logger.record(event="detect", payload={"n": index})

    logger.verify_chain(expected_head=head, expected_count=count)


def test_a_fully_rewritten_log_is_caught_against_a_recorded_head(tmp_path: Path) -> None:
    path = tmp_path / "trustvault.log"
    logger = TrustVaultLogger(path)
    for index in range(4):
        logger.record(event="detect", payload={"n": index})
    count, head = logger.head()

    # Rewrite every entry with new content and recompute a consistent chain.
    previous = GENESIS_HASH
    rewritten = []
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        entry["payload"] = {"n": "forged"}
        entry["prev_hash"] = previous
        entry.pop("sha256")
        entry["sha256"] = entry_hash(entry)
        previous = entry["sha256"]
        rewritten.append(json.dumps(entry))
    path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")

    logger.verify_chain()  # internally consistent
    with pytest.raises(TamperDetectedError):
        logger.verify_chain(expected_head=head, expected_count=count)


def test_head_of_an_empty_or_missing_log(tmp_path: Path) -> None:
    logger = TrustVaultLogger(tmp_path / "none.log")
    assert logger.head() == (0, GENESIS_HASH)
