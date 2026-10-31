"""What the TrustVault hash chain does and does not prove.

`docs/AUDIT_LOGGING.md` calls this the canonical tamper-evident audit log, so the limits of
the guarantee belong in tests rather than in a reader's assumptions.
"""

import json
import threading

import pytest

from lionlock.logger import ChainStateError, TrustVaultLogger
from lionlock.utils.chain_verifier import TamperDetectedError, verify_chain


def _records(log_path) -> list:
    return [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_concurrent_appends_produce_one_unbroken_chain(tmp_path) -> None:
    """Unsynchronised writers read the same head hash and both link to it, which shows up
    later as a prev_hash mismatch on a log nobody tampered with."""
    logger = TrustVaultLogger(tmp_path / "trustvault.log")
    threads = [
        threading.Thread(
            target=lambda n=n: [logger.record("detect", {"w": n, "i": i}) for i in range(25)]
        )
        for n in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    logger.verify_chain(expected_count=200)
    assert len(_records(logger.path)) == 200


def test_a_torn_final_entry_is_refused_rather_than_silently_restarted(tmp_path) -> None:
    """A process that died mid-append leaves a partial line. Starting a new chain from
    GENESIS there would break continuity without reporting it."""
    log_path = tmp_path / "trustvault.log"
    logger = TrustVaultLogger(log_path)
    logger.record("detect", {"signal": "one"})
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write('{"ts": "2026-01-01T00:00:00Z", "event": "detect", "pay')

    with pytest.raises(ChainStateError, match="unreadable entry"):
        logger.record("detect", {"signal": "two"})

    # Nothing was appended, so no second chain was started behind the operator's back.
    text = log_path.read_text(encoding="utf-8")
    assert text.count('"prev_hash": "' + "0" * 64 + '"') == 1


def test_an_entry_larger_than_the_tail_window_is_still_chained(tmp_path) -> None:
    """The previous hash is found by reading the tail, which must handle a long entry."""
    logger = TrustVaultLogger(tmp_path / "trustvault.log")
    logger.record("detect", {"blob": "x" * 40000})
    logger.record("detect", {"signal": "after"})

    logger.verify_chain(expected_count=2)
    entries = _records(logger.path)
    assert entries[1]["prev_hash"] == entries[0]["sha256"]


def test_entries_removed_from_the_end_are_not_detected_by_the_links_alone(tmp_path) -> None:
    """A prefix of a valid chain is a valid chain.

    This is the limit of an unkeyed forward-linked chain and the reason verify_chain takes
    expected_count. Deleting recent entries is the realistic way to hide activity, so it is
    pinned here rather than left to be discovered.
    """
    log_path = tmp_path / "trustvault.log"
    logger = TrustVaultLogger(log_path)
    for index in range(5):
        logger.record("detect", {"signal": index})
    logger.verify_chain(expected_count=5)

    kept = _records(log_path)[:2]
    log_path.write_text("".join(json.dumps(entry) + "\n" for entry in kept), encoding="utf-8")

    # The links still check out: truncation from the end is invisible to them.
    logger.verify_chain()
    verify_chain(kept)

    # An externally known entry count is what catches it.
    with pytest.raises(TamperDetectedError, match="Expected 5 entries, found 2"):
        logger.verify_chain(expected_count=5)
