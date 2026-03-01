import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest import TestCase

from lionlock import TrustVaultLogger
from lionlock.utils.chain_verifier import GENESIS_HASH, TamperDetectedError, verify_chain


class TrustVaultLoggerTests(TestCase):
    def test_record_writes_chained_digest_and_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "trustvault.log"
            logger = TrustVaultLogger(log_path)
            payload = {"signal": "noop"}

            logger.record(event="detect", payload=payload)
            logger.flush()
            logger.close()

            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual(entry["event"], "detect")
            self.assertEqual(entry["payload"], payload)
            self.assertEqual(entry["prev_hash"], GENESIS_HASH)
            datetime.fromisoformat(entry["ts"].removesuffix("Z"))

    def test_verify_chain_detects_tampering_and_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "trustvault.log"
            logger = TrustVaultLogger(log_path)
            logger.record(event="detect", payload={"signal": "noop-1"})
            logger.record(event="detect", payload={"signal": "noop-2"})
            logger.flush()
            logger.verify_chain()

            lines = log_path.read_text(encoding="utf-8").splitlines()
            tampered = json.loads(lines[1])
            tampered["payload"] = {"signal": "mutated"}
            lines[1] = json.dumps(tampered)
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            with self.assertRaises(TamperDetectedError):
                logger.verify_chain()

            truncated_entries = [json.loads(lines[1])]
            with self.assertRaises(TamperDetectedError):
                verify_chain(truncated_entries)

    def test_stress_logging_many_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "trustvault.log"
            logger = TrustVaultLogger(log_path)
            total = 500

            for idx in range(total):
                logger.record(event="detect", payload={"signal": f"noop-{idx}"})

            logger.flush()
            logger.close()
            logger.verify_chain()

            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), total)
