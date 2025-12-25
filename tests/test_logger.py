import hashlib
import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest import TestCase

from lionlock import TrustVaultLogger


class TrustVaultLoggerTests(TestCase):
    def test_record_writes_digest_and_payload(self) -> None:
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
            datetime.fromisoformat(entry["ts"].removesuffix("Z"))  # validates timestamp format

            serialized = json.dumps(
                {"ts": entry["ts"], "event": "detect", "payload": payload},
                sort_keys=True,
                separators=(",", ":"),
            )
            expected = hashlib.sha256(serialized.encode()).hexdigest()
            self.assertEqual(entry["sha256"], expected)

    def test_stress_logging_many_events(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / "trustvault.log"
            logger = TrustVaultLogger(log_path)
            total = 500

            for idx in range(total):
                logger.record(event="detect", payload={"signal": f"noop-{idx}"})

            logger.flush()
            logger.close()

            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), total)
