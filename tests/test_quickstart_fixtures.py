import importlib.util
import json
from pathlib import Path


def _load_quickstart_module():
    module_path = Path("examples/quickstart.py")
    spec = importlib.util.spec_from_file_location("quickstart", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_fixture_schema_and_minimum_samples() -> None:
    fixture_path = Path("tests/fixtures/sample_sessions.json")
    samples = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert isinstance(samples, list)
    assert len(samples) >= 5
    for sample in samples:
        assert isinstance(sample.get("id"), str) and sample["id"]
        assert isinstance(sample.get("text"), str) and sample["text"]
        assert sample.get("label") in {"FLAGGED", "CLEAN"}


def test_quickstart_loader_reads_fixture_records() -> None:
    module = _load_quickstart_module()
    records = module.load_fixture_sessions("tests/fixtures/sample_sessions.json")
    assert len(records) >= 5
    assert {record["label"] for record in records}.issubset({"FLAGGED", "CLEAN"})
