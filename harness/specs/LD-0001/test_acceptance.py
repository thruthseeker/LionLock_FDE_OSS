"""LD-0001 acceptance: the real-data reproducibility claim.

Skips rather than fails when the private data or its reader is absent, so a clone without
``LIONLOCK_DATA_DIR`` — CI, or any cloud session — stays green.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

SPEC_DIR = Path(__file__).resolve().parent
REPO_ROOT = SPEC_DIR.parents[2]

for candidate in (str(REPO_ROOT), str(REPO_ROOT / "src")):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)


def _product_module() -> Any:
    module_spec = importlib.util.spec_from_file_location("_ld0001_product", SPEC_DIR / "product.py")
    assert module_spec is not None and module_spec.loader is not None
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def measured() -> dict[str, Any]:
    module = _product_module()
    try:
        return module.product()
    except module.DataUnavailable as reason:
        pytest.skip(f"private data unavailable: {reason}")


def test_both_runs_have_a_thousand_results(measured: dict[str, Any]) -> None:
    for run, counts in sorted(measured["rows"].items()):
        assert counts["consolidated"] == 1000, (run, counts)
        assert counts["runner"] == 1000, (run, counts)


def test_every_prompt_pairs_across_the_two_runs(measured: dict[str, Any]) -> None:
    assert measured["pairs"] == 1000, measured["pairs"]


def test_the_two_runs_reproduced_each_other_exactly(measured: dict[str, Any]) -> None:
    """The claim this spec exists to hold: 1,000/1,000 identical completion hashes."""
    assert measured["differing_completion_hash"] == 0, measured["differing_completion_hash"]
    assert measured["identical_completion_hash"] == measured["pairs"]


def test_pair_fingerprint_matches_the_private_expectations(measured: dict[str, Any]) -> None:
    module = _product_module()
    expectations_path = module.data_dir() / "expectations.json"
    if not expectations_path.is_file():
        pytest.skip(
            "no expectations.json in LIONLOCK_DATA_DIR; measured "
            f"pair_fingerprint {measured['pair_fingerprint']}"
        )
    expected = json.loads(expectations_path.read_text()).get("LD-0001", {})
    if "pair_fingerprint" not in expected:
        pytest.skip(
            "expectations.json has no LD-0001.pair_fingerprint; measured "
            f"{measured['pair_fingerprint']}"
        )
    assert measured["pair_fingerprint"] == expected["pair_fingerprint"]


def test_product_is_stable_within_a_process(measured: dict[str, Any]) -> None:
    """Cheap guard against iteration-order leaking into the fingerprint."""
    again = _product_module().product()
    assert again["pair_fingerprint"] == measured["pair_fingerprint"]
