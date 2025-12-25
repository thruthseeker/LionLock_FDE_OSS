import json
from pathlib import Path
from typing import Any

from lionlock.trust_overlay.logger import append_trust_record, build_trust_record
from lionlock.trust_overlay.schemas import EXACT_BANNED_KEYS


def _build_record(config: dict | None = None) -> dict:
    return build_trust_record(
        session_id="session-1",
        turn_index=1,
        model_id="model-1",
        prompt_type="qa",
        derived_signals={"overall_risk": 0.2},
        aggregate_score=0.2,
        response_text="ok",
        response_hash=None,
        score_history=[],
        timestamps=[],
        config=config or {},
        user_id="user-1",
    )


def _contains_banned_keys(value: Any) -> bool:
    banned = {key.lower() for key in EXACT_BANNED_KEYS}
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in banned:
                return True
            if _contains_banned_keys(item):
                return True
    if isinstance(value, list):
        return any(_contains_banned_keys(item) for item in value)
    return False


def test_pseudonymous_user_key_omitted_without_salt() -> None:
    record = _build_record(config={})
    assert "pseudonymous_user_key" not in record


def test_append_trust_record_drops_prompt_response_keys(tmp_path: Path) -> None:
    record = _build_record(config={})
    record["prompt"] = "secret"
    record["signal_summary"]["response_text"] = "secret"
    record["signal_summary"]["raw_prompt"] = "secret"

    path = append_trust_record(record, base_dir=tmp_path)
    line = path.read_text(encoding="utf-8").splitlines()[0]
    saved = json.loads(line)

    assert "prompt" not in saved
    assert _contains_banned_keys(saved) is False
