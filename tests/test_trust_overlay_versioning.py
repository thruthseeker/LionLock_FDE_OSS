from pathlib import Path

from lionlock.trust_overlay.versioning import code_fingerprint


def test_code_fingerprint_deterministic(tmp_path: Path) -> None:
    overlay_root = tmp_path / "trust_overlay"
    overlay_root.mkdir()
    (overlay_root / "__init__.py").write_text("x", encoding="utf-8")
    (overlay_root / "engine.py").write_text("y", encoding="utf-8")

    first = code_fingerprint(overlay_root)
    second = code_fingerprint(overlay_root)
    assert first == second

    (overlay_root / "engine.py").write_text("y!", encoding="utf-8")
    third = code_fingerprint(overlay_root)
    assert first != third
