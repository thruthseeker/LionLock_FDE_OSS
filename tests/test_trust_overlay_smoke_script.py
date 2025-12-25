import py_compile
from pathlib import Path


def test_trust_overlay_smoke_script_exists_and_compiles() -> None:
    root = Path(__file__).resolve().parents[1]
    script = root / "scripts" / "trust_overlay_smoke.py"
    assert script.exists()
    py_compile.compile(str(script), doraise=True)


def test_smoke_docs_reference_canonical_path() -> None:
    root = Path(__file__).resolve().parents[1]
    doc_paths = [root / "README.md"]
    docs_root = root / "docs"
    if docs_root.exists():
        doc_paths.extend(path for path in docs_root.rglob("*.md"))

    for path in doc_paths:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if "trust_overlay_smoke.py" in line:
                assert "scripts/trust_overlay_smoke.py" in line
                assert "tools/trust_overlay_smoke.py" not in line

    contrib = root / "docs" / "CONTRIBUTING.md"
    if contrib.exists():
        content = contrib.read_text(encoding="utf-8")
        assert content.count("python scripts/trust_overlay_smoke.py") == 1
