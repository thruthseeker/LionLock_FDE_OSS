"""Static guarantees: the decision and export path cannot reach the network or an AI model.

These modules score responses, make gating decisions, compute trust records, and decide what
telemetry may be exported. The test parses their imports and fails if any of them pulls in a
networking, remote-database, or ML/LLM library, so the guarantee cannot regress silently.
"""

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src" / "lionlock"

DETERMINISTIC_MODULES = [
    "core/__init__.py",
    "core/gating.py",
    "core/models.py",
    "core/scoring.py",
    "signal_schemas.py",
    "trust_overlay/config.py",
    "trust_overlay/engine.py",
    "trust_overlay/schemas.py",
    "telemetry/canonical.py",
    "telemetry/policy.py",
    "telemetry/snapshot.py",
    "telemetry/store.py",
    "telemetry/export.py",
]

FORBIDDEN_ROOTS = {
    # networking
    "socket",
    "ssl",
    "http",
    "urllib",
    "requests",
    "httpx",
    "aiohttp",
    "websockets",
    # remote databases
    "sqlalchemy",
    "psycopg",
    "psycopg2",
    # AI / ML
    "openai",
    "anthropic",
    "transformers",
    "torch",
    "tensorflow",
    "sklearn",
    "langchain",
    "llama_cpp",
    "ollama",
}
FORBIDDEN_INTERNAL = ("lionlock.connectors", "lionlock.telemetry.upload")


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
        elif isinstance(node, ast.ImportFrom) and node.level > 0:
            package = path.parent.relative_to(SRC.parent).parts
            base = ".".join(package[: len(package) - node.level + 1])
            names.add(f"{base}.{node.module}" if node.module else base)
    return names


@pytest.mark.parametrize("relative", DETERMINISTIC_MODULES)
def test_decision_and_export_path_has_no_network_or_ai_imports(relative: str) -> None:
    path = SRC / relative
    for name in _imports(path):
        assert name.split(".")[0] not in FORBIDDEN_ROOTS, f"{relative} imports {name}"
        assert not name.startswith(FORBIDDEN_INTERNAL), f"{relative} imports {name}"


def test_runtime_dependencies_contain_no_ai_libraries() -> None:
    pyproject = (SRC.parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    dependencies = pyproject.split("dependencies = [", 1)[1].split("]", 1)[0].lower()
    for library in ("openai", "anthropic", "transformers", "torch", "tensorflow", "langchain"):
        assert library not in dependencies
