"""Runtime guarantees: scoring and gating reach no network, and load no AI stack.

``tests/test_offline_guarantees.py`` proves this statically. It parses each decision module and
fails if that module writes a networking, remote-database or ML import. Two things are invisible
to a parser: a module can reach the network through a dependency it never names, and a package's
``__init__`` can load code the module itself does not import. Both happen here. Importing
``lionlock.telemetry.canonical``, which is pure JSON and hashing, runs
``lionlock/telemetry/__init__.py``, which imports ``.upload``, which imports ``ssl`` and
``urllib.request``. The static audit forbids a direct import of ``lionlock.telemetry.upload`` and
cannot see that the package loads it anyway.

So this file asserts behaviour rather than syntax.

* ``network_blocked`` replaces every entry point in ``socket`` that can open a connection with a
  recorder that raises. The pipeline runs inside it, and the test asserts the recorder stayed
  empty **and** that the product is identical to the unblocked run. Zero recorded attempts is the
  proof; the unchanged product is what rules out a quietly swallowed fallback.
* ``test_network_blocker_records_and_raises`` tests the blocker itself. Without it, a blocker that
  silently did nothing would make everything else here pass for the wrong reason.
* The import audits run in a fresh, isolated interpreter and inspect what was really loaded,
  rather than what the source says it imports.

What this does not prove: a C extension that calls ``connect(2)`` itself bypasses Python's
``socket`` module and would not be recorded. The import audits are what cover that risk, by
establishing that no such extension is loaded on the scoring path to begin with.
"""

import hashlib
import json
import socket
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from lionlock.core.gating import decide_gate, evaluate_policy
from lionlock.core.scoring import SIGNAL_SCHEMA_VERSION, aggregate_score, score_payload

SRC_DIR = Path(__file__).resolve().parents[1] / "src"

# Everything in ``socket`` that can open a connection or resolve a name. Patched only when the
# attribute exists, so the blocker stays valid on a platform that ships a smaller socket module.
BLOCKED_SOCKET_CALLS = (
    "socket",
    "socketpair",
    "create_connection",
    "create_server",
    "getaddrinfo",
    "gethostbyname",
    "gethostbyname_ex",
    "gethostbyaddr",
)

# Third-party stacks that must never be loaded by the deterministic runtime. AGENTS.md allows an
# offline analysis tool to use other libraries; the runtime may not.
FORBIDDEN_THIRD_PARTY = frozenset(
    {
        # AI / LLM clients and ML frameworks
        "openai",
        "anthropic",
        "transformers",
        "torch",
        "tensorflow",
        "sklearn",
        "langchain",
        "llama_cpp",
        "ollama",
        "onnxruntime",
        # numeric stacks an ML implementation would need
        "numpy",
        "scipy",
        "pandas",
        # HTTP clients
        "requests",
        "httpx",
        "aiohttp",
        "websockets",
        "urllib3",
        # remote databases
        "sqlalchemy",
        "psycopg",
        "psycopg2",
    }
)

# Network-capable or non-deterministic standard-library modules the scoring core is allowed to
# have loaded, each one a transitive import of something it genuinely needs. None is called by
# scoring or gating; the behavioural tests above are what establish that.
#
#   socket     <- email.utils          selectors  <- socket
#   urllib     <- pathlib (as_uri)     random     <- statistics (core uses pstdev)
#   uuid       <- pydantic._internal._generate_schema
#   secrets    <- pydantic.types
#
# Which of these appear depends on the interpreter, because the standard library keeps making its
# own imports lazier: 3.11 and 3.12 load socket, selectors and urllib, and 3.13 loads none of the
# three. That is why this is asserted as a subset rather than an exact set. A new entry is a
# regression worth failing on; a disappearing one means the surface shrank, which is the direction
# we want, and must not fail a test.
CORE_ALLOWED_STDLIB = frozenset({"socket", "selectors", "urllib", "random", "uuid", "secrets"})

# The telemetry and trust-overlay path additionally loads the opt-in uploader and the local log, so
# a TLS and HTTP client and SQLite are resident. Pinned so the surface cannot grow unnoticed. See
# the module docstring: making this set smaller is the fix, and the subset check welcomes it.
TELEMETRY_ALLOWED_STDLIB = CORE_ALLOWED_STDLIB | {"ssl", "http", "sqlite3"}

DECISION_FIELDS = (
    "decision_risk_score",
    "severity",
    "gating_decision",
    "trigger_signal",
    "reason_code",
)

# A spread of inputs rather than one happy path: a clean answer, a repetition loop, fluent drift,
# a payload with every metadata input present, and one with latency stats only.
CORPUS: tuple[dict[str, Any], ...] = (
    {
        "id": "clean-grounded",
        "prompt": "What is the capital of France?",
        "response": "The capital of France is Paris.",
    },
    {
        "id": "repetition-loop",
        "prompt": "Summarise the report.",
        "response": "The report says the report says the report says the report says the report.",
    },
    {
        "id": "fluent-drift",
        "prompt": "What were the Q3 revenue figures?",
        "response": (
            "Quarterly performance reflects a confluence of macroeconomic tailwinds, and "
            "stakeholders should appreciate the nuanced trajectory of our strategic posture."
        ),
    },
    {
        "id": "full-metadata",
        "prompt": "Explain the gating rule.",
        "response": "Gating compares the decision risk score against the configured bands.",
        "metadata": {
            "entropy_decay": 0.4,
            "drift_slope": 0.25,
            "turn_index": 12,
            "duration_ms": 1850.0,
            "latency_window_stats": [120.0, 180.0, 140.0, 900.0],
        },
    },
    {
        "id": "latency-only",
        "prompt": "List the trust bands.",
        "response": "The bands are green, yellow, orange and red.",
        "metadata": {"latency_window_stats": [200.0, 205.0, 198.0]},
    },
)


class NetworkAccessAttempted(RuntimeError):
    """Raised when code under test tries to open a connection or resolve a name."""


@contextmanager
def network_blocked() -> Iterator[list[str]]:
    """Remove the network for the duration of the block, recording every attempt to use it.

    Yields the list of attempted calls. An empty list afterwards means the code inside made no
    attempt at all, which is a stronger statement than "it did not crash".
    """
    attempts: list[str] = []
    patched = {
        name: getattr(socket, name) for name in BLOCKED_SOCKET_CALLS if hasattr(socket, name)
    }

    def deny(name: str) -> Any:
        def _deny(*args: Any, **kwargs: Any) -> Any:
            attempts.append(name)
            raise NetworkAccessAttempted(f"socket.{name}() was called")

        return _deny

    for name in patched:
        setattr(socket, name, deny(name))
    try:
        yield attempts
    finally:
        for name, original in patched.items():
            setattr(socket, name, original)


def decision_product() -> list[dict[str, Any]]:
    """Everything the scoring and gating path observably produces for the corpus."""
    cases = []
    for entry in CORPUS:
        payload: dict[str, Any] = {"prompt": entry["prompt"], "response": entry["response"]}
        if "metadata" in entry:
            payload["metadata"] = entry["metadata"]
        bundle = score_payload(payload)
        assert bundle is not None, f"{entry['id']} was rejected by validation"
        aggregate = aggregate_score(bundle)
        policy = evaluate_policy(bundle)
        gate = decide_gate(aggregate, bundle.signal_scores)
        cases.append(
            {
                "id": entry["id"],
                "signal_schema_version": bundle.signal_schema_version,
                "missing_inputs": list(bundle.missing_inputs),
                "signal_scores": bundle.signal_scores.as_dict(),
                "derived_signals": bundle.derived_signals.as_dict(),
                "aggregate_score": aggregate,
                "evaluate_policy": {f: getattr(policy, f) for f in DECISION_FIELDS},
                "decide_gate": {f: getattr(gate, f) for f in DECISION_FIELDS},
            }
        )
    return cases


def digest(product: list[dict[str, Any]]) -> str:
    """A short, readable fingerprint, so a mismatch names itself in the assertion message."""
    text = json.dumps(product, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# Imports the requested modules in a fresh interpreter and reports what was actually loaded. Run
# with -I so an inherited PYTHONPATH, the working directory or a user site directory cannot
# pre-import something and quietly corrupt the audit.
_AUDIT_CHILD = """
import importlib
import json
import sys

sys.path.insert(0, sys.argv[1])
for name in sys.argv[2].split(","):
    importlib.import_module(name)
print(json.dumps(sorted({module.split(".")[0] for module in sys.modules})))
"""


def loaded_modules(*modules: str) -> frozenset[str]:
    result = subprocess.run(
        [sys.executable, "-I", "-c", _AUDIT_CHILD, str(SRC_DIR), ",".join(modules)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"import audit failed: {result.stderr.strip()}"
    return frozenset(json.loads(result.stdout))


def test_network_blocker_records_and_raises() -> None:
    """The instrument works. Every other test here depends on this one being true."""
    with network_blocked() as attempts:
        with pytest.raises(NetworkAccessAttempted):
            socket.socket()
        with pytest.raises(NetworkAccessAttempted):
            socket.getaddrinfo("example.invalid", 443)
    assert attempts == ["socket", "getaddrinfo"]
    # The real socket module is restored on the way out, so one test cannot leak into the next.
    assert socket.socket is not None
    assert "deny" not in getattr(socket.socket, "__name__", "socket")


def test_scoring_and_gating_make_no_network_call() -> None:
    baseline = decision_product()
    with network_blocked() as attempts:
        blocked = decision_product()
    assert attempts == [], f"scoring or gating tried to use the network: {attempts}"
    assert digest(blocked) == digest(baseline)
    assert blocked == baseline


def test_scoring_core_loads_no_network_or_ai_stack() -> None:
    """The scoring core is importable without a TLS client, an HTTP client or an ML framework.

    ``lionlock/__init__.py`` exports ``TrustVaultLogger``, so importing the core necessarily runs
    the package ``__init__`` too. This asserts what that whole chain pulls in.
    """
    loaded = loaded_modules("lionlock.core", "lionlock.signal_schemas")
    assert not (loaded & FORBIDDEN_THIRD_PARTY)
    for module in ("ssl", "http", "asyncio"):
        assert module not in loaded, f"importing the scoring core loaded {module}"


def test_scoring_core_loads_no_unlisted_risky_stdlib() -> None:
    """Nothing network-capable or random beyond the documented, attributed transitive imports."""
    loaded = loaded_modules("lionlock.core", "lionlock.signal_schemas")
    risky = {
        "socket",
        "selectors",
        "urllib",
        "random",
        "uuid",
        "ssl",
        "http",
        "asyncio",
        "secrets",
        "ftplib",
        "smtplib",
        "xmlrpc",
        "telnetlib",
    }
    assert (loaded & risky) <= CORE_ALLOWED_STDLIB


def test_telemetry_path_loads_no_ai_stack_and_no_new_network_surface() -> None:
    """The export path loads the opt-in uploader, and that is the whole network surface.

    Loading is not calling: nothing here opens a connection, and uploads are opt-in and off by
    default. The point of pinning the set is that it cannot grow without a test failing. Shrinking
    it, by having ``lionlock/telemetry/__init__.py`` stop importing ``.upload`` eagerly, is the
    fix rather than a regression, and the subset check below accepts it.
    """
    loaded = loaded_modules(
        "lionlock.telemetry.canonical",
        "lionlock.telemetry.policy",
        "lionlock.telemetry.export",
        "lionlock.trust_overlay.engine",
    )
    assert not (loaded & FORBIDDEN_THIRD_PARTY)
    risky = {
        "socket",
        "selectors",
        "urllib",
        "random",
        "uuid",
        "ssl",
        "http",
        "sqlite3",
        "secrets",
        "asyncio",
        "ftplib",
        "smtplib",
        "xmlrpc",
        "telnetlib",
    }
    assert (loaded & risky) <= TELEMETRY_ALLOWED_STDLIB


def test_schema_version_is_reported_for_the_record() -> None:
    """Ties the proof to a schema version, so a future change cannot silently re-scope it."""
    assert SIGNAL_SCHEMA_VERSION == "SE-0.4.0"
