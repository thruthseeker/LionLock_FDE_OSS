"""The single gate: ``python -m harness verify [--spec ID]``.

Every check is deterministic and reports the same thing for every agent. Nothing here reads the
network, samples, or depends on wall-clock time, so two agents on the same commit get the same
report. Findings from the privacy check carry locations only, never the offending text, because
this repo is public and the report itself is written to disk.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any, Iterable, Sequence

from harness.fingerprint import canonical, fingerprint
from harness.specs import (
    Spec,
    SpecError,
    discover_specs,
    load_oracle_callable,
    load_product_callable,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
HARNESS_DIR = REPO_ROOT / "harness"
SPECS_DIR = HARNESS_DIR / "specs"
BASELINE_DIR = HARNESS_DIR / "baseline"
OUT_DIR = HARNESS_DIR / "out"
CONTRACT_LOCK = HARNESS_DIR / "contract.lock.json"
PYTHON_VERSION_FILE = REPO_ROOT / ".python-version"
REQUIREMENTS_LOCK = HARNESS_DIR / "env" / "requirements.lock"

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"
PENDING = "PENDING"

PINNED_TOOLS = ("pydantic", "pytest", "ruff", "mypy")

# Files an agent working a job must never edit. The contract check makes that mechanical instead of
# a matter of trust.
PROTECTED_GLOBS = (
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "Makefile",
    ".python-version",
    ".github/workflows/verify.yml",
    ".devcontainer/devcontainer.json",
)

PRIVACY_PATTERNS: tuple[tuple[str, str], ...] = (
    ("home_path", r"/(?:home|Users)/[A-Za-z0-9._-]+"),
    ("email", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    ("private_dir", r"\.private/"),
    ("private_ipv4", r"\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b"),
    (
        "credential",
        r"\b(?:sk-[A-Za-z0-9]{8,}|ghp_[A-Za-z0-9]{8,}|github_pat_[A-Za-z0-9_]{8,}|AKIA[0-9A-Z]{12,})\b",
    ),
    ("private_key", r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----"),
)

# The privacy scanner would otherwise flag its own pattern table. Exact paths only: a prefix match
# would also skip files such as harness/verify.pyi or AGENTS.md.bak.
PRIVACY_SCAN_EXCLUDES = frozenset({"harness/verify.py"})


@dataclass
class CheckResult:
    name: str
    status: str
    detail: str
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def failed(self) -> bool:
        return self.status == FAIL


# The only caller variables a check may see. Everything else is dropped, so a shell setting such as
# LIONLOCK_GATING_ENABLED, DO_NOT_TRACK or PYTEST_ADDOPTS cannot change a result.
PASSTHROUGH_ENV = (
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "VIRTUAL_ENV",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "COMSPEC",
    "PATHEXT",
    "USERPROFILE",
)


def _run(
    command: Sequence[str],
    *,
    cwd: Path = REPO_ROOT,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command with a fixed environment, so results don't depend on the caller's shell."""
    env = {name: os.environ[name] for name in PASSTHROUGH_ENV if name in os.environ}
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONUTF8"] = "1"
    # Colour codes and progress bars would end up in the report.
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        list(command), cwd=str(cwd), env=env, capture_output=True, text=True, check=False
    )


def _git(*args: str) -> str:
    result = _run(["git", *args])
    return result.stdout.strip() if result.returncode == 0 else ""


def _git_porcelain() -> tuple[tuple[str, str], ...]:
    """``git status --porcelain`` as (status, path) pairs.

    Parsed here rather than through ``_git`` because ``_git`` strips the whole output, which eats
    the leading space of the first line. Porcelain lines are two status characters, a space, then
    the path, so for an unstaged modification (" M AGENTS.md") that strip shifted every slice by
    one and ``line[3:]`` yielded "GENTS.md" — a path matching no allowed_paths entry, which the
    scope check then reported as a violation. Staged and untracked entries begin with a non-space
    character, so only the first line of certain runs was affected.
    """
    result = _run(["git", "status", "--porcelain", "--untracked-files=all"])
    if result.returncode != 0:
        return ()
    return parse_porcelain(result.stdout)


def parse_porcelain(output: str) -> tuple[tuple[str, str], ...]:
    """Parse porcelain text into sorted (status, path) pairs. Pure, so it is directly testable."""
    entries = []
    for line in output.splitlines():
        if len(line) < 4:
            continue
        status, path = line[:2], line[3:].strip().strip('"')
        # Renames read "old -> new"; only the destination matters.
        path = path.split(" -> ")[-1].strip().strip('"')
        if path:
            entries.append((status, path))
    return tuple(sorted(entries))


def _relative(path: str | Path) -> str:
    candidate = Path(path)
    try:
        return candidate.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return candidate.as_posix()


# --------------------------------------------------------------------------------------- check 1


def check_env() -> CheckResult:
    if not PYTHON_VERSION_FILE.is_file():
        return CheckResult("env", FAIL, f"{_relative(PYTHON_VERSION_FILE)} is missing")
    expected = PYTHON_VERSION_FILE.read_text().strip()
    actual = f"{sys.version_info.major}.{sys.version_info.minor}"
    problems: list[str] = []
    if actual != expected:
        problems.append(f"python {actual}, expected {expected}")

    pinned = _pinned_versions()
    installed: dict[str, str] = {}
    for tool in PINNED_TOOLS:
        try:
            from importlib.metadata import version as dist_version

            installed[tool] = dist_version(tool)
        except Exception:
            installed[tool] = "absent"
        if tool in pinned and installed[tool] != pinned[tool]:
            problems.append(f"{tool} {installed[tool]}, expected {pinned[tool]}")

    data = {"python": actual, "expected_python": expected, "tools": installed, "pinned": pinned}
    if problems:
        return CheckResult("env", FAIL, "; ".join(problems) + " — run `make setup`", data)
    return CheckResult(
        "env",
        PASS,
        f"python {actual}, " + ", ".join(f"{tool} {installed[tool]}" for tool in PINNED_TOOLS),
        data,
    )


def _pinned_versions() -> dict[str, str]:
    if not REQUIREMENTS_LOCK.is_file():
        return {}
    pinned: dict[str, str] = {}
    for line in REQUIREMENTS_LOCK.read_text().splitlines():
        match = re.match(r"^([A-Za-z0-9._-]+)==([^\s\\]+)", line.strip())
        if match:
            pinned[match.group(1).lower().replace("_", "-")] = match.group(2)
    return {tool: pinned[tool] for tool in PINNED_TOOLS if tool in pinned}


# --------------------------------------------------------------------------------------- check 2


def protected_files() -> tuple[str, ...]:
    """Protected paths that exist, plus everything under harness/ bar the report directory."""
    found = {glob for glob in PROTECTED_GLOBS if (REPO_ROOT / glob).is_file()}
    for path in HARNESS_DIR.rglob("*"):
        if not path.is_file():
            continue
        relative = _relative(path)
        if relative.startswith("harness/out/") or "__pycache__" in relative:
            continue
        if relative == _relative(CONTRACT_LOCK):
            continue  # the lock cannot contain its own hash
        found.add(relative)
    return tuple(sorted(found))


def hash_protected() -> dict[str, str]:
    from lionlock.telemetry.canonical import sha256_hex

    digests: dict[str, str] = {}
    for relative in protected_files():
        raw = (REPO_ROOT / relative).read_bytes()
        # Fold CRLF so a Windows checkout agrees with a Linux one.
        digests[relative] = sha256_hex(raw.replace(b"\r\n", b"\n"))
    return digests


def check_contract() -> CheckResult:
    current = hash_protected()
    if not CONTRACT_LOCK.is_file():
        return CheckResult(
            "contract",
            SKIP,
            f"{_relative(CONTRACT_LOCK)} absent — run `make lock` (maintainer)",
            {"files": len(current)},
        )
    raw: Any = json.loads(CONTRACT_LOCK.read_text())
    locked: dict[str, str] = (
        {str(key): str(value) for key, value in raw["files"].items()}
        if isinstance(raw, dict) and isinstance(raw.get("files"), dict)
        else {}
    )
    changed = sorted(key for key in set(locked) & set(current) if locked[key] != current[key])
    added = sorted(set(current) - set(locked))
    removed = sorted(set(locked) - set(current))
    data = {"changed": changed, "added": added, "removed": removed, "files": len(current)}
    if changed or added or removed:
        parts = []
        if changed:
            parts.append(f"{len(changed)} modified ({', '.join(changed[:3])})")
        if added:
            parts.append(f"{len(added)} added ({', '.join(added[:3])})")
        if removed:
            parts.append(f"{len(removed)} removed ({', '.join(removed[:3])})")
        return CheckResult(
            "contract", FAIL, "; ".join(parts) + " — a maintainer must re-run `make lock`", data
        )
    return CheckResult("contract", PASS, f"{len(current)} protected files match the lock", data)


# --------------------------------------------------------------------------------------- check 3


def _tool_failure(name: str, result: subprocess.CompletedProcess[str], why: str) -> list[str]:
    """A synthetic finding for a tool that did not run properly.

    It can never appear in a baseline, so the ratchet reports it as new and the gate fails. Without
    this a crashed linter returns zero findings, which reads exactly like a clean tree — the most
    dangerous failure mode a gate can have.
    """
    detail = next(
        (
            line.strip()
            for line in (result.stdout + "\n" + result.stderr).splitlines()
            if line.strip()
        ),
        "no output",
    )
    return [name, "harness-tool-failure", f"{why}: {detail}"]


def collect_ruff() -> list[list[str]]:
    result = _run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            ".",
            "--output-format",
            "json",
            "--exit-zero",
            "--no-cache",
        ]
    )
    try:
        findings = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        return [_tool_failure("ruff", result, "output was not valid JSON")]
    if result.returncode != 0:
        return [_tool_failure("ruff", result, f"exit code {result.returncode} with --exit-zero")]
    return sorted(
        [
            _relative(item.get("filename", "")),
            str(item.get("code") or ""),
            str(item.get("message", "")),
        ]
        for item in findings
    )


FORMAT_ARROW = re.compile(r"^\s*-->\s*(?P<file>.+?):\d+:\d+\s*$")


def collect_format() -> list[list[str]]:
    """One finding per file ruff would reformat.

    ruff 0.16 reports these as an ``unformatted:`` header followed by an ``--> path:line:col``
    arrow, so the arrow is what identifies the file. Deduplicated, because a file with several
    differing regions can carry more than one arrow and the ratchet compares identities.
    """
    result = _run([sys.executable, "-m", "ruff", "format", "--check", ".", "--no-cache"])
    # 0 = everything formatted, 1 = some files would be reformatted. Anything else is a bad run.
    if result.returncode not in (0, 1):
        return [_tool_failure("ruff-format", result, f"exit code {result.returncode}")]
    files = set()
    for line in result.stdout.splitlines():
        match = FORMAT_ARROW.match(line)
        if match:
            files.add(_relative(match.group("file")))
    if result.returncode == 1 and not files:
        return [_tool_failure("ruff-format", result, "reported changes but no file parsed")]
    return sorted([path, "format", "would reformat"] for path in sorted(files))


MYPY_LINE = re.compile(
    r"^(?P<file>[^:]+):(?P<line>\d+):(?:\d+:)?\s*error:\s*(?P<msg>.*?)(?:\s+\[(?P<code>[a-z-]+)\])?$"
)


def collect_mypy() -> list[list[str]]:
    result = _run(
        [
            sys.executable,
            "-m",
            "mypy",
            "src",
            "harness",
            # Spec directories hold same-named modules (every spec has a product.py) and are loaded
            # by file path, never imported as packages. Without this mypy aborts with "Duplicate
            # module named product" and checks nothing at all.
            "--exclude",
            "^harness/specs/",
            "--no-error-summary",
            "--show-error-codes",
            "--no-pretty",
            "--hide-error-context",
        ]
    )
    found = []
    for line in result.stdout.splitlines():
        match = MYPY_LINE.match(line.strip())
        if match:
            found.append(
                [
                    _relative(match.group("file")),
                    match.group("code") or "error",
                    match.group("msg").strip(),
                ]
            )
    # 0 = clean, 1 = errors found. 2 means a usage or fatal error, where the absence of parsed
    # findings means "mypy never ran", not "there is nothing wrong".
    if result.returncode not in (0, 1):
        found.append(_tool_failure("mypy", result, f"exit code {result.returncode}"))
    elif result.returncode == 1 and not found:
        found.append(_tool_failure("mypy", result, "reported errors but none could be parsed"))
    return sorted(found)


COLLECTORS = {"ruff": collect_ruff, "format": collect_format, "mypy": collect_mypy}


def _baseline_path(name: str) -> Path:
    return BASELINE_DIR / f"{name}.json"


def check_ratchet() -> list[CheckResult]:
    """Fail only on findings that aren't already in the baseline.

    Compared as a multiset of (file, code, message), so inserting a line above an existing finding
    doesn't register as new. Legacy debt stays untouched, which keeps this out of the way of other
    open PRs.
    """
    results = []
    for name in sorted(COLLECTORS):
        found = COLLECTORS[name]()
        path = _baseline_path(name)
        if not path.is_file():
            results.append(
                CheckResult(
                    f"ratchet:{name}",
                    SKIP,
                    f"no baseline — run `make baseline` (maintainer); {len(found)} findings now",
                    {"found": len(found)},
                )
            )
            continue
        baseline = Counter(tuple(item) for item in json.loads(path.read_text()))
        current = Counter(tuple(item) for item in found)
        new = current - baseline
        fixed = baseline - current
        data = {
            "found": len(found),
            "baseline": sum(baseline.values()),
            "new": [list(item) for item, count in sorted(new.items()) for _ in range(count)],
            "fixed_count": sum(fixed.values()),
        }
        if new:
            first = "; ".join(f"{item[0]} {item[1]}" for item in sorted(new)[:3])
            results.append(
                CheckResult(
                    f"ratchet:{name}", FAIL, f"{sum(new.values())} new finding(s): {first}", data
                )
            )
        else:
            note = f"{len(found)} findings, none new"
            if fixed:
                note += f" ({sum(fixed.values())} fewer than baseline)"
            results.append(CheckResult(f"ratchet:{name}", PASS, note, data))
    return results


# --------------------------------------------------------------------------------------- check 4


def check_tests() -> CheckResult:
    result = _run(
        [sys.executable, "-m", "pytest", "-o", "addopts=", "-p", "no:cacheprovider", "-q", "-rfE"]
    )
    lines = [line for line in result.stdout.strip().splitlines() if line.strip()]
    summary = lines[-1] if lines else "no output"
    # Test ids only, from pytest's short summary; enough to find the failure without the full log.
    failing = [
        line.split(" - ")[0].split(" ", 1)[1]
        for line in lines
        if line.startswith(("FAILED ", "ERROR ")) and " " in line
    ]
    data = {"returncode": result.returncode, "summary": summary, "failing": failing}
    if result.returncode != 0:
        detail = summary + (": " + ", ".join(failing[:3]) if failing else "")
        return CheckResult("tests", FAIL, detail, data)
    return CheckResult("tests", PASS, summary, data)


# --------------------------------------------------------------------------------------- check 5


def check_acceptance(spec: Spec, *, selected: bool) -> CheckResult:
    name = f"acceptance:{spec.spec_id}"
    if not spec.acceptance_path.is_file():
        return CheckResult(name, SKIP, "no test_acceptance.py")
    blocking = spec.is_blocking or selected
    result = _run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(spec.acceptance_path),
            "-o",
            "addopts=",
            "-p",
            "no:cacheprovider",
            "--import-mode=importlib",
            "-q",
        ]
    )
    tail = [line for line in result.stdout.strip().splitlines() if line.strip()]
    summary = tail[-1] if tail else "no output"
    data = {"returncode": result.returncode, "summary": summary, "blocking": blocking}
    if result.returncode == 0:
        return CheckResult(name, PASS, summary, data)
    if blocking:
        return CheckResult(name, FAIL, summary, data)
    return CheckResult(name, PENDING, f"not implemented yet — {summary}", data)


# --------------------------------------------------------------------------------------- check 6


def _product_in_subprocess(spec: Spec, hashseed: str) -> tuple[str | None, str]:
    result = _run(
        [sys.executable, "-m", "harness", "product", "--spec", spec.spec_id],
        extra_env={"PYTHONHASHSEED": hashseed},
    )
    if result.returncode != 0:
        return None, (result.stderr.strip() or result.stdout.strip())[-400:]
    return result.stdout.strip(), ""


def check_determinism(spec: Spec, *, selected: bool) -> CheckResult:
    """Run product() twice in fresh processes under different hash seeds; demand byte equality."""
    name = f"determinism:{spec.spec_id}"
    if not spec.product_path.is_file():
        return CheckResult(name, SKIP, "no product.py")
    blocking = spec.is_blocking or selected

    first, error = _product_in_subprocess(spec, "0")
    if first is None:
        status = FAIL if blocking else PENDING
        return CheckResult(name, status, f"product() failed: {error}", {"blocking": blocking})
    second, error = _product_in_subprocess(spec, "4242")
    if second is None:
        status = FAIL if blocking else PENDING
        return CheckResult(
            name, status, f"product() failed on rerun: {error}", {"blocking": blocking}
        )

    from lionlock.telemetry.canonical import sha256_hex

    actual_fp = sha256_hex(first)
    data: dict[str, Any] = {"blocking": blocking, "fingerprint": actual_fp}
    if first != second:
        return CheckResult(name, FAIL, "product() is not deterministic across hash seeds", data)

    golden_fp = _golden_fingerprint(spec)
    data["golden_fingerprint"] = golden_fp
    if golden_fp is None:
        return CheckResult(name, SKIP, f"deterministic ({actual_fp[:12]}), no golden yet", data)
    if golden_fp != actual_fp:
        status = FAIL if blocking else PENDING
        return CheckResult(
            name, status, f"fingerprint {actual_fp[:12]} != golden {golden_fp[:12]}", data
        )
    return CheckResult(name, PASS, f"deterministic and matches golden ({golden_fp[:12]})", data)


def _golden_fingerprint(spec: Spec) -> str | None:
    if not spec.golden_path.is_file():
        return None
    golden = json.loads(spec.golden_path.read_text())
    value = golden.get("expected_fingerprint")
    return str(value) if isinstance(value, str) else None


def product_text(spec: Spec) -> str:
    """Canonical JSON for a spec's product. Used by the ``product`` subcommand."""
    return canonical(load_product_callable(spec)())


# --------------------------------------------------------------------------------------- 7 and 8


def _contract_base_commit(changed_since: str | None = None) -> tuple[str, str]:
    """Where the scope and privacy diffs start.

    With ``changed_since`` (CI) it is the merge-base, so the diffs cover exactly the change under
    review and never commits that landed on the base branch since. Without it (local runs) it is the
    commit that last touched the contract lock.
    """
    if changed_since:
        sha = _git("merge-base", changed_since, "HEAD")
        if sha:
            return sha, f"merge-base with {changed_since}"
    sha = _git("log", "-1", "--format=%H", "--", str(CONTRACT_LOCK.relative_to(REPO_ROOT)))
    if sha:
        return sha, "last commit touching the contract lock"
    sha = _git("rev-parse", "HEAD")
    return sha, "HEAD (contract lock not committed yet)"


def _changed_paths(base: str) -> tuple[str, ...]:
    changed: set[str] = set()
    for line in _git("diff", "--name-only", f"{base}..HEAD").splitlines():
        if line.strip():
            changed.add(line.strip())
    for _status, path in _git_porcelain():
        changed.add(path)
    return tuple(sorted(path for path in changed if path))


def _glob_matches(path: str, pattern: str) -> bool:
    """Whole-path glob match where ``*`` never crosses a ``/``.

    ``Path.match`` anchors relative patterns on the right, so ``tests/test_*.py`` would also match
    ``anything/tests/test_x.py``; plain ``fnmatch`` lets ``*`` span directories. Matching component
    by component avoids both.
    """
    parts = path.split("/")
    pattern_parts = pattern.split("/")
    return len(parts) == len(pattern_parts) and all(
        fnmatchcase(part, glob) for part, glob in zip(parts, pattern_parts, strict=True)
    )


def _within_allowed(path: str, allowed: Iterable[str]) -> bool:
    for pattern in allowed:
        if path == pattern or _glob_matches(path, pattern):
            return True
        if pattern.endswith("/") and path.startswith(pattern):
            return True
    return False


def check_scope(spec: Spec, changed_since: str | None = None) -> CheckResult:
    base, origin = _contract_base_commit(changed_since)
    if not base:
        return CheckResult(f"scope:{spec.spec_id}", SKIP, "not a git checkout")
    changed = _changed_paths(base)
    # Harness-owned files are governed by the contract check, not by a spec's allowed paths.
    reviewed = [path for path in changed if not path.startswith("harness/out/")]
    outside = sorted(path for path in reviewed if not _within_allowed(path, spec.allowed_paths))
    data = {"base": base, "base_origin": origin, "changed": list(reviewed), "outside": outside}
    if outside:
        return CheckResult(
            f"scope:{spec.spec_id}",
            FAIL,
            f"{len(outside)} file(s) outside allowed_paths: {', '.join(outside[:5])}",
            data,
        )
    return CheckResult(
        f"scope:{spec.spec_id}",
        PASS,
        f"{len(reviewed)} changed file(s), all in allowed_paths",
        data,
    )


def check_privacy(changed_since: str | None = None) -> CheckResult:
    """Scan added lines for things a public repo must not carry. Locations only, never the text."""
    base, origin = _contract_base_commit(changed_since)
    if not base:
        return CheckResult("privacy", SKIP, "not a git checkout")

    findings: list[dict[str, Any]] = []
    diff = _run(["git", "diff", "--unified=0", base, "--", "."]).stdout
    current_file = ""
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            continue
        if line.startswith("+") and not line.startswith("+++"):
            findings.extend(_scan_line(current_file, line[1:]))

    for path in _untracked_text_files():
        try:
            for number, line in enumerate(
                (REPO_ROOT / path).read_text(errors="replace").splitlines(), start=1
            ):
                findings.extend(_scan_line(path, line, line_number=number))
        except OSError:
            continue

    data = {"base": base, "base_origin": origin, "findings": findings}
    if findings:
        where = "; ".join(
            f"{item['file']}:{item['line']} {item['pattern']}" for item in findings[:5]
        )
        return CheckResult("privacy", FAIL, f"{len(findings)} finding(s): {where}", data)
    return CheckResult(
        "privacy", PASS, "no home paths, emails, private IPs or credentials added", data
    )


def _scan_line(path: str, text: str, *, line_number: int | str = "?") -> list[dict[str, Any]]:
    if not path or path in PRIVACY_SCAN_EXCLUDES:
        return []
    if path.startswith("harness/out/"):
        return []
    hits = []
    for name, pattern in PRIVACY_PATTERNS:
        if re.search(pattern, text):
            # Location and pattern name only. The matched text is deliberately not recorded.
            hits.append({"file": path, "line": line_number, "pattern": name})
    return hits


def _untracked_text_files() -> tuple[str, ...]:
    paths = [
        path
        for status, path in _git_porcelain()
        if status == "??" and not path.endswith("/") and (REPO_ROOT / path).is_file()
    ]
    return tuple(sorted(paths))


# ----------------------------------------------------------------------------------- orchestration


def touched_specs(specs: Sequence[Spec], changed_since: str) -> tuple[str, ...]:
    """Open specs whose ``allowed_paths`` cover a file changed since ``changed_since``.

    CI cannot be told which job a pull request works, so it infers it: a change that touches an open
    spec's files is treated as that spec's job, and its acceptance and scope checks block.
    """
    changed = [
        line.strip()
        for line in _git("diff", "--name-only", f"{changed_since}...HEAD").splitlines()
        if line.strip()
    ]
    return tuple(
        spec.spec_id
        for spec in specs
        if spec.status == "open"
        and any(_within_allowed(path, spec.allowed_paths) for path in changed)
    )


def verify(spec_id: str | None = None, *, changed_since: str | None = None) -> int:
    specs = discover_specs(SPECS_DIR)
    if spec_id and not any(spec.spec_id == spec_id for spec in specs):
        print(f"RESULT: FAIL\nunknown spec {spec_id!r}", file=sys.stderr)
        return 2
    if changed_since and not _git("rev-parse", "--verify", "--quiet", changed_since):
        print(f"RESULT: FAIL\nunknown revision {changed_since!r}", file=sys.stderr)
        return 2

    selected_ids = set(touched_specs(specs, changed_since) if changed_since else ())
    if spec_id:
        selected_ids.add(spec_id)

    results: list[CheckResult] = [check_env(), check_contract()]
    results.extend(check_ratchet())
    results.append(check_tests())

    for spec in specs:
        selected = spec.spec_id in selected_ids
        results.append(check_acceptance(spec, selected=selected))
        results.append(check_determinism(spec, selected=selected))

    results.append(check_privacy(changed_since))
    for spec in specs:
        if spec.spec_id in selected_ids:
            results.append(check_scope(spec, changed_since))

    failed = [item for item in results if item.failed]
    overall = FAIL if failed else PASS
    _write_report(results, overall, spec_id, sorted(selected_ids))
    _print_report(results, overall, spec_id)
    return 1 if failed else 0


def _write_report(
    results: Sequence[CheckResult], overall: str, spec_id: str | None, selected: Sequence[str]
) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "result": overall,
        "spec": spec_id,
        "selected_specs": list(selected),
        "commit": _git("rev-parse", "HEAD"),
        "checks": [
            {"name": item.name, "status": item.status, "detail": item.detail, "data": item.data}
            for item in results
        ],
    }
    # Canonical, so two agents' reports differ only where their results differ.
    (OUT_DIR / "verify_report.json").write_text(canonical(payload) + "\n")


def _print_report(results: Sequence[CheckResult], overall: str, spec_id: str | None) -> None:
    width = max((len(item.name) for item in results), default=10)
    for item in results:
        print(f"{item.status:<8} {item.name:<{width}}  {item.detail}")
    print()
    if spec_id:
        print(f"SPEC: {spec_id}")
        for item in results:
            if item.name.startswith("determinism:") and spec_id in item.name:
                got = item.data.get("fingerprint")
                if got:
                    print(f"FINGERPRINT: {got}")
    print(f"RESULT: {overall}")


# ------------------------------------------------------------------------------- maintainer actions


def write_baseline() -> int:
    BASELINE_DIR.mkdir(parents=True, exist_ok=True)
    for name in sorted(COLLECTORS):
        found = COLLECTORS[name]()
        _baseline_path(name).write_text(json.dumps(found, indent=2, sort_keys=True) + "\n")
        print(f"baseline {name}: {len(found)} findings -> {_relative(_baseline_path(name))}")
    return 0


def write_lock() -> int:
    digests = hash_protected()
    CONTRACT_LOCK.write_text(json.dumps({"files": digests}, indent=2, sort_keys=True) + "\n")
    print(f"contract lock: {len(digests)} files -> {_relative(CONTRACT_LOCK)}")
    return 0


def write_golden(spec_id: str) -> int:
    specs = {spec.spec_id: spec for spec in discover_specs(SPECS_DIR)}
    if spec_id not in specs:
        print(f"unknown spec {spec_id!r}", file=sys.stderr)
        return 2
    spec = specs[spec_id]
    try:
        observed = load_product_callable(spec)()
        oracle = load_oracle_callable(spec)
    except SpecError as error:
        print(str(error), file=sys.stderr)
        return 2

    if oracle is None:
        # No oracle: the golden can only record what the code already does. Fine for a spec written
        # after the fact, useless for gating a change that hasn't been made.
        expected = observed
        provenance = "product() — no oracle, so this golden records current behaviour"
    else:
        mirror = oracle(apply_rule=False)
        if canonical(mirror) != canonical(observed):
            print(
                f"oracle mirror disagrees with the library at {_first_difference(mirror, observed)}"
                "\nThe oracle no longer mirrors _evaluate_policy_with_scores. Fix the oracle before"
                " regenerating the golden.",
                file=sys.stderr,
            )
            return 2
        expected = oracle(apply_rule=True)
        provenance = "oracle.py — mirror reproduces the library exactly with the rule off"

    payload = {
        "spec": spec_id,
        "provenance": provenance,
        "expected_fingerprint": fingerprint(expected),
        "baseline_fingerprint": fingerprint(observed),
        "expected": expected,
        "baseline": observed,
    }
    spec.golden_path.write_text(canonical(payload) + "\n")
    print(f"golden {spec_id}: expected {payload['expected_fingerprint']}")
    print(f"  baseline (current behaviour): {payload['baseline_fingerprint']}")
    print(f"  provenance: {provenance}")
    print(f"  written to {_relative(spec.golden_path)}")
    return 0


def _first_difference(left: Any, right: Any, path: str = "") -> str:
    """Where two products first disagree, as a dotted path. Keeps oracle drift debuggable."""
    if isinstance(left, dict) and isinstance(right, dict):
        for key in sorted(set(left) | set(right)):
            if key not in left:
                return f"{path}.{key} (missing from the oracle)"
            if key not in right:
                return f"{path}.{key} (missing from the product)"
            if canonical(left[key]) != canonical(right[key]):
                return _first_difference(left[key], right[key], f"{path}.{key}")
        return path or "(no difference)"
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return f"{path} (length {len(left)} vs {len(right)})"
        for index, (one, other) in enumerate(zip(left, right)):
            if canonical(one) != canonical(other):
                return _first_difference(one, other, f"{path}[{index}]")
        return path or "(no difference)"
    return f"{path or '(root)'}: oracle {left!r} vs product {right!r}"
