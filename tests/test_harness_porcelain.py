"""Regression tests for porcelain parsing in the harness scope and privacy checks.

The defect these cover: ``_git`` strips its entire output, so the leading space of the first
``git status --porcelain`` line was consumed before the per-line ``line[3:]`` slice. A porcelain
line is two status characters, a space, then the path, so for an unstaged modification
(" M AGENTS.md") every slice shifted by one and the path came back as "GENTS.md". That path matches
no spec's ``allowed_paths``, so the scope check reported a violation against correctly scoped work.

Staged (``M ``, ``A ``) and untracked (``??``) entries begin with a non-space character, which is
why only some runs were affected and the failure looked intermittent.
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness.verify import parse_porcelain  # noqa: E402


def test_unstaged_modification_keeps_its_first_character() -> None:
    """The exact shape that used to lose a character."""
    assert parse_porcelain(" M AGENTS.md\n") == ((" M", "AGENTS.md"),)


def test_leading_unstaged_entry_does_not_shift_later_entries() -> None:
    output = " M AGENTS.md\n M harness/verify.py\n?? notes.txt\n"
    assert parse_porcelain(output) == (
        (" M", "AGENTS.md"),
        (" M", "harness/verify.py"),
        ("??", "notes.txt"),
    )


def test_every_status_prefix_yields_an_intact_path() -> None:
    for prefix in (" M", "M ", "MM", "A ", " D", "D ", "??", "AM", "R "):
        assert parse_porcelain(f"{prefix} harness/verify.py") == ((prefix, "harness/verify.py"),), (
            prefix
        )


def test_rename_reports_the_destination() -> None:
    assert parse_porcelain("R  old/name.py -> new/name.py") == (("R ", "new/name.py"),)


def test_quoted_paths_are_unquoted() -> None:
    assert parse_porcelain(' M "harness/a file.py"') == ((" M", "harness/a file.py"),)


def test_blank_and_truncated_lines_are_ignored() -> None:
    assert parse_porcelain("\n\n M \nxyz\n M real.py\n") == ((" M", "real.py"),)


def test_output_is_sorted_so_reports_are_deterministic() -> None:
    forward = parse_porcelain(" M b.py\n M a.py\n")
    reverse = parse_porcelain(" M a.py\n M b.py\n")
    assert forward == reverse == ((" M", "a.py"), (" M", "b.py"))
