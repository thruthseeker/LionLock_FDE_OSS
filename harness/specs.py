"""Spec discovery and loading.

A spec is a directory under ``harness/specs/`` holding a ``SPEC.md`` whose TOML front matter sits
between ``+++`` lines. Everything the harness needs to gate a job comes from that front matter, so
the prose below it can be written for whichever agent is reading it without affecting the gate.
"""

from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import tomllib

FRONT_MATTER_FENCE = "+++"

VALID_STATUSES = ("open", "done")
# This repository is public, so every spec is too. Specs that read private data belong in a private
# repository; a "private" tier here would invite exactly the leak the privacy check exists to stop.
VALID_TIERS = ("public",)


class SpecError(RuntimeError):
    """A spec is malformed. Always a maintainer bug, never an agent's fault."""


@dataclass(frozen=True)
class Spec:
    spec_id: str
    title: str
    status: str
    tier: str
    allowed_paths: tuple[str, ...]
    directory: Path

    @property
    def product_path(self) -> Path:
        return self.directory / "product.py"

    @property
    def golden_path(self) -> Path:
        return self.directory / "golden.json"

    @property
    def acceptance_path(self) -> Path:
        return self.directory / "test_acceptance.py"

    @property
    def is_blocking(self) -> bool:
        """``done`` specs must keep passing forever; ``open`` ones only block when selected."""
        return self.status == "done"


def _split_front_matter(text: str, source: Path) -> str:
    lines = text.splitlines()
    if not lines or lines[0].strip() != FRONT_MATTER_FENCE:
        raise SpecError(f"{source}: must start with a {FRONT_MATTER_FENCE} front-matter fence")
    for index in range(1, len(lines)):
        if lines[index].strip() == FRONT_MATTER_FENCE:
            return "\n".join(lines[1:index])
    raise SpecError(f"{source}: front matter is never closed with {FRONT_MATTER_FENCE}")


def load_spec(directory: Path) -> Spec:
    source = directory / "SPEC.md"
    if not source.is_file():
        raise SpecError(f"{directory}: no SPEC.md")
    try:
        meta: dict[str, Any] = tomllib.loads(_split_front_matter(source.read_text(), source))
    except tomllib.TOMLDecodeError as error:
        raise SpecError(f"{source}: front matter is not valid TOML: {error}") from error

    for key in ("id", "title", "status", "tier", "allowed_paths"):
        if key not in meta:
            raise SpecError(f"{source}: front matter is missing '{key}'")
    if meta["status"] not in VALID_STATUSES:
        raise SpecError(f"{source}: status must be one of {VALID_STATUSES}")
    if meta["tier"] not in VALID_TIERS:
        raise SpecError(f"{source}: tier must be one of {VALID_TIERS}")
    if meta["id"] != directory.name:
        raise SpecError(f"{source}: id {meta['id']!r} does not match directory {directory.name!r}")
    if not isinstance(meta["allowed_paths"], list) or not all(
        isinstance(item, str) for item in meta["allowed_paths"]
    ):
        raise SpecError(f"{source}: allowed_paths must be a list of strings")

    return Spec(
        spec_id=str(meta["id"]),
        title=str(meta["title"]),
        status=str(meta["status"]),
        tier=str(meta["tier"]),
        allowed_paths=tuple(meta["allowed_paths"]),
        directory=directory,
    )


def discover_specs(specs_root: Path) -> tuple[Spec, ...]:
    """Every spec, ordered by id so reports and exit codes are stable."""
    if not specs_root.is_dir():
        return ()
    directories = sorted(
        (
            child
            for child in specs_root.iterdir()
            if child.is_dir() and (child / "SPEC.md").is_file()
        ),
        key=lambda child: child.name,
    )
    return tuple(load_spec(directory) for directory in directories)


def load_oracle_callable(spec: Spec) -> Callable[..., Any] | None:
    """The spec's ``oracle.expected`` if it has one, else ``None``.

    An oracle lets a golden be generated before the change exists, which is the only way a spec can
    check an implementation rather than merely record it.
    """
    oracle_path = spec.directory / "oracle.py"
    if not oracle_path.is_file():
        return None
    module_name = f"_harness_oracle_{spec.spec_id.replace('-', '_')}"
    module_spec = importlib.util.spec_from_file_location(module_name, oracle_path)
    if module_spec is None or module_spec.loader is None:
        raise SpecError(f"{spec.spec_id}: oracle.py could not be imported")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    expected = getattr(module, "expected", None)
    if not callable(expected):
        raise SpecError(f"{spec.spec_id}: oracle.py defines no callable expected()")
    return expected


def load_product_callable(spec: Spec) -> Callable[[], Any]:
    """Import the spec's ``product.py`` by path and hand back its ``product`` function."""
    if not spec.product_path.is_file():
        raise SpecError(f"{spec.spec_id}: no product.py")
    module_name = f"_harness_product_{spec.spec_id.replace('-', '_')}"
    module_spec = importlib.util.spec_from_file_location(module_name, spec.product_path)
    if module_spec is None or module_spec.loader is None:
        raise SpecError(f"{spec.spec_id}: product.py could not be imported")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    product = getattr(module, "product", None)
    if not callable(product):
        raise SpecError(f"{spec.spec_id}: product.py defines no callable product()")
    return product
