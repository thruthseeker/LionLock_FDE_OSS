"""Canonical serialisation and fingerprints for harness products.

Reuses the repo's own ``canonical_json``/``sha256_hex`` so a fingerprint means the same thing here
as it does in telemetry. Two extra normalisations happen first, both so that two agents on two
machines agree byte for byte:

* Floats are rounded to ``FLOAT_PRECISION`` decimals. Different libm builds can disagree in the
  last bits of a sigmoid or a mean, which would otherwise break an exact fingerprint comparison.
* Non-finite floats become string sentinels. ``canonical_json`` is called with ``allow_nan=False``
  and would raise, and a crash is a worse failure mode than a recorded "this was NaN".
"""

from __future__ import annotations

import math
from typing import Any

from lionlock.telemetry.canonical import canonical_json, sha256_hex

FLOAT_PRECISION = 9

NAN_SENTINEL = "__nan__"
POS_INF_SENTINEL = "__inf__"
NEG_INF_SENTINEL = "__-inf__"


def normalise(value: Any) -> Any:
    """Recursively round floats and make the value safe for ``canonical_json``."""
    # bool is a subclass of int, so it has to be checked before the numeric branches.
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        if math.isnan(value):
            return NAN_SENTINEL
        if math.isinf(value):
            return POS_INF_SENTINEL if value > 0 else NEG_INF_SENTINEL
        rounded = round(value, FLOAT_PRECISION)
        # 0.0 and -0.0 are equal but serialise differently, so collapse the sign.
        return 0.0 if rounded == 0.0 else rounded
    if isinstance(value, dict):
        return {str(key): normalise(value[key]) for key in sorted(value, key=str)}
    if isinstance(value, (list, tuple)):
        return [normalise(item) for item in value]
    return str(value)


def canonical(value: Any) -> str:
    """Canonical JSON text for a product. Stable across processes and machines."""
    return canonical_json(normalise(value))


def fingerprint(value: Any) -> str:
    """SHA-256 of the canonical JSON text."""
    return sha256_hex(canonical(value))
