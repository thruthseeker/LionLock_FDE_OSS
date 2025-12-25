"""Trust Overlay package (passive, read-only reference layer)."""

from .config import (
    DEFAULT_PROFILE,
    DRIFT_THRESHOLDS_BY_PROFILE,
    PROFILE_THRESHOLDS,
    TRUST_LOGIC_VERSION_DEFAULT,
    resolve_profile,
    resolve_runtime_mode,
    resolve_trust_logic_version,
    resolve_trust_overlay_config,
    resolve_trust_overlay_sql_config,
)
from .engine import (
    assign_badge,
    compute_confidence_band,
    compute_trust_score,
    compute_volatility,
    detect_drift,
    map_label,
    trigger_flags,
)
from .logger import append_trust_record, build_trust_record
from .schemas import TrustRecord, validate_trust_record
from .versioning import code_fingerprint

__all__ = [
    "DEFAULT_PROFILE",
    "DRIFT_THRESHOLDS_BY_PROFILE",
    "PROFILE_THRESHOLDS",
    "TRUST_LOGIC_VERSION_DEFAULT",
    "assign_badge",
    "append_trust_record",
    "build_trust_record",
    "code_fingerprint",
    "compute_confidence_band",
    "compute_trust_score",
    "compute_volatility",
    "detect_drift",
    "map_label",
    "resolve_profile",
    "resolve_runtime_mode",
    "resolve_trust_logic_version",
    "resolve_trust_overlay_config",
    "resolve_trust_overlay_sql_config",
    "trigger_flags",
    "TrustRecord",
    "validate_trust_record",
]
