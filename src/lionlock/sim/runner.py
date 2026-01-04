from __future__ import annotations

import hashlib
import os
import socket
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from sqlalchemy import create_engine, text
except Exception:
    create_engine = None  # type: ignore[assignment]
    text = None  # type: ignore[assignment]

from lionlock import config as lionlock_config
from lionlock.core import gating as gating_module
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores, canonical_gating_decision
from lionlock.core.scoring import DEFAULT_SIGNAL_WEIGHTS, SIGNAL_SCHEMA_VERSION, aggregate_score
from lionlock.logging import events_sql, missed_signal_sql, sql_init
from lionlock.logging.connection import validate_identifier
from lionlock.replay import policy_registry
from lionlock.trust_overlay import resolve_trust_logic_version
from lionlock.trust_overlay.versioning import code_fingerprint

from . import labels as labels_module
from . import reporting
from .profiles import ScenarioSpec, build_profile


LIONLOCK_DB_CANONICAL = "postgresql://localhost/lionlock"
SQLITE_FALLBACK_PATH = "./sim_out/lionlock_sim.db"
SQLITE_FALLBACK_URI = f"sqlite:///{SQLITE_FALLBACK_PATH}"
DEFAULT_PROFILE = "standard"
DEFAULT_TURNS = 100
DEFAULT_SEED = 123
DECISION_ORDER = {"ALLOW": 0, "REFRESH": 1, "BLOCK": 2}


@dataclass(frozen=True)
class SimResult:
    run_id: str
    report: Dict[str, Any]
    output_paths: Dict[str, str]
    db_uri: str
    labels_path: str


@dataclass(frozen=True)
class DbTarget:
    uri: str
    engine: str
    schema: str
    db_source: str
    offline_fallback_engaged: bool
    warnings: List[str]


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _noise(seed: int, turn_index: int, tag: str) -> float:
    payload = f"{seed}:{turn_index}:{tag}".encode("utf-8")
    digest = hashlib.sha256(payload).digest()
    return int.from_bytes(digest[:4], "big") / 2**32


def _jitter(seed: int, turn_index: int, tag: str) -> float:
    return _noise(seed, turn_index, tag) - 0.5


def _sqlite_path_from_uri(uri: str) -> str | None:
    prefix = "sqlite:///"
    if not uri.startswith(prefix):
        return None
    return uri[len(prefix) :]


def _default_schema_for_engine(engine: str) -> str:
    return "public" if engine == "postgres" else "main"


def _detect_engine(uri: str) -> str:
    lowered = uri.lower()
    if lowered.startswith(("postgresql://", "postgres://")):
        return "postgres"
    if lowered.startswith("sqlite://"):
        return "sqlite"
    raise ValueError(f"Unsupported DB URI scheme: {uri!r}")


def _ensure_sqlite_parent(uri: str) -> None:
    sqlite_path = _sqlite_path_from_uri(uri)
    if not sqlite_path or sqlite_path == ":memory:":
        return
    path = Path(sqlite_path)
    path.parent.mkdir(parents=True, exist_ok=True)


def _test_postgres_connection(uri: str, *, timeout_s: float = 1.0) -> None:
    if create_engine is None or text is None:
        raise RuntimeError("SQLAlchemy required for postgres connectivity tests.")
    connect_args = {"connect_timeout": max(1, int(round(timeout_s)))}
    engine = create_engine(uri, connect_args=connect_args, pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    finally:
        try:
            engine.dispose()
        except Exception:
            pass


def _detect_offline(*, timeout_s: float = 0.3) -> bool:
    targets = [("1.1.1.1", 53), ("8.8.8.8", 53)]
    for host, port in targets:
        try:
            with socket.create_connection((host, port), timeout=timeout_s):
                return False
        except OSError:
            continue
    return True


def _resolve_db_target(
    *,
    explicit_db: str | None,
    env_db: str | None,
    schema_override: str | None,
) -> DbTarget:
    warnings: List[str] = []

    if explicit_db:
        uri = explicit_db
        db_source = "cli"
    elif env_db:
        uri = env_db
        db_source = "env"
    else:
        uri = LIONLOCK_DB_CANONICAL
        db_source = "runtime_constant"

    engine = _detect_engine(uri)
    offline_fallback_engaged = False

    if engine == "postgres":
        try:
            _test_postgres_connection(uri)
        except Exception:
            offline = _detect_offline()
            if offline and db_source == "runtime_constant":
                uri = SQLITE_FALLBACK_URI
                engine = "sqlite"
                db_source = "offline_fallback"
                offline_fallback_engaged = True
                warnings.append(
                    "SQLite fallback engaged (offline/no-postgres). Logs are local-only; sync is NOT NOW."
                )
            elif offline:
                raise RuntimeError(
                    "Postgres DSN provided via CLI/env is unreachable while offline; "
                    "refusing implicit sqlite fallback. Use --db sqlite:///... (or env) to opt in."
                ) from None
            else:
                raise RuntimeError(
                    "Postgres resolved but unreachable while online; refusing sqlite fallback."
                ) from None

    if engine == "sqlite":
        if db_source == "runtime_constant":
            raise RuntimeError(
                "SQLite cannot be the runtime default; use --db sqlite:///... or set LIONLOCK_DB_URL."
            )
        if db_source != "offline_fallback":
            warnings.append("SQLite selected; logs are local-only; sync is NOT NOW.")
        _ensure_sqlite_parent(uri)

    schema = schema_override or _default_schema_for_engine(engine)

    return DbTarget(
        uri=uri,
        engine=engine,
        schema=schema,
        db_source=db_source,
        offline_fallback_engaged=offline_fallback_engaged,
        warnings=warnings,
    )


def _baseline_policy_config() -> Dict[str, Any]:
    return {
        "gating": {
            "enabled": True,
            "thresholds": {"yellow": 0.45, "orange": 0.65, "red": 0.80},
            "hallucination_mode": "block",
        },
        "signals": {
            "enabled": list(DEFAULT_SIGNAL_WEIGHTS.keys()),
            "weights": dict(DEFAULT_SIGNAL_WEIGHTS),
        },
    }


def _canonical_config_hash(config: Dict[str, Any]) -> str:
    payload = reporting.canonical_json_bytes(config)
    return hashlib.sha256(payload).hexdigest()


def _resolve_policy(
    policy_version: str,
    *,
    registry_path: str | None,
) -> Tuple[str, Dict[str, Any], str]:
    policy_version = policy_registry.validate_policy_version(policy_version)
    if registry_path:
        bundle = policy_registry.resolve_policy(policy_version, registry_path=registry_path)
        config_hash = _canonical_config_hash(bundle.config)
        return bundle.policy_version, bundle.config, config_hash

    try:
        bundle = policy_registry.resolve_policy(policy_version)
    except (FileNotFoundError, KeyError, ValueError):
        config = _baseline_policy_config()
        return policy_version, config, _canonical_config_hash(config)

    config_hash = _canonical_config_hash(bundle.config)
    return bundle.policy_version, bundle.config, config_hash


def _run_id_base(
    profile: str,
    turns: int,
    seed: int,
    policy_version: str,
    config_hash: str,
    fingerprint: str,
) -> str:
    raw = f"{profile}|{turns}|{seed}|{policy_version}|{config_hash}|{fingerprint}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _append_run_id(run_id: str) -> str:
    nonce = uuid.uuid4().hex[:8]
    return f"{run_id}-{nonce}"


def _timestamp_for_turn(turn_index: int) -> str:
    base = datetime(2025, 1, 1, tzinfo=timezone.utc)
    ts = base + timedelta(seconds=turn_index)
    return ts.isoformat().replace("+00:00", "Z")


def _decision_for_db(decision: str) -> str:
    value = str(decision or "").strip().upper()
    if value == "WARN":
        value = "REFRESH"
    value = canonical_gating_decision(value)
    if value not in ("ALLOW", "REFRESH", "BLOCK"):
        raise ValueError(f"Unsupported gating decision token for DB: {value!r}")
    return value


def _evaluate_policy(bundle: SignalBundle, policy_config: Dict[str, Any]) -> Any:
    gating_cfg = policy_config.get("gating", {}) if isinstance(policy_config, dict) else {}
    signals_cfg = policy_config.get("signals", {}) if isinstance(policy_config, dict) else {}
    thresholds = gating_cfg.get("thresholds") if isinstance(gating_cfg, dict) else None
    gating_enabled = True
    hallucination_mode = "warn_only"
    if isinstance(gating_cfg, dict):
        gating_enabled = bool(gating_cfg.get("enabled", True))
        hallucination_mode = str(gating_cfg.get("hallucination_mode") or "warn_only")
    weights = signals_cfg.get("weights") if isinstance(signals_cfg, dict) else None
    enabled_signals = signals_cfg.get("enabled") if isinstance(signals_cfg, dict) else None
    if not isinstance(weights, dict):
        weights = None
    if not isinstance(enabled_signals, list):
        enabled_signals = None
    aggregate = aggregate_score(bundle, weights=weights, enabled_signals=enabled_signals)
    return gating_module._evaluate_policy_with_scores(
        aggregate=aggregate,
        signal_scores=bundle.signal_scores,
        derived_signals=bundle.derived_signals,
        thresholds=thresholds,
        gating_enabled=gating_enabled,
        hallucination_mode=hallucination_mode,
        hard_gate_reasons_enabled=None,
        signal_bundle=bundle,
    )


def _signal_scores(spec: ScenarioSpec, seed: int) -> SignalScores:
    severity = spec.severity
    degradation = spec.degradation_level
    rep = (
        0.15
        + severity * 0.55
        + degradation * 0.1
        + _jitter(seed, spec.turn_index, "rep") * 0.08
    )
    nov = (
        0.15
        + severity * 0.5
        + degradation * 0.1
        + _jitter(seed, spec.turn_index, "nov") * 0.08
    )
    coh = (
        0.2
        + severity * 0.6
        + degradation * 0.2
        + _jitter(seed, spec.turn_index, "coh") * 0.06
    )
    ctx = (
        0.12
        + severity * 0.5
        + degradation * 0.15
        + _jitter(seed, spec.turn_index, "ctx") * 0.06
    )
    hall = (
        0.2
        + max(spec.low_conf_level, severity) * 0.6
        + degradation * 0.1
        + _jitter(seed, spec.turn_index, "hall") * 0.05
    )
    return SignalScores(
        repetition_loopiness=_clamp(rep),
        novelty_entropy_proxy=_clamp(nov),
        coherence_structure=_clamp(coh),
        context_adherence=_clamp(ctx),
        hallucination_risk=_clamp(hall),
    )


def _derived_signals(spec: ScenarioSpec, seed: int) -> DerivedSignals:
    degradation = spec.degradation_level
    fatigue = _clamp(spec.fatigue_level + degradation * 0.1)
    fatigue_25 = _clamp(
        fatigue * 0.9 + _jitter(seed, spec.turn_index, "fatigue25") * 0.03
    )
    fatigue_50 = _clamp(
        fatigue * 1.0 + _jitter(seed, spec.turn_index, "fatigue50") * 0.03
    )
    low_conf = _clamp(spec.low_conf_level + degradation * 0.05)
    congestion = _clamp(spec.congestion_level + degradation * 0.05)
    return DerivedSignals(
        fatigue_risk_index=fatigue,
        fatigue_risk_25t=fatigue_25,
        fatigue_risk_50t=fatigue_50,
        low_conf_halluc=low_conf,
        congestion_signature=congestion,
    )


def _bundle_for_spec(spec: ScenarioSpec, seed: int) -> SignalBundle:
    scores = _signal_scores(spec, seed)
    derived = _derived_signals(spec, seed)
    if spec.miss_intent == "expected_warn_actual_allow":
        scores = SignalScores(
            repetition_loopiness=0.2,
            novelty_entropy_proxy=0.2,
            coherence_structure=0.2,
            context_adherence=0.2,
            hallucination_risk=0.2,
        )
        derived = DerivedSignals(
            fatigue_risk_index=0.15,
            fatigue_risk_25t=0.12,
            fatigue_risk_50t=0.15,
            low_conf_halluc=0.1,
            congestion_signature=0.1,
        )
    return SignalBundle(
        signal_schema_version=SIGNAL_SCHEMA_VERSION,
        signal_scores=scores,
        derived_signals=derived,
        missing_inputs=(),
    )


def _delete_run_rows(uri: str, schema: str, run_id: str) -> None:
    sqlite_path = _sqlite_path_from_uri(uri)
    if sqlite_path is not None:
        with sqlite3.connect(sqlite_path) as conn:
            conn.execute("DELETE FROM events WHERE session_id=?", (run_id,))
            conn.execute("DELETE FROM missed_signal_events WHERE session_id=?", (run_id,))
            conn.commit()
        return

    if create_engine is None or text is None:
        raise RuntimeError("SQLAlchemy required for non-sqlite deletes.")
    validate_identifier(schema, "schema")
    events_table = f"{schema}.events" if schema else "events"
    missed_table = (
        f"{schema}.missed_signal_events" if schema else "missed_signal_events"
    )
    engine = create_engine(uri)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(f"DELETE FROM {events_table} WHERE session_id=:sid"),
                {"sid": run_id},
            )
            conn.execute(
                text(f"DELETE FROM {missed_table} WHERE session_id=:sid"),
                {"sid": run_id},
            )
    finally:
        try:
            engine.dispose()
        except Exception:
            pass


def run_simulation(
    *,
    profile: str = DEFAULT_PROFILE,
    turns: int = DEFAULT_TURNS,
    seed: int = DEFAULT_SEED,
    output_dir: str = "sim_out",
    db_url: str | None = None,
    schema: str | None = None,
    policy_version: str = "dev-local",
    policy_registry_path: str | None = None,
    append_run: bool = False,
) -> SimResult:
    profile = str(profile or "").strip().lower()
    env_db = os.getenv("LIONLOCK_DB_URL", "").strip() or None
    db_target = _resolve_db_target(
        explicit_db=db_url,
        env_db=env_db,
        schema_override=schema,
    )
    resolved_db = db_target.uri
    resolved_schema = db_target.schema

    policy_version, policy_config, config_hash = _resolve_policy(
        policy_version,
        registry_path=policy_registry_path,
    )

    trust_logic_version = resolve_trust_logic_version(lionlock_config.load_config())
    fingerprint = code_fingerprint()

    base_run_id = _run_id_base(
        profile, turns, seed, policy_version, config_hash, fingerprint
    )
    run_id = _append_run_id(base_run_id) if append_run else base_run_id

    ok, message = sql_init.init_schema(resolved_db, schema=resolved_schema)
    if not ok:
        raise RuntimeError(message)
    if not append_run:
        _delete_run_rows(resolved_db, resolved_schema, run_id)

    specs = build_profile(profile, turns, seed)
    decision_counts = {"ALLOW": 0, "REFRESH": 0, "BLOCK": 0}
    missed_count = 0
    overtrigger_count = 0
    trigger_counts: Dict[str, int] = {}
    miss_reason_counts: Dict[str, int] = {}

    fatigue_high = False
    low_conf_high = False
    congestion_high = False
    expected_block = False
    threshold_high = 0.8

    labels: List[Dict[str, Any]] = []

    for spec in specs:
        bundle = _bundle_for_spec(spec, seed)
        decision = _evaluate_policy(bundle, policy_config)
        actual_decision = _decision_for_db(decision.gating_decision)
        expected_decision = _decision_for_db(spec.expected_decision)

        if bundle.derived_signals.fatigue_risk_index >= threshold_high:
            fatigue_high = True
        if bundle.derived_signals.low_conf_halluc >= threshold_high:
            low_conf_high = True
        if bundle.derived_signals.congestion_signature >= threshold_high:
            congestion_high = True
        if expected_decision == "BLOCK":
            expected_block = True

        decision_counts[actual_decision] = decision_counts.get(actual_decision, 0) + 1
        trigger_counts[decision.trigger_signal] = (
            trigger_counts.get(decision.trigger_signal, 0) + 1
        )

        response_hash = hashlib.sha256(
            f"{run_id}:{spec.turn_index}".encode("utf-8")
        ).hexdigest()
        timestamp = _timestamp_for_turn(spec.turn_index)

        event = {
            "session_id": run_id,
            "turn_index": spec.turn_index,
            "timestamp": timestamp,
            "signal_bundle": bundle,
            "gating_decision": actual_decision,
            "decision_risk_score": decision.decision_risk_score,
            "trigger_signal": decision.trigger_signal,
            "trust_logic_version": trust_logic_version,
            "policy_version": policy_version,
            "config_hash": config_hash,
            "code_fingerprint": fingerprint,
            "prompt_type": "unknown",
            "response_hash": response_hash,
            "replay_id": run_id,
            "severity": decision.severity,
        }
        ok, message = events_sql.record_gating_event(
            uri_or_dsn=resolved_db,
            event=event,
            schema=resolved_schema,
        )
        if not ok:
            raise RuntimeError(message)

        expected_canon = expected_decision
        actual_canon = actual_decision
        missed = False
        overtrigger = False
        miss_reason = None
        if expected_canon in ("REFRESH", "BLOCK") and (
            DECISION_ORDER[expected_canon] > DECISION_ORDER[actual_canon]
        ):
            missed = True
            if expected_canon == "REFRESH":
                miss_reason = "missed_warn_allow"
            elif actual_canon == "ALLOW":
                miss_reason = "missed_block_allow"
            else:
                miss_reason = "missed_block_warn"
        elif expected_canon == "ALLOW" and (
            DECISION_ORDER[actual_canon] > DECISION_ORDER["ALLOW"]
        ):
            overtrigger = True

        if missed:
            missed_count += 1
            miss_reason_counts[miss_reason] = miss_reason_counts.get(miss_reason, 0) + 1
            record = {
                "session_id": run_id,
                "turn_index": spec.turn_index,
                "timestamp": timestamp,
                "signal_bundle": bundle,
                "gating_decision": actual_decision,
                "decision_risk_score": decision.decision_risk_score,
                "trigger_signal": decision.trigger_signal,
                "trust_logic_version": trust_logic_version,
                "policy_version": policy_version,
                "config_hash": config_hash,
                "code_fingerprint": fingerprint,
                "prompt_type": "unknown",
                "response_hash": response_hash,
                "replay_id": run_id,
                "miss_reason": miss_reason,
                "expected_decision": expected_canon,
                "actual_decision": actual_canon,
            }
            ok, message = missed_signal_sql.record_missed_signal_event(
                uri_or_dsn=resolved_db,
                record=record,
                schema=resolved_schema,
            )
            if not ok:
                raise RuntimeError(message)
        if overtrigger:
            overtrigger_count += 1

        labels.append(
            {
                "session_id": run_id,
                "turn_index": spec.turn_index,
                "replay_id": run_id,
                "expected_decision": expected_canon,
                "run_id": run_id,
                "turn_id": spec.turn_index,
                "scenario_family": spec.scenario_family,
                "ground_truth_state": spec.ground_truth_state,
                "seed": seed,
                "profile": profile,
                "policy_version": policy_version,
                "config_hash": config_hash,
            }
        )

    missed_rate = missed_count / max(1, turns)
    if missed_rate <= 0.05:
        missed_status = "PASS"
    elif missed_rate <= 0.10:
        missed_status = "WARN"
    else:
        missed_status = "FAIL"

    overtrigger_rate = overtrigger_count / max(1, turns)
    if overtrigger_rate <= 0.20:
        overtrigger_status = "PASS"
    elif overtrigger_rate <= 0.35:
        overtrigger_status = "WARN"
    else:
        overtrigger_status = "FAIL"

    labels_path = str(Path(output_dir) / "labels.jsonl")
    labels_sha256 = labels_module.write_labels(labels_path, labels)

    report: Dict[str, Any] = {
        "run_id": run_id,
        "seed": seed,
        "profile": profile,
        "turns": turns,
        "policy_version": policy_version,
        "config_hash": config_hash,
        "code_fingerprint": fingerprint,
        "trust_logic_version": trust_logic_version,
        "decisions": decision_counts,
        "missed": {
            "count": missed_count,
            "rate": round(missed_rate, 6),
            "status": missed_status,
        },
        "overtrigger_rate": round(overtrigger_rate, 6),
        "overtrigger_status": overtrigger_status,
        "coverage": {
            "fatigue_high": fatigue_high,
            "low_conf_halluc": low_conf_high,
            "congestion_high": congestion_high,
            "expected_block": expected_block,
        },
        "labels_sha256": labels_sha256,
        "trigger_histogram": trigger_counts,
        "miss_reason_counts": miss_reason_counts,
        "logging": {
            "chosen_db_engine": db_target.engine,
            "db_source": db_target.db_source,
            "schema_in_use": db_target.schema,
            "offline_fallback_engaged": db_target.offline_fallback_engaged,
            "warnings": list(db_target.warnings),
        },
    }

    report["report_json_sha256"] = reporting.report_json_hash(report)
    output_paths = reporting.write_outputs(output_dir, report)
    output_paths["labels_jsonl"] = labels_path

    return SimResult(
        run_id=run_id,
        report=report,
        output_paths=output_paths,
        db_uri=resolved_db,
        labels_path=labels_path,
    )
