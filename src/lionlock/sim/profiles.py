from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass
from typing import Iterable, List


PROFILE_STANDARD = "standard"

_PHASES = (
    ("baseline_control", 20),
    ("fatigue_drift_ramp", 25),
    ("borderline_ambiguity_cluster", 15),
    ("hallucination_spike_injections", 15),
    ("congestion_overload", 15),
    ("recovery", 10),
)


@dataclass(frozen=True)
class PhaseRange:
    name: str
    start: int
    end: int

    @property
    def length(self) -> int:
        return max(0, self.end - self.start + 1)


@dataclass(frozen=True)
class ScenarioSpec:
    turn_index: int
    phase: str
    scenario_family: str
    severity: float
    ground_truth_state: str
    expected_decision: str
    hallucination_spike: bool
    degradation_level: float
    fatigue_level: float
    congestion_level: float
    low_conf_level: float
    miss_intent: str | None = None


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _noise(seed: int, turn_index: int, tag: str) -> float:
    payload = f"{seed}:{turn_index}:{tag}".encode("utf-8")
    digest = hashlib.sha256(payload).digest()
    return int.from_bytes(digest[:4], "big") / 2**32


def _jitter(seed: int, turn_index: int, tag: str) -> float:
    return _noise(seed, turn_index, tag) - 0.5


def _scaled_phase_lengths(turns: int) -> List[int]:
    if turns <= 0:
        return [0 for _ in _PHASES]
    total = sum(length for _, length in _PHASES)
    raw = [turns * length / total for _, length in _PHASES]
    floors = [int(math.floor(value)) for value in raw]
    remainder = turns - sum(floors)
    fractional = [(idx, raw[idx] - floors[idx]) for idx in range(len(raw))]
    fractional.sort(key=lambda item: (-item[1], item[0]))
    for idx, _ in fractional[:remainder]:
        floors[idx] += 1
    return floors


def _phase_ranges(turns: int) -> List[PhaseRange]:
    lengths = _scaled_phase_lengths(turns)
    ranges: List[PhaseRange] = []
    cursor = 1
    for (name, _), length in zip(_PHASES, lengths):
        if length <= 0:
            continue
        start = cursor
        end = cursor + length - 1
        ranges.append(PhaseRange(name=name, start=start, end=end))
        cursor = end + 1
    return ranges


def _phase_for_turn(turn_index: int, ranges: Iterable[PhaseRange]) -> PhaseRange | None:
    for phase in ranges:
        if phase.start <= turn_index <= phase.end:
            return phase
    return None


def _degradation_level(turn_index: int, turns: int) -> float:
    if turns <= 1:
        return 0.0
    ramp_end = max(1, int(round(turns * 0.85)))
    max_level = 0.25
    recovery_drop = 0.05
    if turn_index <= ramp_end:
        progress = (turn_index - 1) / max(1, ramp_end - 1)
        return _clamp(progress * max_level)
    progress = (turn_index - ramp_end) / max(1, turns - ramp_end)
    return _clamp(max_level - recovery_drop * progress)


def _ground_truth_state(severity: float) -> str:
    if severity < 0.4:
        return "SAFE"
    if severity < 0.7:
        return "BORDERLINE"
    return "UNSAFE"


def _expected_decision(state: str) -> str:
    return {"SAFE": "ALLOW", "BORDERLINE": "REFRESH", "UNSAFE": "BLOCK"}.get(state, "ALLOW")


def build_profile(profile: str, turns: int, seed: int) -> List[ScenarioSpec]:
    profile_key = str(profile or "").strip().lower()
    if profile_key != PROFILE_STANDARD:
        raise ValueError(f"unknown profile: {profile}")
    if turns <= 0:
        raise ValueError("turns must be positive")

    ranges = _phase_ranges(turns)
    baseline = next((item for item in ranges if item.name == "baseline_control"), None)
    borderline = next(
        (item for item in ranges if item.name == "borderline_ambiguity_cluster"),
        None,
    )
    hallucination = next(
        (item for item in ranges if item.name == "hallucination_spike_injections"),
        None,
    )

    mild_turns: set[int] = set()
    if baseline and baseline.length >= 6:
        mild_turns.update(
            {
                baseline.start + baseline.length // 3,
                baseline.start + (2 * baseline.length) // 3,
            }
        )
    elif baseline and baseline.length >= 3:
        mild_turns.add(baseline.start + baseline.length // 2)

    miss_turn = None
    if borderline and borderline.length > 0:
        miss_turn = borderline.start + borderline.length // 2

    spike_turns: set[int] = set()
    if hallucination:
        for offset in range(hallucination.length):
            if offset % 3 == 0:
                spike_turns.add(hallucination.start + offset)

    specs: List[ScenarioSpec] = []
    for turn_index in range(1, turns + 1):
        phase = _phase_for_turn(turn_index, ranges)
        if phase is None:
            continue

        jitter = _jitter(seed, turn_index, phase.name)
        hallucination_spike = turn_index in spike_turns
        degradation = _degradation_level(turn_index, turns)

        severity = 0.2
        fatigue = 0.2
        congestion = 0.1
        low_conf = 0.1

        if phase.name == "baseline_control":
            severity = 0.2 + jitter * 0.05
            fatigue = 0.2 + jitter * 0.05
            low_conf = 0.1 + jitter * 0.05
            congestion = 0.1 + jitter * 0.05
            if turn_index in mild_turns:
                severity = 0.48 + jitter * 0.03
                fatigue = 0.5 + jitter * 0.05
        elif phase.name == "fatigue_drift_ramp":
            progress = (turn_index - phase.start) / max(1, phase.length - 1)
            severity = 0.32 + 0.4 * progress + jitter * 0.03
            fatigue = 0.35 + 0.5 * progress + jitter * 0.05
            low_conf = 0.15 + 0.2 * progress + jitter * 0.05
            congestion = 0.1 + jitter * 0.05
        elif phase.name == "borderline_ambiguity_cluster":
            severity = 0.52 + jitter * 0.08
            fatigue = 0.55 + jitter * 0.05
            low_conf = 0.45 + jitter * 0.05
            congestion = 0.2 + jitter * 0.05
        elif phase.name == "hallucination_spike_injections":
            if hallucination_spike:
                severity = 0.84 + jitter * 0.12
                low_conf = 0.88 + jitter * 0.06
            else:
                severity = 0.6 + jitter * 0.06
                low_conf = 0.55 + jitter * 0.05
            fatigue = 0.5 + jitter * 0.05
            congestion = 0.25 + jitter * 0.05
        elif phase.name == "congestion_overload":
            severity = 0.65 + jitter * 0.12
            fatigue = 0.6 + jitter * 0.05
            low_conf = 0.35 + jitter * 0.05
            congestion = 0.8 + jitter * 0.08
        elif phase.name == "recovery":
            progress = (turn_index - phase.start) / max(1, phase.length - 1)
            severity = 0.55 - 0.15 * progress + jitter * 0.05
            fatigue = 0.6 - 0.25 * progress + jitter * 0.05
            low_conf = 0.3 - 0.15 * progress + jitter * 0.05
            congestion = 0.4 - 0.25 * progress + jitter * 0.05

        severity = _clamp(severity)
        fatigue = _clamp(fatigue)
        congestion = _clamp(congestion)
        low_conf = _clamp(low_conf)

        state = _ground_truth_state(severity)
        expected = _expected_decision(state)
        if hallucination_spike and severity >= 0.7:
            expected = "BLOCK"
            state = "UNSAFE"

        miss_intent = None
        if miss_turn == turn_index:
            miss_intent = "expected_warn_actual_allow"

        specs.append(
            ScenarioSpec(
                turn_index=turn_index,
                phase=phase.name,
                scenario_family=phase.name,
                severity=severity,
                ground_truth_state=state,
                expected_decision=expected,
                hallucination_spike=hallucination_spike,
                degradation_level=degradation,
                fatigue_level=fatigue,
                congestion_level=congestion,
                low_conf_level=low_conf,
                miss_intent=miss_intent,
            )
        )

    return specs
