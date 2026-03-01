"""Validation models for inbound Module 02 signal payloads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

try:  # Prefer Pydantic v2 when available.
    from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt, StrictStr, ValidationError

    class SignalMetadata(BaseModel):
        """Optional metadata used for derived signal calculations."""

        model_config = ConfigDict(extra="forbid", strict=True)

        entropy_decay: StrictFloat | StrictInt | None = Field(default=None)
        drift_slope: StrictFloat | StrictInt | None = Field(default=None)
        turn_index: StrictInt | None = Field(default=None, ge=0)
        duration_ms: StrictFloat | StrictInt | None = Field(default=None, ge=0)
        latency_window_stats: list[StrictFloat | StrictInt] | None = Field(default=None)

    class SignalPayload(BaseModel):
        """Strict boundary payload for scoring."""

        model_config = ConfigDict(extra="forbid", strict=True)

        prompt: StrictStr = Field(min_length=1)
        response: StrictStr = Field(min_length=1)
        metadata: SignalMetadata | None = None

except ModuleNotFoundError:

    class ValidationError(ValueError):
        """Lightweight fallback validation error compatible with pydantic usage."""

        def __init__(self, errors: list[dict[str, Any]]) -> None:
            super().__init__("Validation failed")
            self._errors = errors

        def errors(self) -> list[dict[str, Any]]:
            return self._errors

    @dataclass(frozen=True)
    class SignalMetadata:
        """Fallback strict metadata model when pydantic is unavailable."""

        entropy_decay: float | int | None = None
        drift_slope: float | int | None = None
        turn_index: int | None = None
        duration_ms: float | int | None = None
        latency_window_stats: list[float | int] | None = None

        def model_dump(self, *, exclude_none: bool = False) -> dict[str, Any]:
            payload = {
                "entropy_decay": self.entropy_decay,
                "drift_slope": self.drift_slope,
                "turn_index": self.turn_index,
                "duration_ms": self.duration_ms,
                "latency_window_stats": self.latency_window_stats,
            }
            if exclude_none:
                return {k: v for k, v in payload.items() if v is not None}
            return payload

    @dataclass(frozen=True)
    class SignalPayload:
        """Fallback strict payload model when pydantic is unavailable."""

        prompt: str
        response: str
        metadata: SignalMetadata | None = None

        @classmethod
        def model_validate(cls, payload: dict[str, Any]) -> "SignalPayload":
            errors: list[dict[str, Any]] = []
            if not isinstance(payload, dict):
                raise ValidationError([{"loc": ("payload",), "msg": "must be a dictionary"}])

            prompt = payload.get("prompt")
            response = payload.get("response")
            metadata_raw = payload.get("metadata")

            if not isinstance(prompt, str) or not prompt:
                errors.append({"loc": ("prompt",), "msg": "must be a non-empty string"})
            if not isinstance(response, str) or not response:
                errors.append({"loc": ("response",), "msg": "must be a non-empty string"})

            allowed = {"entropy_decay", "drift_slope", "turn_index", "duration_ms", "latency_window_stats"}
            metadata = None
            if metadata_raw is not None:
                if not isinstance(metadata_raw, dict):
                    errors.append({"loc": ("metadata",), "msg": "must be a dictionary"})
                else:
                    unknown = set(metadata_raw) - allowed
                    if unknown:
                        errors.append({"loc": ("metadata",), "msg": f"unexpected keys: {sorted(unknown)}"})
                    for key in ("entropy_decay", "drift_slope"):
                        value = metadata_raw.get(key)
                        if value is None:
                            continue
                        if not isinstance(value, (int, float)) or isinstance(value, bool):
                            errors.append({"loc": ("metadata", key), "msg": "must be numeric"})
                    turn_index = metadata_raw.get("turn_index")
                    if turn_index is not None and (
                        not isinstance(turn_index, int) or isinstance(turn_index, bool) or turn_index < 0
                    ):
                        errors.append({"loc": ("metadata", "turn_index"), "msg": "must be int >= 0"})
                    duration_ms = metadata_raw.get("duration_ms")
                    if duration_ms is not None and (
                        not isinstance(duration_ms, (int, float))
                        or isinstance(duration_ms, bool)
                        or float(duration_ms) < 0
                    ):
                        errors.append({"loc": ("metadata", "duration_ms"), "msg": "must be numeric >= 0"})
                    latency = metadata_raw.get("latency_window_stats")
                    if latency is not None:
                        if not isinstance(latency, list):
                            errors.append({"loc": ("metadata", "latency_window_stats"), "msg": "must be list"})
                        else:
                            for idx, item in enumerate(latency):
                                if (
                                    not isinstance(item, (int, float))
                                    or isinstance(item, bool)
                                    or float(item) < 0
                                ):
                                    errors.append({"loc": ("metadata", "latency_window_stats", idx), "msg": "must be numeric >= 0"})
                    if not errors:
                        metadata = SignalMetadata(**{k: metadata_raw.get(k) for k in allowed})

            if errors:
                raise ValidationError(errors)
            return cls(prompt=prompt, response=response, metadata=metadata)
