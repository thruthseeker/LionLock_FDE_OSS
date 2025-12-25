"""Event logging utilities for LionLock."""

from .event_log import (
    append_event,
    build_connector_error_event,
    build_signal_event,
    config_hash_from,
    log_event,
)
from .failsafe import failsafe_status, record_failsafe_event

__all__ = [
    "append_event",
    "build_connector_error_event",
    "build_signal_event",
    "config_hash_from",
    "failsafe_status",
    "log_event",
    "record_failsafe_event",
]
