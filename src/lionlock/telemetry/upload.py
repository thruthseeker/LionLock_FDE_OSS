"""Opt-in upload of sealed snapshots to a telemetry endpoint you control.

Nothing here runs unless you opt in. Uploads are refused unless ``telemetry_upload.enabled`` is
true (or ``LIONLOCK_TELEMETRY_UPLOAD=on``) and an endpoint is configured, and they are always
refused while ``DO_NOT_TRACK`` is set. The endpoint must use HTTPS (plain HTTP is allowed only
for localhost) and may not embed credentials. Redirects are never followed, so a bearer token
cannot be forwarded to another host. Immediately before sending, each outbox file is read once,
re-validated against the export policy, and rebuilt from its validated rows; only the rebuilt
bytes are sent, never the outbox file itself.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import random
import re
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping
from urllib.parse import urlsplit

from lionlock.versioning import get_lionlock_version

from . import policy
from .canonical import utc_now_iso
from .export import DEFAULT_ROWS_PER_SNAPSHOT, export_all, pending_snapshots
from .snapshot import SnapshotError, read_capped, rebuild_clean, validate_snapshot_bytes
from .store import open_store, resolve_sqlite_path

UPLOAD_PATH = "/v1/snapshots"
CONTENT_TYPE = "application/vnd.lionlock.snapshot+sqlite"
DEFAULT_TOKEN_ENV = "LIONLOCK_UPLOAD_TOKEN"
MAX_UPLOAD_BYTES = 16 * 1024 * 1024
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
DELIVERED_STATUSES = frozenset({"uploaded", "duplicate"})

_TRUE = {"1", "true", "t", "yes", "y", "on"}
_FALSE = {"0", "false", "f", "no", "n", "off"}
_TOKEN = re.compile(r"^[\x21-\x7e]{1,512}$")


class UploadDisabledError(RuntimeError):
    """Raised when an upload is attempted while uploads are not allowed."""


@dataclass(frozen=True)
class UploadSettings:
    endpoint: str
    outbox_dir: Path
    blocked_reason: str | None
    token: str | None = field(default=None, repr=False)
    ca_file: str | None = None
    timeout_s: float = 30.0
    interval_hours: float = 24.0
    rows_per_snapshot: int = DEFAULT_ROWS_PER_SNAPSHOT

    @property
    def allowed(self) -> bool:
        return self.blocked_reason is None

    @property
    def url(self) -> str:
        return self.endpoint.rstrip("/") + UPLOAD_PATH


@dataclass(frozen=True)
class UploadOutcome:
    """Result for one snapshot.

    ``status`` is one of: uploaded, duplicate, rejected, invalid, retry, auth_failed,
    misconfigured.
    """

    file: str
    status: str
    http_status: int | None = None
    detail: str = ""
    retry_after_s: float | None = None

    @property
    def delivered(self) -> bool:
        return self.status in DELIVERED_STATUSES

    def as_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "status": self.status,
            "http_status": self.http_status,
            "detail": self.detail,
        }


def _env_bool(name: str) -> bool | None:
    value = os.getenv(name, "").strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    return None


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def endpoint_problem(endpoint: str) -> str | None:
    """Why ``endpoint`` is unsafe to upload to, or None if it is acceptable."""
    try:
        parts = urlsplit(endpoint)
        host = (parts.hostname or "").lower()
        has_credentials = parts.username is not None or parts.password is not None
        _ = parts.port  # raises ValueError for a non-numeric or out-of-range port
    except ValueError:
        return "telemetry endpoint is not a valid URL"
    if has_credentials:
        return "telemetry endpoint must not embed credentials; use token_env or token_path"
    if parts.query or parts.fragment:
        return "telemetry endpoint must not include a query string or fragment"
    if not host:
        return "telemetry endpoint has no host"
    if parts.scheme == "https":
        return None
    if parts.scheme == "http" and host in LOOPBACK_HOSTS:
        return None
    return "telemetry endpoint must use https (plain http is allowed only for localhost)"


def _load_token(cfg: Mapping[str, Any]) -> str | None:
    env_name = str(cfg.get("token_env") or DEFAULT_TOKEN_ENV).strip() or DEFAULT_TOKEN_ENV
    token = os.getenv(env_name, "").strip()
    if token:
        return token
    token_path = str(cfg.get("token_path") or "").strip()
    if not token_path:
        return None
    try:
        lines = Path(token_path).expanduser().read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            return stripped
    return None


def resolve_upload_settings(config: Mapping[str, Any] | None) -> UploadSettings:
    raw = config.get("telemetry_upload", {}) if isinstance(config, Mapping) else {}
    cfg: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
    enabled = bool(cfg.get("enabled", False))
    toggle = _env_bool("LIONLOCK_TELEMETRY_UPLOAD")
    if toggle is not None:
        enabled = toggle
    endpoint = (
        os.getenv("LIONLOCK_TELEMETRY_ENDPOINT", "").strip()
        or str(cfg.get("endpoint") or "").strip()
    )
    outbox_raw = str(cfg.get("outbox_dir") or "").strip()
    outbox_dir = (
        Path(outbox_raw).expanduser()
        if outbox_raw
        else resolve_sqlite_path(config).parent / "outbox"
    )

    token: str | None = None
    blocked: str | None
    if _env_bool("DO_NOT_TRACK"):
        blocked = "DO_NOT_TRACK is set"
    elif not enabled:
        blocked = "uploads are opt-in and telemetry_upload.enabled is false"
    elif not endpoint:
        blocked = "telemetry_upload.endpoint is not set"
    else:
        blocked = endpoint_problem(endpoint)
        if blocked is None:
            token = _load_token(cfg)
            if token is not None and not _TOKEN.fullmatch(token):
                token = None
                blocked = "upload token contains characters that are not allowed"

    ca_file = str(cfg.get("ca_file") or "").strip() or None
    return UploadSettings(
        endpoint=endpoint,
        outbox_dir=outbox_dir,
        blocked_reason=blocked,
        token=token,
        ca_file=ca_file,
        timeout_s=max(1.0, _as_float(cfg.get("timeout_s"), 30.0)),
        interval_hours=max(0.0, _as_float(cfg.get("interval_hours"), 24.0)),
        rows_per_snapshot=max(1, _as_int(cfg.get("rows_per_snapshot"), DEFAULT_ROWS_PER_SNAPSHOT)),
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _send(request: urllib.request.Request, settings: UploadSettings) -> Any:
    context = ssl.create_default_context(cafile=settings.ca_file)
    handlers: List[urllib.request.BaseHandler] = [
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=context),
    ]
    if (urlsplit(request.full_url).hostname or "").lower() in LOOPBACK_HOSTS:
        # Plain http is allowed only for loopback; never relay it (or its token) via a proxy.
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)
    return opener.open(request, timeout=settings.timeout_s)


def _retry_after(value: str | None) -> float | None:
    if value and value.strip().isdigit():
        return float(value.strip())
    return None


def _classify(name: str, status: int, retry_after: float | None = None) -> UploadOutcome:
    if status == 200:
        return UploadOutcome(name, "duplicate", status, "endpoint already had this snapshot")
    if 200 <= status < 300:
        return UploadOutcome(name, "uploaded", status, "accepted")
    if status in (401, 403):
        return UploadOutcome(name, "auth_failed", status, "endpoint refused the credentials")
    if status in (408, 425, 429) or status >= 500:
        return UploadOutcome(name, "retry", status, "endpoint asked to retry later", retry_after)
    if status in (400, 409, 413, 415, 422):
        return UploadOutcome(name, "rejected", status, "endpoint rejected this snapshot")
    return UploadOutcome(name, "misconfigured", status, "unexpected response; check the endpoint")


def upload_snapshot(path: Path, settings: UploadSettings) -> UploadOutcome:
    """Send one sealed snapshot. Raises ``UploadDisabledError`` if uploads are not allowed.

    The request body is the gzip of a file rebuilt from the snapshot's validated rows.
    ``X-LionLock-File-SHA256`` and ``Idempotency-Key`` are the SHA-256 of that rebuilt,
    uncompressed file (the receiver recomputes it after decompressing), never of the gzip bytes.
    ``path`` is read once and never modified.
    """
    if not settings.allowed:
        raise UploadDisabledError(settings.blocked_reason or "uploads are disabled")
    try:
        info = validate_snapshot_bytes(read_capped(path))
        payload = rebuild_clean(info)
    except SnapshotError as exc:
        return UploadOutcome(path.name, "invalid", None, str(exc))
    body = gzip.compress(payload, mtime=0)
    if len(body) > MAX_UPLOAD_BYTES:
        return UploadOutcome(path.name, "invalid", None, "snapshot is too large to upload")
    payload_sha = hashlib.sha256(payload).hexdigest()

    headers = {
        "Content-Type": CONTENT_TYPE,
        "Content-Encoding": "gzip",
        "User-Agent": f"lionlock/{policy.package_version_label(get_lionlock_version({}))}",
        "Idempotency-Key": payload_sha,
        "X-LionLock-File-SHA256": payload_sha,
        "X-LionLock-Content-Digest": info.content_digest,
        "X-LionLock-Install-Id": info.install_id,
        "X-LionLock-Segment": str(info.segment_index),
    }
    if settings.token:
        headers["Authorization"] = f"Bearer {settings.token}"
    request = urllib.request.Request(settings.url, data=body, headers=headers, method="POST")
    try:
        with _send(request, settings) as response:
            status = int(response.status)
            response.read(65536)
    except urllib.error.HTTPError as exc:
        retry_after = _retry_after(exc.headers.get("Retry-After") if exc.headers else None)
        exc.close()
        return _classify(path.name, int(exc.code), retry_after)
    except (urllib.error.URLError, OSError) as exc:
        return UploadOutcome(path.name, "retry", None, f"network error ({type(exc).__name__})")
    return _classify(path.name, status)


def _set_aside(path: Path, outcome: UploadOutcome, directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    os.replace(path, directory / path.name)
    reason = f"{outcome.status} {outcome.http_status or ''} {outcome.detail}".strip()
    (directory / f"{path.name}.reason.txt").write_text(reason + "\n", encoding="utf-8")


def upload_pending(
    settings: UploadSettings,
    *,
    max_attempts: int = 3,
    sleep: Callable[[float], None] = time.sleep,
) -> List[UploadOutcome]:
    """Drain the outbox oldest-first; stop at the first snapshot that cannot be delivered yet.

    Delivered snapshots are deleted. Snapshots the endpoint (or the local policy check)
    rejects are moved to ``<outbox>/rejected`` and never retried.
    """
    if not settings.allowed:
        raise UploadDisabledError(settings.blocked_reason or "uploads are disabled")
    outcomes: List[UploadOutcome] = []
    for path in pending_snapshots(settings.outbox_dir):
        outcome = upload_snapshot(path, settings)
        for attempt in range(1, max(1, max_attempts)):
            if outcome.status != "retry":
                break
            delay = outcome.retry_after_s if outcome.retry_after_s is not None else 2.0**attempt
            sleep(min(60.0, delay) * random.uniform(0.8, 1.2))
            outcome = upload_snapshot(path, settings)
        outcomes.append(outcome)
        if outcome.delivered:
            path.unlink(missing_ok=True)
        elif outcome.status in {"rejected", "invalid"}:
            _set_aside(path, outcome, settings.outbox_dir / "rejected")
        else:
            break
    return outcomes


def export_and_upload(
    config: Mapping[str, Any] | None,
    *,
    max_attempts: int = 3,
    sleep: Callable[[float], None] = time.sleep,
) -> Dict[str, Any]:
    """Seal everything new into the outbox, then upload it. Requires uploads to be enabled."""
    settings = resolve_upload_settings(config)
    if not settings.allowed:
        raise UploadDisabledError(settings.blocked_reason or "uploads are disabled")
    exported = export_all(
        open_store(config), settings.outbox_dir, rows_per_snapshot=settings.rows_per_snapshot
    )
    outcomes = upload_pending(settings, max_attempts=max_attempts, sleep=sleep)
    return {
        "exported": [result.as_dict() for result in exported],
        "uploads": [outcome.as_dict() for outcome in outcomes],
        "pending": len(pending_snapshots(settings.outbox_dir)),
        "more_pending": exported.more_pending,
    }


def maybe_export_and_upload(config: Mapping[str, Any] | None) -> Dict[str, Any]:
    """Export and upload at most once per ``interval_hours``. Never raises.

    Safe to call on every application start: it returns immediately when uploads are off.
    """
    try:
        settings = resolve_upload_settings(config)
        if not settings.allowed:
            return {"status": "disabled", "reason": settings.blocked_reason}
        store = open_store(config)
        last_run = store.get_meta("upload:last_run_utc").get("upload:last_run_utc")
        now = datetime.now(timezone.utc)
        if last_run and settings.interval_hours > 0:
            previous = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
            if now - previous < timedelta(hours=settings.interval_hours):
                return {"status": "skipped", "reason": "upload interval has not elapsed"}
        # Record the attempt first so a failing endpoint is not retried on every start.
        store.set_meta({"upload:last_run_utc": utc_now_iso()})
        summary = export_and_upload(config, max_attempts=1)
        return {"status": "ok", **summary}
    except Exception as exc:  # noqa: BLE001 - telemetry must never break the host application
        return {"status": "error", "reason": type(exc).__name__}
