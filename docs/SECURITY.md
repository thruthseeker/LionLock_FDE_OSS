# Security Policy

## Reporting Vulnerabilities
- Email: security@lionlock.example
- Include affected component, version (commit hash), and reproduction steps.
- Expect first response within 72 hours; coordinated disclosure is appreciated.

## Supported Versions
This public release is intended for security hardening; breaking changes may occur. Pin to a commit hash for production deployments.

## Hardening Guidance
- Write logs to a directory with restrictive permissions; avoid world-writable paths.
- Rotate or archive trustvault logs regularly to keep auditing manageable.
- Verify SHA256 fields before consuming events downstream.
- Keep `tools/lockdown.sh` outputs under version control for tamper detection.
- Archive unmaintained prototypes under `archive/experimental/` to keep the public surface small.

## Privacy Trade-offs (OSS)
- Key-based scrubbing blocks known prompt/response field names.
- Value-based scanning rejects obvious markers (e.g., `prompt:` / `response=`) and large free-text strings.
- These checks are heuristic: they can miss short/unlabeled text and can reject long descriptive values.
- Avoid passing raw prompt/response text; hash, summarize, or redact upstream before logging.
- Canonical SQL writers for Module 05 events and missed-signal events enforce value scanning; other logs may only apply key-based scrubs.

## Security Checks
- Secret scanning: `bash tools/secret_scan.sh`
- Dependency audit: `bash tools/security_audit.sh` (requires `pip-audit` via `pip install -e '.[dev]'`)
- Policy: fix vulnerabilities when found; if a specific issue must be temporarily allowed, document it with rationale and date in an allowlist before suppressing.
- No secrets in the repository: rotate any leaked material immediately if detected.
