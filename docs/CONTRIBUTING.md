# Contributing

Please follow the [Code of Conduct](../CODE_OF_CONDUCT.md) and use the issue and pull request templates in [`.github/`](../.github/). Report security issues privately as described in [SECURITY.md](SECURITY.md), not in a public issue.

## Setup
- Create and activate a virtualenv (Python 3.10+):
  `python -m venv .venv && source .venv/bin/activate`
- Install dev dependencies (includes pytest): `pip install -e ".[dev]"`
- If you skip the editable install, run tests with `PYTHONPATH=src`.

## Trust Overlay Smoke Harness
Run from repo root:
- `python scripts/trust_overlay_smoke.py`

## Pre-commit Hooks
- Install hooks: `pre-commit install`
- Run hooks manually on all files: `pre-commit run --all-files`

## Checks to Run Before PRs
- `bash tools/ci_local.sh`
- `pytest -q`
- `bash tools/secret_scan.sh`
- `bash tools/security_audit.sh`
