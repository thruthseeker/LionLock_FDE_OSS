# Contributing

Please follow the [Code of Conduct](../CODE_OF_CONDUCT.md) and use the issue/PR templates in `.github/`.

## Setup
- Create a virtualenv (Python 3.10+) outside the repo (see `VENV_REDIRECT_POLICY.yaml.md`):
  `python -m venv /home/master/Desktop/lionlock_artifacts/publicrepo_LionLock_FDE/.venv && source /home/master/Desktop/lionlock_artifacts/publicrepo_LionLock_FDE/.venv/bin/activate`
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
