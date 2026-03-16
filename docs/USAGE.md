# Usage

## Local Development
- Create an environment outside the repo (see `docs/internal/VENV_REDIRECT_POLICY.yaml.md`):
  ```bash
  python -m venv ~/.lionlock_env && source ~/.lionlock_env/bin/activate
  ```
  Or use your preferred venv location (e.g., `$HOME/.venv` or `/tmp/lionlock_venv`):
- Install the package with dev tools: `pip install -e .[dev]`

## Logging
```python
from lionlock import TrustVaultLogger

logger = TrustVaultLogger("build/trustvault.log")
logger.record(event="detect", payload={"signal": "noop"})
logger.flush()
logger.close()
```

## Tests and Checks
- Run pytest (or `python -m unittest discover -s tests` if pytest is unavailable): `pytest -q`
- If you skip the editable install, run tests with `PYTHONPATH=src`.
- Byte-compile sources: `python -m compileall src`

## Docker
- Build the test image: `docker compose build`
- Run the suite in a container: `docker compose run --rm lionlock-test`

## Local CI Checks
- Run the full lint/type/test suite: `bash tools/ci_local.sh` (requires dev extras installed)

## Developer Setup (one-command helper)
- `bash tools/dev_setup.sh` uses `tools/venv_guard.sh` to enforce the external venv, installs dev extras, and runs pytest.

## Lockdown Workflow
- Run `./tools/lockdown.sh` to generate a SHA256 manifest and OpenTimestamps proof.
- Commit the generated manifest and `.ots` proof to track release integrity.

## Archived Assets
FastAPI, React, and docker-compose prototypes now live in `archive/experimental/`. They are not part of the supported OSS surface but remain available for reference.


## Audit logging
- Canonical tamper-evident audit stream: `TrustVaultLogger` (see `docs/AUDIT_LOGGING.md`).
- Verify chain integrity with `TrustVaultLogger.verify_chain()`.
- Public JSONL/SQL telemetry in `lionlock.logging.event_log` is non-canonical analytics output.
