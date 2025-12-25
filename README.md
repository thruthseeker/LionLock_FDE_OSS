# LionLock

LLM reliability logging and fatigue-signal utilities (OSS core). LionLock gives developers a lightweight, auditable way to log and assess LLM output reliability/fatigue signals so they can build safer, more trustworthy AI systems.

**Status:** Alpha (stable minimal API; not a full LLM gateway).

## Trust Overlay (OSS v1)
Trust Overlay is passive and read-only: it does **not** enforce policy, gate outputs, or disable models.
Raw prompt/response logging is **never enabled by default**; see `docs/trust_overlay.md` for details.

## What This Package Provides
- Append-only `TrustVaultLogger` with SHA256 stamping and UTC timestamps
- Deterministic, structured TrustVault-style JSONL events for audits
- Source layout under `src/` with tests, examples, and CI
- Security tooling for secret scanning and dependency auditing

## Supported Platforms
- Python 3.10+ on Linux, macOS, Windows; Docker for tests/demo
- CPU-only; cloud-agnostic (runs anywhere Python runs)

## Quickstart (contributors)
```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
python examples/basic_logger.py
```
Expected: prints the log path and writes a JSONL file with fields `ts`, `event`, `payload`, `sha256`.

Run tests:
```bash
pytest -q
```

## Killer Use Case (try first)
Run the basic logger to produce a TrustVault-style event log on disk:
```bash
python examples/basic_logger.py
cat build/examples/trustvault.log
```
You should see one JSON line with a timestamped event and matching SHA256.

## Install (package)
- Editable/dev install (recommended): `python -m venv .venv && source .venv/bin/activate && pip install -e '.[dev]'`
- GUI extras: `python -m pip install -e '.[dev,gui]'`
- Standard install: `pip install .`

## Configuration
Config is optional. Defaults:
- Log path defaults to the value you pass the logger (e.g., `build/examples/trustvault.log`)
- Verbosity: set `LIONLOCK_LOG_LEVEL=DEBUG` for noisy runs (assumes standard Python logging)

Safe sample (optional) for `configs/config.example.yaml`:
```yaml
trustvault:
  path: ./logs/trustvault.jsonl
logging:
  level: INFO
```

## Local GUI
- Install extras: `python -m pip install -e '.[dev,gui]'`
- Run: `./tools/run_gui.sh`
- Docs: `docs/GUI.md` and `apps/streamlit_gui/README.md`
- Telemetry queries (signals-only): `docs/telemetry_queries.md`

## Non-goals (v0.1)
- Not a full LLM proxy/gateway
- Not a hallucination detector or “truth machine”
- Not an enterprise deployment suite

## Docker
- Build: `docker compose build`
- Run tests in container: `docker compose run --rm lionlock-test`

## Project Structure
- `src/lionlock/` — package code
- `tests/` — test coverage for the logger
- `examples/` — runnable snippets
- `apps/streamlit_gui/` — Streamlit harness for local TrustVault testing
- `tools/` — scripts for CI/local checks, security scans, and lockdown
- `docs/` — usage, roadmap, and security notes
- `configs/` — configuration stubs/placeholders
- `archive/experimental/` — historical/experimental assets (not supported)

## Contributing
Use `bash tools/ci_local.sh` before opening a PR. Keep the public surface minimal and auditable.
- Enable pre-commit hooks for lint/format: `pre-commit install` (requires dev extras).
- Governance: BDFL-maintained; “best effort” response times in early alpha.
- See `docs/CONTRIBUTING.md` for details.

## Security
See `docs/SECURITY.md` for reporting guidance and security tooling. Avoid world-writable log directories; verify `sha256` before consuming events.

## Releases and Changelog
- Release process: see `RELEASE.md`
- Changelog: see `CHANGELOG.md`

## API Surface
- Public exports: `from lionlock import TrustVaultLogger` (see `docs/API.md`)

## License
Apache License 2.0
