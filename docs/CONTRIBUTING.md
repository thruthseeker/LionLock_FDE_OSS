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

## The Harness Contract Lock
`harness/contract.lock.json` records the hash of every protected file — the whole of `harness/`, the `Makefile`, `AGENTS.md`, `.python-version` and `.github/workflows/verify.yml`. The `contract` check in `make verify` compares them and fails if any byte moved, so a change that edits one of those files only passes once the lock is refreshed with `make lock`.

That made `make lock` a way around the contract: edit a protected file, refresh the lock, and both agree again. The `harness-lock` job on every pull request closes it. **If the lock differs from the base branch, the check fails.** It also covers `make baseline` and `make golden`, because the ratchet baselines and the spec goldens are themselves protected files, so refreshing either one forces a lock refresh too.

If you hit this check and did not mean to change the harness, restore the lock:

```bash
git checkout origin/main -- harness/contract.lock.json
```

If the harness change *is* intended, a maintainer applies the **`harness-change`** label to the pull request and the check re-runs by itself. Applying a label needs write access to the repository, so a contributor or an agent cannot approve its own harness change by pushing a commit. `make lock`, `make baseline` and `make golden` stay maintainer-only, and are never the way to make a failing check pass.
