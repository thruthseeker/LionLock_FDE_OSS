# AGENTS.md — how to work in this repository

This file is the single source of truth for every agent: Claude, ChatGPT/Codex, Gemini/Antigravity
or a human. There is one gate, `make verify`, and it behaves identically for all of you.

The harness guarantees **the same end product**, not the same code. Your implementation may differ
from another agent's in naming, structure and wording. Its observable output may not: `make verify
SPEC=<ID>` prints a fingerprint, and yours must equal the one in the spec's `golden.json`.

## Setup

```bash
make setup      # creates .venv from a hash-locked requirements file
```

Python is pinned by `.python-version`. The library is used from the source tree via `PYTHONPATH=src`;
nothing is built or installed. `make verify` refuses to run if your Python minor version or any
pinned tool version disagrees with the lock.

## Working a job

1. Read `harness/specs/<ID>/SPEC.md`. The TOML front matter names `allowed_paths` — the only files
   you may change.
2. Run `make verify SPEC=<ID>`. For an unimplemented job it fails; that is the starting point.
3. Implement. Change **only** files inside `allowed_paths`.
4. Re-run `make verify SPEC=<ID>` until it prints `RESULT: PASS`.
5. Commit, push to the branch you were given, and report using the template at the end of the spec.
   Include the fingerprint.

If the spec is wrong, ambiguous, or impossible — **stop and report it.** Do not reinterpret it, and
do not adjust the spec, the golden or the tests to make your implementation pass. A spec that cannot
be met is useful information; a spec quietly bent to fit is not.

## What `make verify` checks

| Check | Fails when |
| --- | --- |
| `env` | Python or a pinned tool version disagrees with the lock |
| `contract` | a protected file was edited |
| `ratchet:ruff` / `ratchet:format` / `ratchet:mypy` | you added a **new** lint or type finding |
| `tests` | the default pytest suite fails |
| `acceptance:<ID>` | a spec's requirement tests fail (blocking for the selected spec and for `done` specs) |
| `determinism:<ID>` | the product differs between two runs, or from `golden.json` |
| `scope:<ID>` | a changed file lies outside `allowed_paths` |
| `privacy` | an added line contains a home path, email, private IP or credential |

The ratchet compares against `harness/baseline/*.json` as a multiset of (file, code, message). This
repository carries pre-existing lint and type findings; you are not asked to fix them, and you must
not add to them. Do not "clean up" unrelated files — that shows up as scope violations and makes
review harder.

The full report is written to `harness/out/verify_report.json`.

## Files you must never edit

`AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `Makefile`, `.python-version`,
`.github/workflows/verify.yml`, `.devcontainer/devcontainer.json`, and everything under `harness/`
— including every spec, corpus, oracle, product and golden file. The `contract` check hashes all of
them and fails if any byte changes.

`make golden`, `make baseline` and `make lock` are **maintainer-only**. Never run them to make a
failing check pass. If you believe a golden or baseline is genuinely wrong, say so in your report and
stop.

## Repository rules

These hold regardless of what a spec says, and a spec never overrides them.

- **This repository is public.** Never commit data, per-request rows, prompts, responses, token or
  request ids, hashes derived from data, personal paths, hostnames, model paths, emails or keys.
  Code, tests, docs and text-free aggregate constants only.
- **The runtime is deterministic.** No machine learning, no network access and no randomness in
  scoring or gating. Offline analysis tools may use other libraries; the runtime may not.
- **Private data stays out.** Specs here are public. Work that reads private data belongs in a
  private repository, and nothing derived from it (rows, hashes, file or run names) comes back here.
- **Calibration constants need evidence.** Do not change a threshold, weight or sigmoid constant
  because it makes a test pass. Bring numbers, and say what data they came from.
- **Report what happened.** If a check fails, say so and include the output. If you skipped
  something, say that too.

## In CI

Every pull request runs the same gate. CI cannot be told which job you are working, so it works it
out: any open spec whose `allowed_paths` your change touches is treated as your job, and its
acceptance and scope checks block exactly as `make verify SPEC=<ID>` would. Run
`make verify CHANGED_SINCE=origin/main` to see the same result locally. Changes that touch no
spec's files are held to every other check.

Checks run with a fixed environment: only `PATH`, `HOME`, temp-directory and virtualenv variables
pass through, so settings in your shell (for example `LIONLOCK_GATING_ENABLED` or
`PYTEST_ADDOPTS`) cannot change a result.
