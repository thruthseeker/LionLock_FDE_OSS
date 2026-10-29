policy:
  purpose: >
    Enforce deterministic virtual environment usage for all local execution,
    Codex agents, and dev tooling in the LionLock FDE workspace. Ensures
    consistent builds and prevents repo pollution by keeping runtime state in one
    known environment: a git-ignored `<repo>/.venv` by default, or the path in
    `LIONLOCK_VENV_PATH` to keep it outside the project tree.

  environment_path: "${LIONLOCK_VENV_PATH:-<repo>/.venv}"

  forbidden_paths:
    - Any `.venv` directory other than the configured environment path

  enforcement:
    - All CLI tooling (e.g., `pip`, `python`, `pytest`) must activate this `.venv`
    - VS Code must resolve interpreter to `.venv/bin/python` in the specified path
    - Codex agents must activate this environment before executing any prompt or script
    - No fallback to global Python or system `site-packages` is permitted

  fallback_behavior: >
    Codex agents and tooling must halt or prompt correction if the active Python
    interpreter does not match the required `.venv`. Silent fallback to global
    Python is explicitly prohibited.

  acceptance_criteria:
    - `$VIRTUAL_ENV` must match the locked environment path
    - `which python` must resolve to `.venv/bin/python` under the correct folder
    - `sys.executable` inside Python must report the exact expected path
    - Codex must reject or flag incorrect interpreter state on activation

  bootstrap:
    auto_create_if_missing: true
    use_requirements_file: "requirements.txt"
    target_path: "${LIONLOCK_VENV_PATH:-<repo>/.venv}"

  environment_proof:
    hash_executable: true
    log_virtual_env_path: true

  codex_context_tags:
    - env: ".venv"
    - env_path: "${LIONLOCK_VENV_PATH:-<repo>/.venv}"
    - env_source: "repo-local by default; external when LIONLOCK_VENV_PATH is set"
    - workspace_integrity: "locked"

  justification: >
    The default `.venv` lives in the repository root and is git-ignored, so a
    fresh clone works with no extra setup. Set `LIONLOCK_VENV_PATH` to keep the
    environment (~500-800MB) outside the project tree instead. This structure:
    - Keeps commits lightweight and portable (the environment is never tracked)
    - Prevents accidental commit of heavy runtime files
    - Isolates interpreter state for multi-env builds
    - Enhances Codex and VS Code agent clarity
    - Supports future modular deployment where multiple modules can reuse a shared `.venv`

    This policy aligns with LionLock's architectural discipline: code-only repos,
    deterministic environments, and maximum clarity for reproducibility.
