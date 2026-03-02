policy:
  purpose: >
    Enforce deterministic virtual environment usage for all local execution,
    Codex agents, and dev tooling in the LionLock FDE workspace. Ensures
    consistent builds, prevents repo pollution, and maintains weight discipline
    by isolating runtime state outside the project tree.

  environment_path: "/home/master/Desktop/lionlock_artifacts/publicrepo_LionLock_FDE/.venv"

  forbidden_paths:
    - "/home/master/Desktop/publicrepo_LionLock_FDE/.venv"   # workspace venv (disallowed to avoid repo bloat)
    - "/home/master/desktop/lionlock_assets/publicrepo_lionlock_FDE/.venv"   # legacy policy path (explicitly disallowed now)
    - Any `.venv` directory outside `/home/master/Desktop/lionlock_artifacts/publicrepo_LionLock_FDE/.venv`

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
    target_path: "/home/master/Desktop/lionlock_artifacts/publicrepo_LionLock_FDE/.venv"

  environment_proof:
    hash_executable: true
    log_virtual_env_path: true

  codex_context_tags:
    - env: ".venv"
    - env_path: "/home/master/Desktop/lionlock_artifacts/publicrepo_LionLock_FDE/.venv"
    - env_source: "external"
    - workspace_integrity: "locked"

  justification: >
    The `.venv` folder is deliberately placed outside the project tree to avoid
    bloating the working directory. At ~500-800MB, `.venv` is too large to be
    co-located with code. This structure:
    - Keeps the repo lightweight and portable
    - Prevents accidental commit of heavy runtime files
    - Isolates interpreter state for multi-env builds
    - Enhances Codex and VS Code agent clarity
    - Supports future modular deployment where multiple modules can reuse a shared `.venv`

    This policy aligns with LionLock's architectural discipline: code-only repos,
    deterministic environments, and maximum clarity for reproducibility.
