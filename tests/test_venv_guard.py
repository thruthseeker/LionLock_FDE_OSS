"""Exercise the shell guard with real, isolated virtual environments."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("entrypoint", ["tools/venv_guard.sh", "scripts/venv_guard.sh"])
@pytest.mark.parametrize("configured", [None, "relative", "absolute"])
def test_guard_accepts_configured_environment(tmp_path, entrypoint, configured):
    root = Path(__file__).resolve().parents[1]
    for script in ("tools/venv_guard.sh", "scripts/venv_guard.sh"):
        target = tmp_path / script
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(root / script, target)
    venv = tmp_path / ("external env" if configured else ".venv")
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)
    env = os.environ.copy()
    env.pop("VIRTUAL_ENV", None)
    env.pop("LIONLOCK_VENV_PATH", None)
    if configured:
        env["LIONLOCK_VENV_PATH"] = "./external env" if configured == "relative" else str(venv)
    result = subprocess.run(
        [
            "bash",
            "-c",
            '. "$1"; python -c "import sys; print(sys.executable)"',
            "guard",
            entrypoint,
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[-1] == str(venv / "bin/python")


def test_guard_refuses_directory_without_activation_script(tmp_path):
    env = os.environ.copy()
    env["LIONLOCK_VENV_PATH"] = str(tmp_path)
    guard = Path(__file__).resolve().parents[1] / "tools/venv_guard.sh"
    result = subprocess.run(["bash", str(guard)], env=env, capture_output=True, text=True)
    assert result.returncode != 0
    assert "Missing activate script" in result.stderr
