# LionLock development harness.
#
# Agents need two commands: `make setup` once, then `make verify SPEC=<ID>` until it says PASS.
# `make golden`, `make baseline` and `make lock` are maintainer-only — see AGENTS.md.

PYTHON ?= python3
VENV := .venv
VENV_PY := $(VENV)/bin/python

# The package is used from the source tree, so nothing is ever built or installed.
export PYTHONPATH := src
export PYTHONDONTWRITEBYTECODE := 1

SPEC_ARG := $(if $(SPEC),--spec $(SPEC),)

.PHONY: setup verify verify-private golden baseline lock clean

setup:
	$(PYTHON) -m venv $(VENV)
	$(VENV_PY) -m pip install --quiet --upgrade pip
	$(VENV_PY) -m pip install --quiet --require-hashes --no-deps -r harness/env/requirements.lock
	@$(VENV_PY) -c "import sys; print('setup complete:', sys.version.split()[0])"

verify:
	$(VENV_PY) -m harness verify $(SPEC_ARG)

verify-private:
	$(VENV_PY) -m harness verify --private $(SPEC_ARG)

# --- maintainer only -------------------------------------------------------------------------
golden:
	@test -n "$(SPEC)" || (echo "usage: make golden SPEC=<ID>" && exit 2)
	$(VENV_PY) -m harness golden --spec $(SPEC)

baseline:
	$(VENV_PY) -m harness baseline

lock:
	$(VENV_PY) -m harness lock

clean:
	rm -rf harness/out
