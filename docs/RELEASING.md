# Publishing a beta release

## Current status

On 28 October 2026, the PyPI JSON API listed only `1.0.0b1`. The b2 version endpoint returned
404, and an uncached pip download from `https://pypi.org/simple` failed with
`No matching distribution found for lionlock==1.0.0b2`. GitHub also listed only `v1.0.0b1`.
A README version, a GitHub release and an installed source version do not prove PyPI availability.

The source at `05434565c96a9534494110cf048caad804dc343d` declares `1.0.0b2` and includes
the fixes described in [CHANGELOG.md](../CHANGELOG.md). The [README](../README.md)
provides an immutable source-install command while publication is pending.

## Before creating the release

1. Select the exact reviewed commit. Check for newer changes before tagging; do not move an
   existing release tag. Use Python 3.12, as pinned in `.python-version`.
2. Run `make setup` and `make verify CHANGED_SINCE=origin/main`. Require `RESULT: PASS`, and
   inspect skipped tests and the verification report. Do not refresh the harness lock, baselines
   or goldens to conceal a failure. The normal environment omits optional SQLAlchemy tests.
3. In a separate clean build environment, install `build==1.6.1` and `twine`, then run
   `python -m build` and `python -m twine check --strict dist/*`.
4. Confirm `pyproject.toml`, wheel and sdist metadata all declare `1.0.0b2`, both CLI entry
   points are present, and the intended tag is exactly `v1.0.0b2`.
5. Install the built wheel in a fresh environment outside the checkout. Run `python -m pip check`,
   the README scoring example, `lionlock-telemetry --help` and `lionlock-sim --help`. Check
   `importlib.metadata.version('lionlock')`. Use synthetic databases for preservation and receiver
   tests; never run release validation against a tester's existing telemetry data.
6. Confirm the actual GitHub `pypi` environment still requires a maintainer reviewer, and that
   PyPI's Trusted Publisher configuration matches owner `thruthseeker`, repository
   `LionLock_FDE_OSS`, workflow `publish.yml`, and environment `pypi`. Workflow comments alone
   do not establish those settings. Do not replace Trusted Publishing with an API token.

## Publish through the existing workflow

1. Create the `v1.0.0b2` tag at the checked commit and publish a GitHub **pre-release**. Include
   the b2 fixes and upgrade requirements below. The workflow triggers on `release: published`;
   pushing a tag alone does not publish to PyPI.
2. Inspect the `publish` workflow's build job. It must pass the tag/version check and produce
   the `dist` artifact containing the wheel and sdist. Inspect that artifact's versions and
   checksums before approving; local build success is not proof of the workflow artifact.
3. An authorised maintainer approves the waiting `pypi` environment deployment. The publish job
   downloads the build artifact and uses its OIDC identity to upload it. Preserve this approval
   gate; do not bypass it or grant upload rights to the build job.
4. Require a successful publish job. Independently verify
   `https://pypi.org/pypi/lionlock/1.0.0b2/json`, including non-yanked distribution files, and
   download/install with no cache from `https://pypi.org/simple` in a fresh environment.
   Match the downloaded distribution hashes against the approved artifact. Repeat the version,
   dependency and CLI checks and the README example outside the source tree.
5. Only after that succeeds, update the README, receiver instructions and site to lead with the
   PyPI command, remove the pending-publication notices, and record the release/workflow links.
   Keep the compatibility warnings. If publishing fails, retain the verified source fallback
   and report the failure without claiming that the package is available.

## Upgrade requirements for the release notes

- Back up existing local logs, SQL telemetry databases and receiver data before upgrading.
  Stop writers or use a consistent SQLite backup that includes committed WAL contents; verify
  the backup before changing the running installation.
- **Upgrade and validate receivers before clients.** A receiver must admit `1.0.0b2` before
  clients send snapshots with that label. Require tokens on internet-facing endpoints; anonymous
  per-install rate limits are bypassable.
- Native `sqlite:///...` initialization preserves supported tables and rows. A known keyed
  pre-auth schema gains two nullable authentication columns. Extra custom columns and unknown
  layouts are refused without mutation and need a separately reviewed manual migration.
  Never drop, rebuild, rename or delete existing telemetry tables to force compatibility.
- This preservation change does not cover SQLAlchemy URI forms such as
  `sqlite+pysqlite:///...`, PostgreSQL or Trust Overlay initializers. An unsupported receiver
  warehouse is also refused unchanged; retain it and its backup if using a new data directory.
- The b2 fixes keep false-like upload settings disabled, reject negative row limits and key
  authenticated receiver rate limits by token. Review configuration during the upgrade, and
  leave uploads disabled unless the operator explicitly opts in.
