# The development harness

A pinned environment plus spec sheets, so the same job done by different agents produces the same
verified end product. Agents read `AGENTS.md`; this file is for whoever maintains the harness.

## What it guarantees, and what it does not

**Guarantees.** For a given spec and commit, `make verify SPEC=<ID>` reports the same result and the
same fingerprint for every agent, on any machine with the pinned Python. The product is canonical
JSON with floats rounded to 9 decimals, so two libm builds agree.

**Does not guarantee.** Identical code. Two agents can pass the same spec with different naming,
structure and comments. That is intentional: the harness checks the end product, not the prose.

It also cannot tell you a spec is *right*. A golden generated from an implementation only records
what that implementation did. That is why specs for unimplemented work carry an `oracle.py`.

## Layout

```
harness/
  fingerprint.py       canonical JSON + SHA-256
  specs.py             spec discovery, front-matter parsing, product/oracle loading
  verify.py            the eight checks and the maintainer actions
  __main__.py          python -m harness <verify|product|baseline|lock|golden>
  baseline/            recorded pre-existing lint/type findings (the ratchet)
  contract.lock.json   hashes of every protected file
  env/                 requirements.in/.lock, plus the private-tier pair
  specs/<ID>/          SPEC.md, corpus.json, product.py, oracle.py, golden.json, test_acceptance.py
  out/                 verify_report.json (gitignored)
```

## Maintainer workflow

Issuing a spec:

1. Write `harness/specs/<ID>/` from `harness/specs/TEMPLATE.md`. Keep `status = "open"`.
2. If the work is not yet implemented, write `oracle.py` with `expected(*, apply_rule=True)`.
3. At the **base commit**, before any implementation: `make golden SPEC=<ID>`. This refuses to write
   unless `expected(apply_rule=False)` reproduces the library exactly, which is what makes the
   golden trustworthy.
4. `make lock` to record the new files.
5. Confirm `make verify SPEC=<ID>` fails, and that it fails for the reasons the spec names.

Accepting finished work: set `status = "done"` and re-run `make lock`. Done specs block on every
subsequent run, so they become regression tests.

`make baseline` re-records the lint and type ratchet. Only do that when the debt genuinely changed,
and say so in the commit — it is the one action that can hide a new finding.

## Notes on the checks

- **Ratchet, not clean.** This repository has pre-existing ruff, format and mypy findings. The gate
  fails on *new* findings only, compared as a multiset of (file, code, message) so line shifts are
  invisible. Requiring a clean tree would mean touching unrelated legacy code in every job.
- **Scope and privacy diff from the contract lock commit**, not from `HEAD~1`, so an agent that
  commits several times is still measured against the state the job started from.
- **Privacy findings record locations only.** The matched text is deliberately never stored, because
  the report is written to disk and this repository is public.
- **Determinism runs the product in two fresh processes** under different `PYTHONHASHSEED` values.
  Same-process repetition would not catch dictionary or set ordering leaking into the output.

## Adding a protected file

`PROTECTED_GLOBS` in `harness/verify.py` lists the named files; everything under `harness/` except
`out/` is protected automatically. Add the path, then `make lock`. Until the lock is regenerated the
contract check fails, which is the intended nudge.
