# LionLock

Welcome to LionLock FDE! We're excited to announce that we've successfully integrated and completed Modules 6 and 7. As of now, our repo includes:

- Module 06: The replay and evaluation engine for trust and fatigue scenarios. This module brings in replay capabilities with a focus on policy-driven simulations and OSS-safe evaluations.
- Module 07: Our simulation harness for deterministic trust profiling, now fully operational. It's built to run in a Postgres-first mode with explicit SQLite fallback, ensuring full determinism and robust audit trails.

With these modules in place, we've moved beyond our earlier Module 4 milestones and are now focusing on the final integration stages and real-world OSS readiness. Stay tuned for more updates as we continue to refine and enhance LionLock!

Deterministic fatigue-signal scoring and SQL-first reliability telemetry for LLM applications (OSS core).

LionLock helps developers **measure** and **log** reliability/fatigue signals in a privacy-first, audit-ready way.
It is not a hosted service and not a full LLM gateway.

## Status

**Pre-beta** (OSS core is usable; APIs may evolve).
- Modules 1-4: usable
- Module 5 (gating): in progress
- Module 6 (replay/evaluation): usable
- Module 7 (simulation harness): usable

## Privacy model (OSS)

- **No raw prompt/response text is logged by default**
- Telemetry defaults to derived metrics only (e.g. `prompt_type` + `response_hash`, signal bundles)
- SQL is the canonical log pipeline (SQLite local; Postgres supported)

## Module overview (OSS)

- **Module 1** - Session + request scaffolding
- **Module 2** - Signal scoring (`SignalBundle`)
- **Module 3** - Anomaly detection
- **Module 4** - SQL telemetry (append-only events + missed-signal schema)
- **Module 5** - Gating core (**in progress**) - decision tokens remain **ALLOW / REFRESH / BLOCK**
- **Module 6** - Replay + evaluation (read-only by default; optional write-back is explicit)
- **Module 7** - Simulation harness (deterministic scenario generator + SQL logging; Postgres-first with explicit SQLite fallback)

## Quickstart (dev)

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```
