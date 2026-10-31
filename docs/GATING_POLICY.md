# Gating Policy: Passive (Log-Only) vs Active (Enforced)

LionLock computes a deterministic `GateDecision` for every evaluated signal bundle.

Whether that decision is **enforced** or treated as **log-only** is controlled by
`gating.enabled` with an environment override:

- Config key: `gating.enabled` (in `lionlock.toml`)
- Env var override: `LIONLOCK_GATING_ENABLED`

## Resolution order

1. If `LIONLOCK_GATING_ENABLED` is set to a boolean-like value (`true/false`, `1/0`, etc.), it overrides config.
2. Otherwise, LionLock uses `gating.enabled` from config.
3. If neither is provided, default behavior remains **enabled** (`true`).

## Behavior

- `gating.enabled = false` (or env override false):
  - LionLock still computes severity, risk score, trigger signal, and reason code.
  - Decision is emitted as `ALLOW` (log-only mode).
- `gating.enabled = true` (or env override true):
  - LionLock enforces policy decisions (`ALLOW` / `REFRESH` / `BLOCK`) based on thresholds.

## Important runtime note

The OSS library returns a `GateDecision` object. Real-time interruption depends on the caller honoring `GateDecision.gating_decision`.

## Config templates

- TOML template: [`lionlock.toml.example`](../lionlock.toml.example)
- Env template, for database connection settings only: [`.env.example`](../.env.example)

Set gating in `lionlock.toml` (`[gating] enabled = true|false`) or by exporting
`LIONLOCK_GATING_ENABLED` in the process's real environment. A `.env` file that LionLock finds by
itself supplies database connection settings only; a `LIONLOCK_GATING_ENABLED` line in it is
ignored, so a file in an untrusted checkout cannot switch gating off.
