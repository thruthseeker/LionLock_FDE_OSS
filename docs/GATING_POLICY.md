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
- Env template: [`.env.example`](../.env.example)

Copy these into your local runtime files (`lionlock.toml` and `.env`) and adjust as needed.
