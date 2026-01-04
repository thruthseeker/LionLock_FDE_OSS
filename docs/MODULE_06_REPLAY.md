# Module 06 Replay & Evaluation (OSS)

LionLock Module 06 replays gating decisions from SQL telemetry and compares them to deterministic re-evaluation under a chosen policy bundle. It is read-only by default and never exports raw prompt/response text.

## CLI

```
lionlock-replay --db sqlite:///path/to/telemetry.db --policy GC-0.3.1
```

Optional flags:

- `--policy-registry policies.toml` (default)
- `--labels labels.jsonl` (labels are external; JSONL only)
- `--schema public` (Postgres schema)
- `--where SESSION_ID` or `--session SESSION_ID` (exact session filter)
- `--limit N`
- `--out replay_out`
- `--write-back --i-understand-write-back` (explicit opt-in; writes `missed_signal_events`)

Exit codes: `0` success, `2` invalid args/policy, `3` DB read/write failure, `4` label load failure.

## Policy Registry

`--policy` is an identifier, not a filename or path. The registry is a TOML file (default `policies.toml`) mapping policy versions to gating settings.

Example:

```
[policies."GC-0.3.1"]
gating.enabled = true
gating.hallucination_mode = "warn_only"
gating.thresholds.yellow = 0.45
gating.thresholds.orange = 0.65
gating.thresholds.red = 0.80
signals.enabled = [
  "repetition_loopiness",
  "novelty_entropy_proxy",
  "coherence_structure",
  "context_adherence",
  "hallucination_risk",
]
[policies."GC-0.3.1".signals.weights]
repetition_loopiness = 0.30
novelty_entropy_proxy = 0.25
coherence_structure = 0.25
context_adherence = 0.20
hallucination_risk = 0.00
```

`policy_version` and `config_hash` are emitted in replay outputs. `config_hash` is computed via `lionlock.logging.event_log.config_hash_from` over the resolved gating + signals subset.

## Labels (JSONL)

Labels are external to production telemetry. Each JSONL line is keyed by `(session_id, turn_index, replay_id)`:

```
{"session_id":"session-1","turn_index":1,"replay_id":"replay-1","expected_decision":"REFRESH","actual_failure_type":"threshold"}
```

Fields:
- `session_id` (string)
- `turn_index` (int)
- `replay_id` (string, required)
- `response_hash` (optional string; used when present to disambiguate joins)
- `expected_decision` (`ALLOW|REFRESH|BLOCK`)
- `actual_failure_type` (optional string)

Module 06 only joins and evaluates labels; it never infers expected decisions.

## Outputs

`--out` directory includes:
- `replay_report.json` (deterministic JSON, sort_keys, no raw text)
- `replay_report.md`
- `replay_diff.json` (per-turn diff artifact)
- `proposed_missed_signal_events.jsonl` (export-only proposals)

Scores are rounded to 6 decimals in reports for deterministic comparisons.

## Write-back (opt-in)

Write-back is off by default. To write `missed_signal_events`, you must set both:

```
--write-back --i-understand-write-back
```

Write-back only uses existing labels and preserves provenance fields; it never infers labels.

## Determinism

Deterministic replay means identical inputs (DB snapshot, policy_version, labels) produce byte-identical JSON reports. Ordering rules:
- Events are processed in stable order by `(session_id, turn_index, response_hash, event_type, event_pk, timestamp)`.
- Duplicate keys `(session_id, turn_index, response_hash, event_type)` are deduplicated; the lowest `event_pk` wins, otherwise the earliest timestamp wins.
- JSON output uses `sort_keys=True` and compact separators.

## Threat Notes

- Prompt/response text is never consumed or emitted in Module 06. Any attempt to smuggle forbidden keys/content in `signal_bundle` or labels is rejected by the privacy scanners.
- `trust_logic_version` is Trust Overlay metadata; it is never used as a gating policy identifier. Gating policies use `policy_version` + `config_hash`.
- Labels are external to production telemetry and are always read-only; Module 06 never manufactures labels.
- `prompt_type` is treated as non-authoritative metadata and is never used to determine correctness.
- Events with missing identifiers are flagged as `invalid_identifiers` in the report and excluded from recomputation.
