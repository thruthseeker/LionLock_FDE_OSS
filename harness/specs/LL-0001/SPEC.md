+++
id = "LL-0001"
title = "Withhold the uncalibrated fatigue_risk_index from the gating channel (SE-0.4.0)"
status = "done"
tier = "public"
allowed_paths = [
  "src/lionlock/core/scoring.py",
  "src/lionlock/core/gating.py",
  "docs/TELEMETRY.md",
  "tests/test_low_conf_halluc.py",
  "tests/test_fatigue_gating.py",
]
+++

# LL-0001 — stop an uncalibrated signal from gating

## Why

`_fatigue_risk_score` puts a weighted sum of three metadata inputs through a sigmoid with
`FATIGUE_SIGMOID_GAIN = 4.0` and `FATIGUE_SIGMOID_BIAS = 1.5`. The weighted sum lies in `[0, 1]`, so
the output lies in `[0.0025, 0.1192]`.

Two facts make that a problem rather than a curiosity:

1. `entropy_decay` and `drift_slope` are caller-supplied metadata that **nothing in this repository
   defines or produces**. No caller here supplies them, so in practice the score is computed
   entirely from defaults.
2. Gating combines channels with `decision_risk_score = max(aggregate, max(derived_risks))`, and
   `fatigue_risk_index` is first in `TRIGGER_SIGNAL_ORDER`. So an all-defaults score cannot raise a
   band, but it *can* win the trigger tie-break and be reported as the reason a response was gated.

Be clear about the size of this. With the committed constants the ceiling is `0.1192` and the
yellow band starts at `0.45`, so **this change cannot alter any gating decision today**. It corrects
attribution and stops a meaningless number participating in the decision channel. It does not
prevent a live false gate, and nothing in this spec should be described as though it does.

An attempt to calibrate the constants was made and **abandoned**, because a threshold fitted on one
set of results did not carry over to another. Hence "withhold", not "recalibrate". Do not change
`FATIGUE_SIGMOID_GAIN` or `FATIGUE_SIGMOID_BIAS`.

## Requirements

- **R1** — `SIGNAL_SCHEMA_VERSION` is `"SE-0.4.0"`.
- **R2** — signal scores and derived signal *values* are unchanged from SE-0.3.0. This change is
  about participation in the decision, not about arithmetic.
- **R3** — on the real scoring path, for any payload missing any fatigue input, setting
  `fatigue_risk_index` to `0.0` or to `1.0` leaves `decision_risk_score`, `severity`,
  `gating_decision`, `trigger_signal` and `reason_code` identical.
- **R4** — fatigue still works when it is actually measured: a hand-built bundle with every fatigue
  input declared present and `fatigue_risk_index = 0.9` still yields `BLOCK` with
  `trigger_signal = "fatigue_risk_index"`. A rule that silently disabled the signal would also pass
  R3, so this requirement is what stops that.
- **R5** — `decide_gate()` reports the same `missing_inputs` as `score_payload` reports for a payload
  with no metadata — **all five keys** — and never names `fatigue_risk_index` or `fatigue_risk` as
  trigger or reason. `decide_gate` takes raw scores only and receives no metadata whatsoever, so
  `duration_ms` and `latency_window_stats` are just as absent as the fatigue inputs. Declaring only
  three would understate what it is missing.
- **R6** — the full product equals `golden.json`'s `expected` exactly, fingerprint included.
- **R7** — `docs/TELEMETRY.md` carries an SE-0.4.0 replay note stating that derived values are
  numerically identical to SE-0.3.0 and that only `fatigue_risk_index`'s gating participation
  changed. No dataset numbers, paths or hashes.

## Scope note on R5 and congestion

R5 is about *reporting* what is missing. It does **not** ask you to withhold `congestion_signature`,
even though `decide_gate` hardcodes it to `0.0` and its inputs are absent too. That placeholder is a
known, separate defect of the same kind, recorded for its own change. Widening the withholding rule
here would alter the gating channel beyond what this spec's golden expects, and R6 would fail.

## How this is checked

`make verify SPEC=LL-0001` runs the acceptance tests, then runs `product.py` twice in separate
processes under different hash seeds and compares the canonical output against `golden.json`.

`golden.json` was generated at the base commit, **before any implementation existed**, by
`oracle.py` — which recomputes the decision itself rather than calling the library. Generation
refuses to proceed unless `oracle.expected(apply_rule=False)` reproduces the library's output
exactly, so the expectation is a prediction the implementation has to meet, not a recording of it.

## Report template

```
LL-0001: <PASS|FAIL>
fingerprint: <from make verify>
files changed: <list>
requirements: R1 <ok> R2 <ok> R3 <ok> R4 <ok> R5 <ok> R6 <ok> R7 <ok>
notes: <anything the spec did not anticipate>
```
