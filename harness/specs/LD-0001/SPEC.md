+++
id = "LD-0001"
title = "Reproducibility of the run-003 and run-004 calibration results"
status = "done"
tier = "private"
allowed_paths = []
+++

# LD-0001 — same end product, on real data

## Why

LL-0001 proves two agents agree on a synthetic corpus. That is necessary but weak: a corpus written
for a spec can accidentally be easy. This spec makes the same demand against 2,000 real results from
the first two successful calibration runs, so "same end product" is a claim about the data as well as
the code.

It is also the honest record of what those results can and cannot support:

* They **can** show the model and server reproduced themselves — the pairing below is what that
  claim rests on.
* They **cannot** be re-scored by LionLock. The probe never wrote response text to disk, so each
  row carries hashes, lengths, timings and status and no answer text. Any future spec that wants to
  re-score real responses needs a different source, such as a message-tap log. If you find one, stop
  and report it before using it — that is a decision about data handling, not a coding choice.

## What it reads

From `LIONLOCK_DATA_DIR`, by glob so no absolute path is ever written down:

* `**/lionlock-cal-*-run-003_consolidated/*.parquet` and the run-004 equivalent
* `**/lionlock-cal-*-run-003_runner/*.parquet` and the run-004 equivalent

Only the columns the aggregates need are loaded. The dataset is **read-only**; this spec writes
nothing into it.

## What it emits

Text-free aggregates only: row counts, the pair count, how many paired prompts produced an identical
completion hash, status and HTTP-status counts, summaries of completion length and latency, and one
`pair_fingerprint` digest.

Never emitted: prompt ids, request ids, completion hashes, prompt or response text, file paths,
hostnames, or model names. This is the rule that lets the output be discussed and compared without
carrying anything that identifies a request.

## Expected values

`$LIONLOCK_DATA_DIR/expectations.json`, with an `LD-0001` object holding at least
`pair_fingerprint`. It lives there and **not in this repository**, because it contains hashes derived
from private data. If the file is absent the acceptance test reports what it measured and skips the
comparison, so a fresh clone is never blocked by a missing private file.

## How this is checked

`make verify-private` — or `LIONLOCK_DATA_DIR=… make verify-private SPEC=LD-0001`. Without
`LIONLOCK_DATA_DIR` the spec reports SKIP rather than FAIL, so CI and any cloud session stay green
without the data. Run it twice: the `pair_fingerprint` must be identical.

## Report template

```
LD-0001: <PASS|SKIP|FAIL>
pairs: <n>  identical: <n>  differing: <n>
pair_fingerprint: <digest>
matched expectations.json: <yes|no|absent>
```
