# Telemetry: Local SQLite Log and Opt-in Uploads

LionLock records its gating decisions and Trust Overlay records in a single local SQLite file.
That file never leaves the machine. If you opt in, LionLock can also seal an allowlisted,
pseudonymized copy of new rows into small snapshot files and upload them over HTTPS to a
receiver you run. Every upload can be inspected before it is sent.

- **Local first.** Logging is local by default and needs no network.
- **Opt-in upload.** Uploads are off unless you enable them and set an endpoint, and
  `DO_NOT_TRACK=1` always turns them off.
- **Allowlist, not blocklist.** Only the fields listed in the data dictionary below can leave
  the machine. There is no path for prompts, responses, or other free text.
- **Verifiable.** Snapshots have a deterministic content digest, and the receiver re-applies the
  same export policy to every uploaded row.

## How it works

```text
 your app ──log_event()────────────┐
          ──append_trust_record()──┤
                                   ▼
             logs/lionlock.db              local only, hash-chained, owner-only permissions
                   │
                   │  lionlock-telemetry export      (offline; works with uploads disabled)
                   ▼
             logs/outbox/lionlock-<id>-000001.db     allowlisted, re-keyed, deterministic
                   │
                   │  lionlock-telemetry upload      (opt-in; HTTPS; idempotent)
                   ▼
             receiver you control                    validates as untrusted input
               ├── accepted/<sha256>.db              raw snapshots, content-addressed
               └── warehouse.db                      merged tables for analysis
```

## The local log

| Setting | Default | Purpose |
|---|---|---|
| `logging.backend` | `"sqlite"` | `sqlite`, `jsonl`, `sql`, `both` (JSONL + SQL), or `off` |
| `logging.sqlite_path` | `logs/lionlock.db` | Location of the log file |
| `logging.sqlite_max_rows` | `100000` | Rows kept per table; older rows are pruned |

`log_event()` writes public signal events. When the SQLite backend is selected,
`append_trust_record(..., config=config)` also writes Trust Overlay records to the same file.
Writes are synchronous, cost about a millisecond each, and are safe across threads and
processes. There is no background thread, and nothing is buffered that could be lost on exit.

Each table is an append-only hash chain: every row stores the SHA-256 of its contents together
with the previous row's hash. `lionlock-telemetry verify` recomputes the chain and reports the
first row that was edited, reordered, or deleted. Pruning records the hash of the last removed
row, so the retained window stays verifiable. Like any self-contained hash chain, this cannot
detect rows removed from the end of the file. The file is created with owner-only permissions,
and deleted rows are overwritten (`secure_delete`).

The local log holds more than an upload does, for example raw request and session IDs. Share a
snapshot, never the log file itself.

## Enabling uploads

```toml
[telemetry_upload]
enabled = true
endpoint = "https://telemetry.example.org"
# Optional bearer token, read from an environment variable or a file:
token_env = "LIONLOCK_UPLOAD_TOKEN"
token_path = ""
interval_hours = 24
```

| Environment variable | Effect |
|---|---|
| `DO_NOT_TRACK=1` | Disables uploads, overriding every other setting |
| `LIONLOCK_TELEMETRY_UPLOAD=on\|off` | Overrides `telemetry_upload.enabled` |
| `LIONLOCK_TELEMETRY_ENDPOINT` | Overrides `telemetry_upload.endpoint` |
| `LIONLOCK_UPLOAD_TOKEN` | Bearer token (default `token_env`) |

The client enforces these rules:

- The endpoint must use `https://`. Plain `http://` is accepted only for `localhost`.
- Endpoints that embed credentials, query strings, or fragments are refused.
- Redirects are never followed, so a token can never be forwarded to another host.
- Before each send, every snapshot is re-validated against the export policy. A file that fails
  (for example, one edited by hand in the outbox) is moved to `outbox/rejected/` and never sent.
- Snapshots the server rejects as invalid (400, 409, 413, 415, 422) are set aside in
  `outbox/rejected/`. On a network error, 408, 429, or 5xx the client retries with backoff. On
  401, 403, or any other unexpected response it stops. In every case except a rejection, the file
  stays in the outbox for the next run.

To upload from an application, call `maybe_export_and_upload(config)` at startup. It returns
immediately when uploads are off, runs at most once per `interval_hours`, and never raises. Or
schedule `lionlock-telemetry upload` with cron or a systemd timer.

## Inspecting before you opt in

```bash
lionlock-telemetry status                       # log location, row counts, upload state
lionlock-telemetry verify                       # check the hash chains
lionlock-telemetry preview --rows 3             # build the next upload without consuming it
lionlock-telemetry inspect logs/preview/lionlock-*.db
```

`preview` writes exactly the snapshot the next upload would send and prints its metadata and
sample rows, after running the same validation as the receiver. It changes no export state: the
next real export seals the same rows with the same content digest. The snapshot is an ordinary
SQLite file, so you can also open it with `sqlite3`.

`export` seals snapshots for real and advances the export watermark. `export --out DIR` writes
them somewhere other than the outbox, for example to carry them out of an air-gapped network.
Placed in another machine's outbox, they are uploaded by `lionlock-telemetry upload` there.

## Data dictionary: everything an upload can contain

### `snapshot_meta` (one set per snapshot)

| Key | Value |
|---|---|
| `format`, `schema_version` | `lionlock-telemetry-snapshot`, `1` |
| `install_id` | Random 128-bit ID, created on first export; rotate with `reset-identity` |
| `segment_index`, `prev_segment_digest` | Segment counter and the digest of the previous segment |
| `content_digest` | SHA-256 over the canonical content of this snapshot |
| `lionlock_version` | Package version label |
| `python` | Major.minor only, for example `3.11` |
| `platform` | `linux`, `macos`, `windows`, `freebsd`, or `other` |
| `<table>_rows`, `<table>_pruned_before_export` | Row counts and rows lost to local pruning |

### `events` (one row per gating decision)

| Column | Value |
|---|---|
| `seq` | Per-install sequence number (restarts at 1 after `reset-identity`) |
| `ts_hour` | Event time truncated to the UTC hour |
| `decision` | `ALLOW`, `REFRESH`, `BLOCK`, `UNKNOWN`, or `ERROR` |
| `severity` | `green`, `yellow`, `orange`, or `red` |
| `reason_code` | A snake_case identifier such as `hallucination_risk`; anything else is dropped |
| `aggregate_score` | Number in [0, 1] |
| `signal_scores_json` | The five signal scores, each in [0, 1] |
| `signal_bundle_json` | Signal schema version, the five signal scores, the five derived signals, and the names of missing metadata inputs |
| `duration_ms` | Integer from 0 to 86,400,000 |
| `config_hash` | SHA-256 of the gating and signal configuration |

### `trust_records` (one row per Trust Overlay record)

| Column | Value |
|---|---|
| `seq`, `ts_hour` | As above |
| `session_key` | HMAC-SHA256 of the session ID under a per-install key that never leaves the machine |
| `turn_index` | Integer |
| `model_family` | Public family such as `llama`, `gpt-4o`, `claude`, `mistral`, or else `other`/`unknown` |
| `prompt_type` | `qa`, `code`, `creative`, or `other` |
| `trust_score`, `volatility` | Numbers in [0, 1] |
| `trust_label` | `TRUSTED`, `MONITOR`, `AT_RISK`, `UNTRUSTED`, or `UNKNOWN` |
| `badge` | `INSUFFICIENT_DATA`, `STABLE`, `VOLATILE`, `DRIFTING`, `RECOVERING`, or `CLEAN_RUN` |
| `drift_detected` | 0 or 1 |
| `trigger_flags_json` | Subset of `score_below_threshold`, `drift_detected`, `volatility_spike` |
| `detail_json` | Numeric confidence band and drift statistics, signal summary scores, model parameters (temperature, top_p, max_tokens, frequency and presence penalties, tool calling on or off), trust logic version, runtime mode, and the SHA-256 fingerprint of the Trust Overlay source |

### Never uploaded

Prompts, responses, and response hashes. Raw session IDs, request IDs, and user IDs, and the
pseudonymous user key. Hostnames and hostname hashes, container IDs, base URLs, and file paths.
Model names (only the family), stop sequences, seeds, free-text notes, and auth tokens. Exact
timestamps (only the hour).

HTTP requests carry `User-Agent: lionlock/<version>` and headers that repeat the snapshot's
install ID, segment, and digests. The receiver sees the client's IP address at the network level.
The reference receiver never logs or stores it, and your reverse proxy should be configured the
same way (see below).

## Running the receiver

The reference receiver uses only the Python standard library:

```bash
pip install lionlock
lionlock-telemetry serve --data-dir /var/lib/lionlock-telemetry --host 127.0.0.1 --port 8787
```

It binds to localhost. Put a TLS-terminating reverse proxy in front of it and keep access logs
off for this route. With Caddy, which writes no access log unless you add a `log` directive:

```text
telemetry.example.org {
    request_body {
        max_size 16MB
    }
    reverse_proxy 127.0.0.1:8787
}
```

With nginx, use `access_log off;` and `client_max_body_size 16m;` in the location block.

To require tokens, issue one per partner or deployment with the bundled tool. It writes the
token to a file with owner-only permissions and appends only its SHA-256 hash to the allowlist:

```bash
python scripts/log_token_tool.py generate --token-path upload.token --hashes-path token_hashes.txt
lionlock-telemetry serve --data-dir /var/lib/lionlock-telemetry --token-hashes-file token_hashes.txt
```

Clients set `token_path` (or `LIONLOCK_UPLOAD_TOKEN`). The receiver stores only hashes, so a
leaked allowlist does not reveal any token. Without a token file, the receiver accepts anonymous
uploads, rate-limited per install.

### What the receiver checks

In order, before any row reaches the warehouse:

1. Body size, both compressed and decompressed (a gzip bomb is refused at the cap).
2. The SHA-256 of the body matches the declared `X-LionLock-File-SHA256`.
3. The file is written to `quarantine/` and opened read-only, with `trusted_schema=OFF`,
   `cell_size_check=ON`, and SQLite's defensive mode where Python supports it.
4. The schema matches the snapshot schema exactly: no extra tables, views, triggers, or indexes.
5. `PRAGMA quick_check` passes.
6. The metadata is well-formed and the recomputed content digest matches.
7. Every row comes through a re-run of the export policy unchanged.
8. The upload headers agree with the snapshot metadata.

Accepted files move to `accepted/<sha256>.db` and are merged into `warehouse.db` in one
transaction. Rejected files move to `rejected/` with a reason. Re-sending a file returns
`200 duplicate`. Sending different content for a segment that was already received returns
`409`. Each upload row records whether its `prev_segment_digest` links to the previous segment
(`ok`, `gap`, or `broken`).

For production, run the receiver as an unprivileged user in a container with a read-only root
filesystem, a writable data volume, and memory limits.

### Querying the warehouse

```sql
SELECT decision, severity, reason_code, COUNT(*) AS n
FROM events GROUP BY 1, 2, 3 ORDER BY n DESC;

SELECT model_family, trust_label, COUNT(*) AS n
FROM trust_records GROUP BY 1, 2 ORDER BY 1, n DESC;

SELECT lionlock_version, platform, COUNT(DISTINCT install_id) AS installs
FROM uploads GROUP BY 1, 2;
```

Field data can be replayed against a candidate policy, because `signal_bundle_json` holds
exactly what the gating engine consumes:

```python
import json
import sqlite3

from lionlock.core.gating import evaluate_policy
from lionlock.core.models import DerivedSignals, SignalBundle, SignalScores

with sqlite3.connect("warehouse.db") as conn:
    rows = conn.execute(
        "SELECT decision, signal_bundle_json FROM events WHERE signal_bundle_json IS NOT NULL"
    ).fetchall()

changed = 0
for field_decision, raw in rows:
    data = json.loads(raw)
    bundle = SignalBundle(
        signal_schema_version=data["signal_schema_version"],
        signal_scores=SignalScores(**data["signal_scores"]),
        derived_signals=DerivedSignals(**data["derived_signals"]),
        missing_inputs=tuple(data["missing_inputs"]),
    )
    candidate = evaluate_policy(bundle, thresholds={"yellow": 0.55, "orange": 0.75, "red": 0.9})
    changed += candidate.gating_decision != field_decision
print(f"{changed} of {len(rows)} field decisions would change under the candidate thresholds")
```

### Deletion requests

`lionlock-telemetry status` shows an install's `install_id`. To delete everything uploaded under
it, remove its rows from `uploads`, `events`, and `trust_records`, along with the matching files
in `accepted/`. `lionlock-telemetry reset-identity` rotates the install ID and pseudonymization
key, so future uploads cannot be linked to past ones.

## Threat model

| Threat | Mitigation |
|---|---|
| A code change starts exporting content | Allowlist policy; canary tests in `tests/test_telemetry_export.py` fail if any tagged value reaches a snapshot |
| A modified client sends extra fields | The receiver requires the exact schema and re-runs the export policy on every row |
| A crafted SQLite file attacks the parser | Size caps, read-only defensive open, `quick_check`, schema check before any data is read; isolate the process |
| A bearer token leaks in transit | HTTPS only, no redirects, token read from env or file and never logged; the server stores only hashes |
| Re-identification through identifiers | Keyed HMAC pseudonyms that cannot be linked across installs; hour-level timestamps; coarse platform data; identity reset |
| Poisoned or fake uploads | Optional tokens, per-install rate limits, segment chain status; treat community data as statistical |
| Local log tampering | Per-table hash chains and `lionlock-telemetry verify` |
| Receiver compromise | Data minimization limits what an attacker can obtain |

## Determinism and verification

- The same log contents and install identity always produce the same snapshot content digest,
  and byte-identical files on the same SQLite version
  (`test_export_is_deterministic_for_identical_inputs`).
- The same inputs always produce the same hash chain
  (`test_identical_inputs_produce_identical_hash_chains`).
- Scoring, gating, Trust Overlay computation, and the export policy import no networking,
  remote-database, or ML/LLM libraries. `tests/test_offline_guarantees.py` enforces this.
- The receiver accepts a row only if the export policy, which is the same code the client runs,
  leaves it unchanged. The written policy is therefore also the acceptance test.
