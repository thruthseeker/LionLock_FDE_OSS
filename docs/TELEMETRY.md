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
- **Rebuilt, never copied.** The file that is sent, and the file the receiver keeps, are rebuilt
  from validated rows. Bytes hidden inside a SQLite file, such as appended data or the residue
  of deleted rows, cannot travel with it.

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
               ├── accepted/<sha256>.db              clean rebuilds, named by their own SHA-256
               ├── rejected/<sha256>.reason.txt      the reason only, never the uploaded file
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
detect rows removed from the end of the file. The file is kept owner-only: its mode is set when
it is first opened in a process and re-checked on later writes, and a failure to set it is
reported as an error. Deleted rows are overwritten (`secure_delete`). LionLock writes only to its
own log: a database without LionLock's application id is used only if it is completely empty
(no schema and no version stamp), so a file that merely has tables with the same names is
refused unchanged. The file's identity is checked again on every read and write, before its mode
or contents change, so a different database later placed at the same path is refused too. Only
SQLite's own internal objects (names starting with the literal prefix `sqlite_`) are disregarded
when deciding whether a file is empty.

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

`enabled` switches uploads on only when it is `true`, or a string such as `"true"`, `"yes"` or
`"on"`. Anything else, including `"false"`, `"off"`, a typo or a number, leaves uploads off.

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
- Before each send, the outbox file is read once, re-validated against the export policy, and
  rebuilt from its validated rows. Only the rebuilt file is sent, never the outbox file itself,
  and the transport hashes describe the bytes actually sent. A file that fails validation (for
  example, one edited by hand in the outbox) is moved to `outbox/rejected/` and never sent.
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

One run seals at most 1,000 segments. If logged rows remain after that, `export` prints
`"more_pending": true` and exits 1; run it again to continue. `upload` exits 0 only when every
snapshot it handled was delivered (`uploaded` or `duplicate`) and nothing is left to send, 1
otherwise (including rejected or invalid snapshots), and 2 when uploads are disabled.

## Data dictionary: everything an upload can contain

### `snapshot_meta` (one set per snapshot)

| Key | Value |
|---|---|
| `format`, `schema_version` | `lionlock-telemetry-snapshot`, `2` |
| `install_id` | Random 128-bit ID, created on first export; rotate with `reset-identity` |
| `segment_index`, `prev_segment_digest` | Segment counter and the digest of the previous segment |
| `content_digest` | SHA-256 over the canonical content of this snapshot |
| `lionlock_version` | A published LionLock release (currently `0.1.0`, `1.0.0b1` or `1.0.0b2`); anything else, including private or development build numbers, becomes `unknown` |
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
| `reason_code` | `repetition_loop`, `low_novelty`, `low_coherence`, `context_drift`, `hallucination_risk`, `fatigue_risk`, `congestion_risk`, `policy_violation`, or `connector_error`; anything else becomes `null` |
| `aggregate_score` | Number in [0, 1] |
| `signal_scores_json` | The five signal scores, each in [0, 1] |
| `signal_bundle_json` | Signal schema version (`SE-0.2.0`, `SE-0.3.0`, or `SE-0.4.0`; anything else becomes `unknown`), the five signal scores, the five derived signals, and the names of missing metadata inputs |
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
| `detail_json` | Numeric confidence band and drift statistics, signal summary scores, model parameters (temperature, top_p, max_tokens, frequency and presence penalties, tool calling on or off), trust logic version (`TO-0.1.0`, otherwise omitted), runtime mode (`oss`, otherwise omitted), and the SHA-256 fingerprint of the Trust Overlay source |

Label fields carry only the public values listed above, the values LionLock itself emits. A
private name can look exactly like an identifier or a version string, so these fields are checked
for membership, never for shape: anything else is dropped or neutralized as shown. `unknown`
records only that a value was not a recognized public one; replay tooling must not guess the real
version from it. The published-release list grows only through a reviewed code change, never
from logs, the environment, or a received value. Snapshot `schema_version` 2 introduced these
rules and rebuilt transfers. A receiver accepts version 2 only: version 1 snapshots and
warehouses are unsupported and are refused without being changed. Whether any version 1 data
exists outside this repository is unknown; migrating or cleaning it up is not part of this
release.

### Never uploaded

Prompts, responses, and response hashes. Raw session IDs, request IDs, and user IDs, and the
pseudonymous user key. Hostnames and hostname hashes, container IDs, base URLs, and file paths.
Model names (only the family), stop sequences, seeds, free-text notes, and auth tokens. Exact
timestamps (only the hour).

HTTP requests carry `User-Agent: lionlock/<version>` (the same published-release label, else
`unknown`) and headers that repeat the snapshot's install ID, segment, and digests. The byte
domains are fixed:

| Value | SHA-256 of |
|---|---|
| `X-LionLock-File-SHA256`, `Idempotency-Key` | The rebuilt, uncompressed SQLite file; the request body is gzip of exactly these bytes |
| `received_sha256` (receiver) | The request body after bounded decompression |
| `stored_sha256` (receiver) | The clean file kept in `accepted/` |
| `content_digest` | The canonical metadata and rows, independent of file layout |

No digest of the compressed body is used under any of these names. Plain-http loopback endpoints
are contacted directly, ignoring proxy environment variables, so a token and snapshot never pass
through a proxy unencrypted; HTTPS endpoints honor the usual proxy settings. The receiver sees
the client's IP address at the network level.
The reference receiver never logs or stores it, and your reverse proxy should be configured the
same way (see below).

## Running the receiver

The reference receiver uses only the Python standard library. Install a published release from
PyPI:

```bash
pip install lionlock==1.0.0b2
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
leaked allowlist does not reveal any token. With tokens, the upload rate limit counts per token, so
a client cannot reset it by changing its install id. Without a token file, the receiver accepts
anonymous uploads, rate-limited per install id. The client chooses that id, so the anonymous limit
slows a misbehaving client but cannot stop a deliberate one: **require tokens on any endpoint
reachable from the internet.** A token file that lists no hashes (empty, or comments only) is
refused at startup instead of being treated as anonymous mode.

### What the receiver checks

In order, before any row reaches the warehouse:

1. Body size, both compressed and decompressed (a gzip bomb is refused at the cap).
2. The SHA-256 of the body matches the declared `X-LionLock-File-SHA256`.
3. The body is written to an owner-only file in a fresh private directory under `quarantine/`
   and opened read-only, with `trusted_schema=OFF`, `cell_size_check=ON`, and SQLite's defensive
   mode where Python supports it.
4. The schema matches the snapshot schema exactly: no extra tables, views, triggers, or indexes.
5. `PRAGMA quick_check` passes.
6. The metadata is well-formed and the recomputed content digest matches.
7. Every row comes through a re-run of the export policy unchanged.
8. The upload headers agree with the snapshot metadata.
9. The validated rows are rebuilt into a fresh snapshot file, which must reproduce the same
   metadata, rows, and content digest, with no free pages or bytes past its last page.

An accepted upload is stored only as that rebuild, `accepted/<sha256>.db` named by the rebuild's
own SHA-256. The file is written and fsynced before the upload is committed to `warehouse.db`,
so a recorded upload always has its file. Clean accepted files are never deleted by the
receiver; a failure after the file is written but before the commit can leave an unreferenced
("orphan") file, which is not counted as an upload. The uploaded bytes are deleted on every path,
and a failure to delete them is logged and fails the request; a rejection leaves only
`rejected/<sha256>.reason.txt`, named by the SHA-256 of the received file. Keeping raw uploads
would need its own sensitive-data retention policy, and the reference receiver has none.

Duplicates are decided by content: sending a segment again returns `200 duplicate`, even in a
bytewise-different file, but only after the recorded accepted file is checked against its
`stored_sha256`. If that file is missing or corrupt the receiver answers `500 stored evidence
missing or corrupt` and leaves the record as it is. Different content for a segment that was
already received returns `409`, and so does a segment whose rows reuse sequence numbers already
stored for the install; neither changes the warehouse. Each upload row records `received_sha256`
and `stored_sha256` separately, and whether its `prev_segment_digest` links to the previous
segment (`ok`, `gap`, or `broken`). A segment recorded as a `gap` is re-judged when its
predecessor arrives.

`warehouse.db` is stamped with its layout version (`PRAGMA user_version`, currently 2). Before
the receiver creates or writes anything, an existing warehouse is opened read-only and must be
either empty (no schema of its own, `user_version` 0, `application_id` 0; empty tables do not
count, and only SQLite's internal `sqlite_` objects are disregarded) or an exact match for the current layout, including its tables, columns, keys, and
indexes. Anything else, including an older layout, is refused without changing its file,
version fields, or records; start the receiver with a new data directory.

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

Each bundle records its `signal_schema_version`. Bundles from before `SE-0.3.0` carry a
`low_conf_halluc` value computed from `1 - hallucination_risk`, which scored grounded answers as
high risk. When replaying older data, filter on the version, or recompute that field from the
stored signal scores with `lionlock.core.scoring.low_conf_halluc_score`. Leave bundles marked
`unknown` out of any version-specific replay; their real version cannot be recovered.

`SE-0.4.0` changed no numbers. Every derived value it produces is identical to `SE-0.3.0` for the
same inputs, and the signal weights, thresholds and fatigue constants are unchanged. The only
difference is that `fatigue_risk_index` no longer participates in gating when any of
`entropy_decay`, `turn_index` or `drift_slope` is listed in `missing_inputs`; it is still recorded
in every bundle. Two consequences for replay: bundles from `SE-0.3.0` and `SE-0.4.0` can be pooled
for any analysis of the stored values, but a replay that recomputes decisions across the boundary
may see `trigger_signal` and `reason_code` change for rows whose fatigue inputs were absent. The
fatigue score itself is uncalibrated — see the note on `FATIGUE_SIGMOID_GAIN` in
`lionlock/core/scoring.py` — so it should not be treated as a risk probability in either version.

### Deletion requests

`lionlock-telemetry status` shows an install's `install_id`. To delete everything uploaded under
it, remove its rows from `uploads`, `events`, and `trust_records`, along with the files in
`accepted/` named by those rows' `stored_sha256`. `lionlock-telemetry reset-identity` rotates the install ID and pseudonymization
key, so future uploads cannot be linked to past ones. If you copy the warehouse to BigQuery, delete
the same rows there too (`DELETE FROM dataset.events WHERE install_id = '...'`, and likewise for
`trust_records` and `uploads`). If the deleted rows include the last ones the sync copied, the sync
stops before changing anything in BigQuery (see below).

### Copying the warehouse to BigQuery

`lionlock-telemetry bigquery-sync` copies rows the receiver has already validated and committed
into a BigQuery dataset. It uses only the standard library, needs no key file (it takes access
tokens from the Compute Engine metadata server, so run it on a VM whose attached service account
has `roles/bigquery.dataEditor` on the dataset and `roles/bigquery.jobUser` on the project, with
the `bigquery` access scope), and is meant to run hourly next to the receiver:

```bash
lionlock-telemetry bigquery-sync --data-dir /var/lib/lionlock-telemetry \
    --state-file /var/lib/lionlock-bigquery/state.json \
    --project my-project --dataset lionlock_telemetry --location us-central1
```

Nothing is transformed. Each BigQuery table has the warehouse table's columns, types (`TEXT` as
`STRING`, `INTEGER`, `REAL` as `FLOAT`) and nullability, and each row is the warehouse row as
canonical JSON. `events` and `trust_records` are appended to tables partitioned by load day, so a
dataset's default partition expiration applies to them; `uploads` is small and its `chain_status`
can change when a late segment arrives, so it is replaced as a whole whenever it changes. Each
replacement has its own job ID, so content that recurs (a deletion can restore an earlier state)
is loaded again rather than taken as already loaded, and when no upload rows are left the BigQuery
table is deleted (an empty load is not a reliable way to clear it) and recreated by the next
replacement.

Each `events` and `trust_records` row is loaded exactly once, and `uploads` is a snapshot that
every replacement overwrites as a whole, so after a successful run it matches the warehouse:

- New `events` and `trust_records` rows are copied in `rowid` order, in batches of at most 20,000
  rows and 8 MiB. Each batch's `rowid` range and SHA-256 are written to the state file before its
  load job is submitted, and the job ID is derived from the destination, the range and that hash.
  After a crash the same range is rebuilt byte for byte and the existing job is found, so the
  rows are not loaded a second time.
- A batch counts as loaded only when BigQuery reports its job done with no error and with exactly
  as many output rows as were sent. A failed load job loads nothing: the run that saw the failure
  stops with an error, records the next attempt number in the state file, and the next run retries
  the same batch under the next job ID. A persistent error is retried once per run until it is
  fixed; it never stops the sync for good, and starting over with a new state file is never needed
  (it would load every row again).
- The state file keeps the hash of the last row loaded from each table, and every run checks it
  before changing anything in BigQuery. If that row is missing or different, for example because
  the warehouse was replaced or a deletion request removed it, the sync stops without touching
  BigQuery instead of risking overwritten, skipped or repeated rows. A state file is tied to one project,
  dataset and location; another destination needs a new state file.
- Only one sync can use a state file at a time.

The command prints a JSON summary of the rows and jobs it loaded, and exits non-zero on any error.

## Threat model

| Threat | Mitigation |
|---|---|
| A code change starts exporting content | Allowlist policy; canary tests in `tests/test_telemetry_export.py` fail if any tagged value reaches a snapshot |
| A modified client sends extra fields | The receiver requires the exact schema and re-runs the export policy on every row |
| Bytes hidden in a snapshot file (appended data, deleted-row residue) | The uploader sends, and the receiver stores, only files rebuilt from validated rows; raw uploads are deleted after validation |
| A private name passed off as a label or version | Label fields accept only the listed public values, in the client and the receiver alike |
| A deliberately modified client encodes data in numeric fields | Not prevented: numbers are range-checked, not interpreted. Treat uploads from clients you do not control as untrusted |
| A crafted SQLite file attacks the parser | Size caps, read-only defensive open, `quick_check`, schema check before any data is read; isolate the process |
| A bearer token leaks in transit | HTTPS only (plain http only for loopback, never via a proxy), no redirects, token read from env or file and never logged; the server stores only hashes |
| Re-identification through identifiers | Keyed HMAC pseudonyms that cannot be linked across installs; hour-level timestamps; coarse platform data; identity reset |
| Poisoned or fake uploads | Optional tokens, per-token rate limits (per-install, and bypassable, without tokens), segment chain status; treat community data as statistical |
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
