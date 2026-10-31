# Changelog

## Unreleased — audit fixes

From a full review of `src/` after the move to fully open source. Each fix has a test that fails on
`1.0.0b2`.

### Fixed

- **The LLM connector could leak its API key.** urllib follows a redirected POST (301/302/303) as
  a GET that still carries `Authorization`, so one redirect sent the bearer key to whatever host
  the server named. Redirects are no longer followed, the key is never sent over plain http except
  to localhost, and only http/https endpoints are called.
- **A streamed reply could be billed and shown twice.** An empty `choices` chunk (usage or content
  filter) or a dropped stream fell back to a second, non-streaming request and replayed the whole
  reply after the partial one. A stream that fails after text was shown now returns
  `stream_interrupted`.
- **A `.env` file could switch gating off.** A `.env` found implicitly in the current directory or
  repo root was copied into the environment in full. It may now only set database connection
  settings; `load_dotenv(path)` with an explicit path still loads everything.
- **Database credentials in the environment switched SQL telemetry on** (and crashed startup under
  the default backend), and the DSN was copied into `logging_sql.token`. The SQL sink is now
  enabled only by `logging_sql.enabled = true`.
- **A broken `lionlock.toml` was silently ignored**, dropping token auth, failsafe and custom
  thresholds back to defaults. It now raises.
- **`TrustVaultLogger` could fork its chain under concurrent writers**, and a damaged last line
  silently restarted the chain. Appends are now locked, the head is read from the end of the file,
  and a damaged last entry stops writes. `head()` plus `verify_chain(expected_head=,
  expected_count=)` detect truncation and rewrites, which the chain alone cannot.
- **The Trust Overlay table name was put into SQL unchecked.** It must now be a plain identifier.
- **Resending the same upload bypassed the receiver's rate limit**, and a full rate table reset
  every client's budget. Duplicates now count, and only stale buckets are evicted.
- **`evaluate_policy` ignored configured signal weights** while the logged `config_hash` claimed
  they applied. It now takes `weights` and `enabled_signals`, and the quickstart passes them.
- The SQL privacy scrubber now refuses `content`, `completion`, `tool_calls` and the other raw-text
  keys the event log already refused.
- Per-event SQL telemetry no longer rebuilds the token verifier (and its database connection) or
  re-reads `.env` for every event.

### Compatibility

- The database host and port no longer fall back to the generic `HOST` and `PORT` variables; set
  `LIONLOCK_DB_HOST` / `LIONLOCK_DB_PORT` (or the `LIONLOCK_TELEMETRY_DB_*` forms).
- Deployments that relied on environment credentials alone to turn on SQL telemetry must set
  `logging_sql.enabled = true` (and `logging.backend = "sql"` or `"both"`).
- Settings other than database connection settings must come from the real environment or an
  explicit `load_dotenv(path)`, not from an implicitly found `.env`.
- Calling the LLM connector with an API key over plain http to a non-local host now fails with
  `insecure_endpoint_for_api_key`; use https.
- A `TrustVaultLogger` file whose last line is damaged must be inspected (and repaired) before new
  entries can be written.

## 1.0.0b2 — security and data-preservation fixes

Recommended for everyone on `1.0.0b1`. That release was published before everything below, so an
install pinned to it still fails open on the three settings in the first group.

**If you use the opt-in `sqlite:///...` telemetry sink with a customized schema, read the
Compatibility note before upgrading.**

### Fixed

- **The opt-in SQL telemetry sink could destroy existing tables on initialization.** The native
  `sqlite:///...` path rebuilt its tables, dropping and recreating them. Initialization now checks
  the existing `lionlock_sessions`, `lionlock_signals` and `lionlock_failsafe` objects against
  their roles first and **never rebuilds, drops or renames a table**. A keyed table missing
  `auth_token_id` and `auth_signature` is upgraded by adding those two nullable columns, preserving
  existing rows and keys, and a leftover `lionlock_signals_v2` is left untouched. The guard covers
  the native `sqlite:///...` path only; SQLAlchemy URI forms such as `sqlite+pysqlite:///...`,
  PostgreSQL and the Trust Overlay initializers are unchanged.
- **Uploads could switch themselves on.** `telemetry_upload.enabled` went through `bool()`, so a
  quoted `"false"`, `"no"`, `"0"` or `"off"` in a config file enabled uploads. Only a real boolean
  or a recognised true word enables them now; anything else leaves them off.
- **Pruning could switch itself off.** A negative `sqlite_max_rows` collapsed to `0`, which means
  "keep every row". `LogStore` now rejects a negative limit and `open_store` falls back to the
  default.
- **A receiver's upload rate limit could be reset at will.** In token mode the limit counts per
  token, so rotating an install id no longer clears it. Anonymous mode can only count per
  client-chosen install id, which is bypassable by design: require tokens on any internet-facing
  endpoint.
- `decide_gate` declares all five inputs it is missing for a metadata-free payload, not only the
  three fatigue inputs. Decisions themselves are unchanged.
- The README's quick-start example now runs as written, and the claim that logging happens
  automatically is corrected.

### Added

- An agent-agnostic development harness. `make verify` is one gate over tests, lint, type checks,
  determinism, privacy and file scope, and it behaves identically for every contributor.
- A runtime check that scoring and gating reach no network, rather than only a claim that they do
  not: the scoring path is imported in a child process with the socket layer patched, and the
  third-party compiled extensions it loads are pinned so that a new binary fails a test instead of
  arriving unnoticed.
- CI refuses an unapproved change to the harness contract lock, so a change cannot edit a protected
  file and then re-bless itself by regenerating the lock.
- Releases are built and uploaded by GitHub Actions through PyPI Trusted Publishing, so no API
  token has to be stored.

### Changed

- Two claims about the no-network guarantee were stronger than the evidence and have been narrowed
  to what is actually proved. Parsing imports cannot see a module reaching the network through a
  dependency it never names, and a third-party compiled extension *is* loaded on the scoring path
  (`pydantic_core`), which name-based audits cannot speak to either way. Both gaps are now stated
  as open, and the extension surface is pinned by a test.

### Compatibility

- **On the native `sqlite:///...` path, extra custom columns on a telemetry table are now
  refused**, even where named-column inserts worked before. This can turn startup into a
  `RuntimeError` through `get_writer`. Review customized schemas and take a backup before
  upgrading: initialization will not remove columns or their data to make a schema fit, and
  unknown layouts need a separately reviewed manual migration. SQLAlchemy URI forms such as
  `sqlite+pysqlite:///...`, PostgreSQL and the Trust Overlay initializers are unaffected.
- Receivers admit `1.0.0b2` as a public version label. **Upgrade a receiver before its clients**,
  because an older receiver rejects snapshots that carry the new label.

## 1.0.0b1 — first public beta

The first public beta of open-source LionLock. Interfaces may still change before 1.0.0.

- Local, hash-chained SQLite telemetry log, with opt-in uploads of allowlisted, pseudonymized
  fields to a receiver you run (`lionlock-telemetry`).
- Reference ingest server that validates every upload as untrusted input and stores only
  rebuilt, validated snapshots.
- `lionlock-telemetry bigquery-sync`: copies the receiver's warehouse into BigQuery. Each
  `events` and `trust_records` row is loaded exactly once, and `uploads` is replaced as a
  snapshot whenever it changes.
- `low_conf_halluc` no longer flags grounded answers, and the uncalibrated `fatigue_risk_index`
  no longer gates when its inputs are missing (signal schema `SE-0.4.0`).
- Receivers admit `1.0.0b1` as a public version label. Upgrade a receiver before its clients,
  because an older receiver rejects snapshots that carry the new label.

## 0.1.0

Initial open-source preview.
