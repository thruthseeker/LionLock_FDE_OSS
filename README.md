# LionLock FDE – Public Beta (1.0.0b1)

**LionLock_FDE** is a modular **Fatigue Detection Engine** and **Trust Telemetry System** for LLMs.

It’s designed to detect signal drift, compute deterministic gate decisions, and log behavioral metadata for downstream analysis.

This is the **first public beta** of open-source LionLock (version `1.0.0b1`), suitable for developers, researchers, and AI safety teams. No premium modules or proprietary datasets are included.

---

## 🔍 Modules Included

### ✅ Module 01 – Trust Overlay
Captures inbound signal data and emits trust records for analysis. Trust Overlay supports SQL sinks when configured; default behavior uses local file/JSONL logging.

### ✅ Module 02 – Signal Scoring Engine
Normalizes session signals. Flags low-confidence or inconsistent prompt structure.

### ✅ Module 03 – Drift & Fatigue Anomaly Detection
Detects hallucination markers, entropy spikes, and output degradation over time.

### ✅ Module 04 – Telemetry Logging
Logs decisions and trust records to a local, hash-chained SQLite file by default. Opt-in uploads send only allowlisted, pseudonymized fields to a receiver you run. SQL-backed telemetry remains available when explicitly enabled in config.

### ✅ Module 05 – Gating Core & Policy Engine
Computes deterministic gate decisions from trust signals; enforcement vs log-only behavior is controlled by `gating.enabled` / `LIONLOCK_GATING_ENABLED`.

### ✅ Module 06 – Replay Evaluation Layer
Processes saved sessions to check missed signals, drift accumulation, and gate performance.

### ✅ Module 07 – Simulation Harness
Stress-tests policies across multiple profiles and gating thresholds.

---

## 🚀 Get Started

```bash
git clone https://github.com/thruthseeker/LionLock_FDE_OSS.git
cd LionLock_FDE_OSS
bash tools/dev_setup.sh
```


Config templates: [`lionlock.toml.example`](lionlock.toml.example) and [`.env.example`](.env.example).

Five-minute walkthrough: [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

Audit log details: [`docs/AUDIT_LOGGING.md`](docs/AUDIT_LOGGING.md).

---

## 📡 Telemetry

LionLock writes its telemetry to one local SQLite file, `logs/lionlock.db`, and **uploads nothing unless you opt in**. If you enable uploads, only the allowlisted, pseudonymized fields documented in [`docs/TELEMETRY.md`](docs/TELEMETRY.md) are sent, over HTTPS, to a receiver you run. Prompts, responses, raw identifiers, and hostnames are never included, and `DO_NOT_TRACK=1` turns uploads off.

```bash
lionlock-telemetry status    # where the log is and whether uploads are enabled
lionlock-telemetry preview   # exactly what an upload would contain, without sending it
```
