# LionLock FDE – Pre-Beta Public Release

**LionLock_FDE** is a modular **Fatigue Detection Engine** and **Trust Telemetry System** for LLMs.

It’s designed to detect signal drift, compute deterministic gate decisions, and log behavioral metadata for downstream analysis.

This is the **Open Source Public Preview** of LionLock, suitable for developers, researchers, and AI safety teams. No premium modules or proprietary datasets are included.

---

## 🔍 Modules Included

### ✅ Module 01 – Trust Overlay
Captures inbound signal data and emits trust records for analysis. Trust Overlay supports SQL sinks when configured; default behavior uses local file/JSONL logging.

### ✅ Module 02 – Signal Scoring Engine
Normalizes session signals. Flags low-confidence or inconsistent prompt structure.

### ✅ Module 03 – Drift & Fatigue Anomaly Detection
Detects hallucination markers, entropy spikes, and output degradation over time.

### ✅ Module 04 – SQL Telemetry Logging
Supports SQL-backed telemetry when explicitly enabled in config.

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

Audit log details: [`docs/AUDIT_LOGGING.md`](docs/AUDIT_LOGGING.md).
