# LionLock FDE – Pre-Beta Public Release

**LionLock_FDE** is a modular **Fatigue Detection Engine** and **Trust Telemetry System** for LLMs.

It’s designed to detect signal drift, block hallucinated output, and log behavioral metadata to a secure, token-authenticated PostgreSQL backend — **out of the box**.

This is the **Open Source Public Preview** of LionLock, suitable for developers, researchers, and AI safety teams. No premium modules or proprietary datasets are included.

---

## 🔍 Modules Included

### ✅ Module 01 – Trust Overlay
Captures inbound signal data. Sends telemetry to PostgreSQL using a **token-based login system**. Auto-connects on launch — no setup needed.

### ✅ Module 02 – Signal Scoring Engine
Normalizes session signals. Flags low-confidence or inconsistent prompt structure.

### ✅ Module 03 – Drift & Fatigue Anomaly Detection
Detects hallucination markers, entropy spikes, and output degradation over time.

### ✅ Module 04 – SQL Telemetry Logging
Backed by PostgreSQL. Supports opt-in logging, test flags, and downstream replay.

### ✅ Module 05 – Gating Core & Policy Engine
Computes deterministic gate decisions from trust signals; enforcement vs log-only behavior is controlled by `gating.enabled` / `LIONLOCK_GATING_ENABLED`.

### ✅ Module 06 – Replay Evaluation Layer
Processes saved sessions to check missed signals, drift accumulation, and gate performance.

### ✅ Module 07 – Simulation Harness
Stress-tests policies across multiple profiles and gating thresholds.

---

## 🚀 Get Started

```bash
git clone https://github.com/truthseeker/LionLock_FDE_OSS.git
cd LionLock_FDE_OSS
bash tools/dev_setup.sh
