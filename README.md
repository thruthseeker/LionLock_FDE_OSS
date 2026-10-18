# LionLock FDE – Public Beta (1.0.0b1)

**LionLock_FDE** scores LLM replies with fixed, deterministic rules and turns those scores into a gate decision. It also provides a tamper-evident local log to record those decisions in.

No AI model is involved in scoring or deciding: the same input always gives the same output. This is the **first public beta** of open-source LionLock (version `1.0.0b1`), suitable for developers, researchers, and AI safety teams. Interfaces may change before 1.0.0. No premium modules or proprietary datasets are included.

---

## What it does, and what it doesn't

- **Scores** a prompt and reply with lexical heuristics: repetition, low novelty, sentence structure, and drift from the prompt's words.
- **Decides** a severity band (green, yellow, orange, red) and a suggested action (`ALLOW`, `REFRESH`, `BLOCK`), with the signal and reason that triggered it.
- **Logs** decisions you record to a local, hash-chained SQLite file you can verify. Scoring and deciding do not write the log themselves; [`examples/quickstart.py`](examples/quickstart.py) shows the logging calls.

LionLock **does not stop a model call by itself**: it returns a decision, and your code acts on it (see [`docs/GATING_POLICY.md`](docs/GATING_POLICY.md)). Its signals are text heuristics, not fact-checking: they catch loops and some structural problems but can miss a fluent, off-topic answer, and no accuracy figures have been published yet. The fatigue score is uncalibrated and never raises a decision on its own when its inputs are missing.

---

## 🔍 Modules Included

### ✅ Module 01 – Trust Overlay
Captures inbound signal data and emits trust records for analysis. Trust Overlay supports SQL sinks when configured; default behavior uses local file/JSONL logging.

### ✅ Module 02 – Signal Scoring Engine
Computes deterministic signal scores from a prompt and response: repetition, novelty, sentence structure, and context adherence.

### ✅ Module 03 – Drift & Fatigue Anomaly Detection
Flags score patterns across turns, such as rising risk and decisions that disagree with their severity. The fatigue risk index is experimental and uncalibrated.

### ✅ Module 04 – Telemetry Logging
Logs decisions and trust records to a local, hash-chained SQLite file by default. Opt-in uploads send only allowlisted, pseudonymized fields to a receiver you run. SQL-backed telemetry remains available when explicitly enabled in config.

### ✅ Module 05 – Gating Core & Policy Engine
Computes deterministic gate decisions from trust signals. `gating.enabled` / `LIONLOCK_GATING_ENABLED` switches between suggested actions and log-only (`ALLOW`); acting on the decision is up to the caller.

### ✅ Module 06 – Replay Evaluation Layer
Re-evaluates logged decisions under a chosen policy to check missed signals, drift accumulation, and gate performance.

### ✅ Module 07 – Simulation Harness
Stress-tests policies across multiple profiles and gating thresholds.

---

## 🚀 Get Started

Install the library and the `lionlock-telemetry` and `lionlock-sim` commands from PyPI:

```bash
pip install lionlock==1.0.0b1
```

```python
from lionlock.core.scoring import score_response
from lionlock.core.gating import evaluate_policy

prompt = "What is the capital of France?"
reply = "The capital of France is Paris."

decision = evaluate_policy(score_response(prompt, reply))
print(decision.severity, decision.gating_decision, decision.reason_code)
```

For the quickstart with sample sessions, the tests, and the developer tools, clone the repository:

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

---

## 🤝 Contributing and security

See [`docs/CONTRIBUTING.md`](docs/CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [`docs/SECURITY.md`](docs/SECURITY.md).

## License

Apache License 2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
