# Explainable AI-Based Real-Time Enterprise Windows Threat Detection & Investigation Dashboard

[![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Express.js](https://img.shields.io/badge/Express.js-4.x-000000?style=flat-square&logo=express&logoColor=white)](https://expressjs.com)
[![React](https://img.shields.io/badge/React-18.x-61DAFB?style=flat-square&logo=react&logoColor=black)](https://reactjs.org)
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg?style=flat-square)](LICENSE)

An end-to-end, enterprise-grade threat detection, investigation, and Explainable AI (XAI) security dashboard. The system ingests raw Windows Security Event Logs (`EVTX` / `JSON`), extracts **10 domain-informed behavioral features**, runs multi-model hybrid classification (XGBoost, Random Forest, Isolation Forest Anomaly Detection), translates TreeSHAP feature weights into natural language security reasoning via the **Security Intelligence Layer**, maps events to **MITRE ATT&CK tactics & techniques**, and computes dynamic host risk scores in real-time.

---

## 🌟 Primary Novelties & Features

### 1. Security Intelligence Layer (XAI to Human Security Reasoning)
Converts raw numerical SHAP attribution weights into actionable SOC playbooks, threat summaries, key evidence packages, and recommended mitigation actions without relying on black-box LLMs.

### 2. 10 Domain-Informed Behavioral Features
- `failed_login_count_5m`: Cumulative failed logons (EventID 4625) per 5-minute rolling window.
- `time_delta_prev_event`: Monotonic elapsed seconds from previous event on same host.
- `is_powershell_executed`: Detection flag for PowerShell, `pwsh`, encoded commands, Base64 payloads, and IEX.
- `privilege_escalation_flag`: Flag for EventIDs 4672, 4720, 4732.
- `unusual_process_parent_ratio`: Size-independent rarity score for parent-child process pairs normalized by `max_count`.
- `session_duration`: Elapsed session duration scoped per `[Computer, TargetUserName]`.
- `commandline_entropy`: Shannon entropy of command-line string (obfuscation/Base64 payload detector).
- `event_frequency_1h`: Host event frequency per 1-hour rolling window.
- `is_known_attack_eventid`: Ground-truth binary indicator for high-risk Windows security EventIDs.
- `process_name_entropy`: Shannon entropy of executable basename.

### 3. Multi-Model Hybrid Detection Engine
Combines supervised tree ensembles (XGBoost / Random Forest) with an unsupervised Isolation Forest anomaly detector.

### 4. Dynamic Host Risk Engine & MITRE ATT&CK Mapping
Real-time risk scoring (0–100 scale) based on event severity, threat tactic stage weights, tactic diversity multipliers, and rule/AI agreement corroboration.

### 5. 3-Agent Governance System (Coder → Supervisor → CEO)
Built-in multi-agent review architecture enforcing code quality, type annotations, Google docstrings, WDAC compatibility, unit test coverage, and git pre-commit quality gates.

---

## 📂 Expected Raw Dataset Directory Structure (`dataset/`)

If you are running the dataset ingestion and training pipeline from scratch, place your raw dataset files under the `dataset/` directory according to the following path structure:

```
dataset/
├── atomic-evtx-extracted/
│   └── attacks_by_category_atomic_and_tools_removed/   # EVTX JSON files by category
│       ├── Credential Access/
│       ├── Defense Evasion/
│       └── ...
├── Windows-APT 2025 A Dataset for APT-Inspired Attack/
│   └── combined.csv                                    # Windows-APT attack & background log CSV
└── comiset/
    └── Comiset23_Lab_Environment_Dataset/
        └── dataset_comillas2.json                      # Winlogbeat/ECS format COMISET JSON
```

---

## 🛠️ Data Pipeline & Research Script Execution

All pipeline scripts automatically create missing target directories (`data/processed/phase10_2/`, `ai/models/artifacts/`, `reports/diagrams/`) at runtime using `Path.mkdir(parents=True, exist_ok=True)`.

### Step-by-Step Pipeline Commands

```bash
# Step 1: Rebuild Unified Supervised Datasets (Atomic Red Team + Windows-APT)
.venv\Scripts\python.exe scratch/rebuild_phase10_2_unified.py
# → Output: data/processed/phase10_2/ (train.csv, val.csv, internal_test.csv, external_test_windows_apt.csv)

# Step 2: Stream COMISET Full Dataset Ingestion with Checkpointing
.venv\Scripts\python.exe scratch/ingest_comiset_full_corrected.py
# → Output: data/processed/phase10_2/comiset_chunks/ (chunk_*.parquet, checkpoint.json)

# Step 3: Train 5-Seed Candidate Models & Rebuild Artifacts
.venv\Scripts\python.exe scratch/execute_phase11_1_multiseed.py
# → Output: ai/models/artifacts/ (best_model.pkl, preprocessor.pkl, isolation_forest.pkl, seed_checkpoints/)
#           ai/models/artifacts/metrics/per_seed_metrics.csv

# Step 4: Run Anti-Overfitting & Stability Validation Suite
.venv\Scripts\python.exe scratch/validate_anti_overfit.py
# → Output: ai/models/artifacts/metrics/ (loo_importance.csv, cv_fold_scores.csv)

# Step 5: Generate 11 Publication-Ready Figures & Research Summary
.venv\Scripts\python.exe scratch/generate_research_diagrams.py
# → Output: reports/diagrams/ (fig1_confusion_matrix.png ... fig11_eventfreq_violin.png)
#           reports/research_paper_metrics_summary.json
```

---

## ⚡ Quickstart & Server Launch

### 1. Environment Setup

```bash
# Clone the repository
git clone https://github.com/khyati50/Capstone.git
cd Capstone

# Create and activate Python virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Install Backend dependencies
cd backend
npm install
cd ..

# Install Frontend dependencies
cd frontend
npm install
cd ..
```

### 2. Service Launch

```bash
# Terminal 1: Start FastAPI Microservice (Port 8000)
.venv\Scripts\python.exe -m uvicorn ai.server:app --port 8000 --reload

# Terminal 2: Start Node.js Express Gateway (Port 5000)
cd backend
npm run dev

# Terminal 3: Start React Dashboard UI (Port 5173)
cd frontend
npm run dev
```

---

## 🧪 Testing & Code Quality

```bash
# Run unit tests
.venv/Scripts/python.exe -m pytest ai/tests/ -v

# Run code formatting check
.venv/Scripts/python.exe -m black ai/ --check --line-length 120

# Run import ordering check
.venv/Scripts/python.exe -m isort ai/ --check-only

# Run flake8 linter
.venv/Scripts/python.exe -m flake8 ai/ --max-line-length=120
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Authors & Attribution

- **Primary Author:** `khyati50` ([khyatianand1134@gmail.com](mailto:khyatianand1134@gmail.com))
- **Co-Author:** `Samriddhi0112` ([motianisamriddhi2005@gmail.com](mailto:motianisamriddhi2005@gmail.com))
- **Co-Author:** `deshnaajainofficial` ([deshnaajainofficial@gmail.com](mailto:deshnaajainofficial@gmail.com))
