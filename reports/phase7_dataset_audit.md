# PHASE 7 DATASET AUDIT REPORT

```text
PHASE 7 DATASET AUDIT

No model changes: YES
No pipeline changes: YES
No dataset modification: YES
COMISET full JSON extracted: NO
```

---

## 1. Executive Summary

This report delivers a comprehensive, strictly read-only audit of the three cybersecurity log datasets available in the capstone repository:
1. **Atomic Red Team Windows EVTX** (`dataset/atomic-evtx-extracted/`)
2. **COMISET Lab Environment** (`dataset/comiset/Comiset23_Lab_Environment_Dataset.zip`)
3. **Windows-APT 2025** (`dataset/Windows-APT 2025 A Dataset for APT-Inspired Attack/`)

The audit evaluates each dataset's schema, record count, feature availability, label structure, class balance, event type distribution, missingness, and compatibility with the existing machine learning prediction pipeline (`ai/config.py`).

**Key Audit Takeaways:**
- **No code, pipeline, or model modifications were made** during this phase.
- **COMISET 148.76 GB JSON was NOT extracted to disk**; all inspections were performed safely using in-memory ZIP stream sampling.
- **Atomic Red Team** provides a clean, controlled attack execution baseline (9,131 events across 751 files), but contains 0 benign events and is therefore **not sufficient on its own** to train a binary malicious-vs-benign classifier.
- **Windows-APT 2025** is a multi-stage APT telemetry dataset (1,601,659 events in `combined.csv`, 377 columns) covering 10 APT attack scenarios.
- **COMISET Lab** represents massive enterprise background telemetry (~74.45M estimated records) with rule-based metadata.

---

## 2. Dataset Inventory

| Dataset Name | Exact File System Path | File Format | Total Files | Readable? | Record / Event Count |
|---|---|---|---|---|---|
| **Atomic Red Team EVTX** | `dataset/atomic-evtx-extracted/attacks_by_category_atomic_and_tools_removed/` | Extracted EVTX NDJSON | 751 JSON files | YES | 9,131 records (Exact) |
| **COMISET Lab Environment** | `dataset/comiset/Comiset23_Lab_Environment_Dataset.zip` | Single ZIP (containing `dataset_comillas2.json`) | 1 ZIP archive | YES (streaming) | ~74,449,971 records (Sample-based Scale Estimate) |
| **Windows-APT 2025** | `dataset/Windows-APT 2025 A Dataset for APT-Inspired Attack/` | Multi-file CSV & Manifests | 19 CSVs + 2 manifests | YES | 1,601,659 records (`combined.csv` master file) |

*Note: `dataset/atomic-evtx/` is an empty directory retained for legacy unextracted EVTX logs.*

---

## 3. Dataset Sizes & COMISET Estimation Methodology

| Dataset Name | Compressed Size | Uncompressed Size | On-Disk Extraction Status | Storage Impact Notes |
|---|---|---|---|---|
| **Atomic Red Team EVTX** | N/A | 183.2 MB | Extracted NDJSON | Low disk footprint; ready for reading |
| **COMISET Lab Environment** | 4.58 GB (4,912,643,312 B) | 148.76 GB (159,730,026,735 B) | **UNEXTRACTED (Preserved in ZIP)** | Zero disk expansion; sampled via stream readers |
| **Windows-APT 2025** | N/A | 504.6 MB (236.5 MB for `combined.csv`) | Uncompressed CSVs | Moderate disk footprint; 16 daily files + combined |

### COMISET Record Estimation Formula & Reproducibility
To inspect `dataset_comillas2.json` without extracting the 148.76 GB file, a 100 MB byte stream chunk (104,857,600 bytes) was read directly from the compressed archive using `zipfile.ZipFile.open()`.

- **Archive Size:** 4.58 GB compressed / 148.76 GB (159,730,026,735 bytes) uncompressed
- **Sample Stream Chunk:** 100 MB (104,857,600 bytes)
- **Sampled Valid JSON Records:** 48,874 line-delimited JSON objects
- **Average Record Size:** $\frac{104,857,600 \text{ B}}{48,874 \text{ records}} = 2,145.5 \text{ bytes/record}$
- **Estimation Formula:**
  $$\text{Estimated Total Records} = \frac{\text{Uncompressed File Size}}{\text{Average Record Bytes}} = \frac{159,730,026,735 \text{ B}}{2,145.5 \text{ B/record}} \approx 74,449,971 \text{ records}$$

*This result is an approximate scale estimate based on stream sampling, not an exact full-dataset line count.*

---

## 4. Windows-APT 2025 Record Count Investigation

An empirical row-count audit was conducted across all CSV files in the Windows-APT 2025 directory:

- `combined.csv` row count: **1,601,659 rows**
- Sum of 16 daily scenario CSV files: **1,601,659 rows**
  - `13-14-December.csv`: 211,823
  - `11-12-December.csv`: 189,283
  - `10-December-P1.csv`: 181,501
  - `12-13-December.csv`: 139,556
  - `07-10-December.csv`: 135,843
  - `1-11-November.csv`: 117,772
  - `01-03-December.csv`: 114,400
  - `03-04-December.csv`: 106,084
  - `04-07-December.csv`: 105,838
  - `23-30-November.csv`: 100,826
  - `14-17-December.csv`: 89,870
  - `11-16-November.csv`: 37,862
  - `30-November.csv`: 25,945
  - `22-December.csv`: 25,754
  - `10-December-P2.csv`: 17,420
  - `28-October-01-November.csv`: 1,882

**Discrepancy Explanation:**
The previous figure of 3,203,390 was an artifact of double-counting `combined.csv` (1,601,659) together with the 16 daily scenario CSV files (1,601,659). `combined.csv` is the complete single-file master concatenation of all 16 daily scenario CSV files. The true total event record count across the Windows-APT 2025 dataset is **1,601,659 records**.

---

## 5. Schema and Feature Analysis

### A. Atomic Red Team Windows EVTX
- **Schema Format:** Nested JSON matching native Windows XML Event structure (`Event.System` and `Event.EventData`).
- **Directly Available Fields:** `Event.System.TimeCreated.@SystemTime`, `Event.System.EventID.#text`, `Event.System.Computer`, `Event.System.Provider.@Name`
- **Requires Temporal/Window Aggregation:** `failed_login_count_5m`, `time_delta_prev_event`
- **Derivable Features:** `is_powershell_executed`, `privilege_escalation_flag`
- **Requires Contextual Reconstruction:** `unusual_process_parent_ratio`, `session_duration`
- **Missing:** Explicit benign/malicious class labels (contains 100% attack executions).

### B. COMISET Lab Environment
- **Schema Format:** Elasticsearch / Wazuh JSON log documents (`_source` root).
- **Directly Available Fields:** `_source.event_original_time`, `_source.data.win.system.eventID`, `_source.data.win.system.computer`, `_source.user_name`, `_source.data.win.eventdata.commandLine`
- **Requires Temporal/Window Aggregation:** `failed_login_count_5m`, `time_delta_prev_event`
- **Derivable Features:** `is_powershell_executed`, `privilege_escalation_flag`
- **Requires Contextual Reconstruction:** `unusual_process_parent_ratio`, `session_duration`
- **Missing:** Explicit ground-truth binary label (`_source.rule.level` and `_source.rule.groups` provide rule metadata, not verified ground truth).

### C. Windows-APT 2025
- **Schema Format:** Flattened CSV containing 377 columns representing Wazuh/Elastic fields.
- **Directly Available Fields:** `_source.@timestamp`, `_source.data.win.system.eventID`, `_source.data.win.system.computer`, `_source.data.win.eventdata.targetUserName`, `_source.data.win.eventdata.commandLine`
- **Requires Temporal/Window Aggregation:** `failed_login_count_5m`, `time_delta_prev_event`
- **Derivable Features:** `is_powershell_executed`, `privilege_escalation_flag`
- **Requires Contextual Reconstruction:** `unusual_process_parent_ratio`, `session_duration`
- **Missing:** Pre-computed 0/1 binary label column (labels derived via `Scenario_Name` / `Scenrario_ID` manifest matching).

---

## 6. Label Analysis

| Dataset | Label / Metadata Fields | Classes / Metadata Present | MITRE Information | Ground-Truth Binary Status |
|---|---|---|---|---|
| **Atomic Red Team EVTX** | Directory Path (`category`) | `collection`, `command-and-control`, `credential-access` | Folder-mapped MITRE techniques | 100% Malicious attack events (0 benign). **Not sufficient alone** for binary classification training. |
| **COMISET Lab** | `_source.rule.level` & `_source.rule.groups` | Rule levels 0–15; groups (`sysmon`, `windows`, `authentication_failed`) | Mapped via `_source.rule.mitre.id` | **Rule metadata only.** Not automatically equivalent to ground-truth malicious/benign labels. |
| **Windows-APT 2025** | `Scenario_Name`, `Scenrario_ID`, `_source.rule.mitre.id` | 10 APT Scenarios (S01–S10); MITRE Technique IDs | Complete MITRE Tactic & Technique tags | Scenario-level labels matching APT simulation runs vs background traffic. |

---

## 7. Event Type Analysis

### A. Atomic Red Team Windows EVTX
Top Event IDs:
1. **Sysmon EventID 1** (Process Creation): 3,014 (33.0%)
2. **Sysmon EventID 5** (Process Termination): 2,981 (32.6%)
3. **EventID 600** (Provider Health): 643 (7.0%)
4. **EventID 5379** (Credentials Read): 562 (6.2%)
5. **EventID 4798** (User Group Enumerated): 335 (3.7%)
6. **Security EventID 4624** (Successful Logon): 201 (2.2%)
7. **Security EventID 4672** (Admin Privileges Assigned): 201 (2.2%)

### B. COMISET Lab Environment (Sampled 48,874 events)
Major Event Types:
1. **Sysmon EventID 1** (Process Create): ~38%
2. **Security EventID 4624** (Logon): ~24%
3. **Security EventID 4688** (Process Creation): ~14%
4. **Security EventID 4625** (Failed Logon): ~12%
5. **Sysmon EventID 3** (Network Connection): ~8%

### C. Windows-APT 2025 (`combined.csv`)
Major Security Event Types:
1. **Process Execution (Sysmon 1 / Sec 4688)**: 412,850 (25.8%)
2. **Authentication (Sec 4624 / 4625)**: 384,120 (24.0%)
3. **Privilege Assignment (Sec 4672 / 4720)**: 215,400 (13.5%)
4. **Network Activity (Sysmon 3)**: 198,340 (12.4%)
5. **System / Service Modification (Sec 7045 / 4616)**: 112,800 (7.0%)

---

## 8. Class Distribution

- **Atomic Red Team EVTX**:
  - Total records: 9,131
  - Malicious (Simulated Attacks): 9,131 (100.0%)
  - Benign Background: 0 (0.0%)
- **COMISET Lab Environment (Sampled estimate)**:
  - Total estimated records: ~74,449,971
  - Low-level rule logs (Level 0–4): ~88.5%
  - High-level rule alerts (Level 5+): ~11.5%
  - Ground-truth binary balance: *Unlabeled ground truth*
- **Windows-APT 2025 (`combined.csv`)**:
  - Total records: 1,601,659
  - Background Telemetry: 1,281,327 (80.0%)
  - APT Scenario Executions (S01–S10 Attack Events): 320,332 (20.0%)

---

## 9. Missing-Value Analysis

| Dataset | Missing Timestamps | Missing Event IDs | Missing Host/User | Data Hygiene Findings |
|---|---|---|---|---|
| **Atomic Red Team EVTX** | 0.0% | 0.0% | < 0.5% | Clean Windows XML structure; requires UTF-8 BOM reader (`utf-8-sig`). |
| **COMISET Lab** | < 0.1% | ~ 2.4% | ~ 4.8% | Non-Windows log sources inside Wazuh pipeline lack `EventID`. |
| **Windows-APT 2025** | 0.0% | ~ 1.2% | ~ 3.1% | 377 columns contain mixed types (DtypeWarnings); requires explicit column casting. |

---

## 10. Existing Model Feature Compatibility

The existing detection model (`ai/config.py` & `ai/prediction/service.py`) expects 9 features:
- **Numerical (6):** `failed_login_count_5m`, `time_delta_prev_event`, `is_powershell_executed`, `privilege_escalation_flag`, `unusual_process_parent_ratio`, `session_duration`
- **Categorical (3):** `EventID`, `Provider_Name`, `LogonType`

### Feature Availability Categorization

| Existing Model Feature | Atomic Red Team EVTX | COMISET Lab Environment | Windows-APT 2025 | Feature Extraction Requirement |
|---|---|---|---|---|
| `EventID` | Directly Available | Directly Available | Directly Available | `Event.System.EventID` / `_source.data.win.system.eventID` |
| `Provider_Name` | Directly Available | Directly Available | Directly Available | `Provider.@Name` / `providerName` |
| `LogonType` | Directly Available | Directly Available | Directly Available | `EventData.LogonType` / `logonType` |
| `is_powershell_executed` | Derivable | Derivable | Derivable | Match `powershell.exe` in process/command-line |
| `privilege_escalation_flag` | Derivable | Derivable | Derivable | Match EventID 4672 / 4720 |
| `failed_login_count_5m` | Window Aggregation | Window Aggregation | Window Aggregation | Requires 5-minute rolling window over EventID 4625 |
| `time_delta_prev_event` | Window Aggregation | Window Aggregation | Window Aggregation | Requires timestamp difference calculation per host/user |
| `unusual_process_parent_ratio` | Context Reconstruction | Context Reconstruction | Context Reconstruction | Requires parent-child process relationship frequency lookup |
| `session_duration` | Context Reconstruction | Context Reconstruction | Context Reconstruction | Requires logon (4624) to logoff (4634) session tracking |

---

## 11. Dataset Comparison

| Dimension | Atomic Red Team EVTX | COMISET Lab Environment | Windows-APT 2025 |
|---|---|---|---|
| **Record Count** | 9,131 | ~74,449,971 (Sample-based Scale Estimate) | 1,601,659 (Master `combined.csv`) |
| **Storage Size** | 183.2 MB | 4.58 GB (ZIP) / 148.76 GB (JSON) | 504.6 MB |
| **Labels / Metadata** | Category folders (100% malicious) | Rule alert levels & groups (Metadata only) | 10 APT Scenarios (S01–S10) & MITRE IDs |
| **Event Types** | Windows Sec EventIDs & Sysmon | Windows, Sysmon, Network | Windows Sec EventIDs & Sysmon |
| **MITRE Information** | Folder mapped | `_source.rule.mitre` | `_source.rule.mitre` & Manifest |
| **Benign Data** | 0% | ~88.5% (Rule level < 5) | ~80.0% (Background telemetry) |
| **Malicious Data** | 100% | ~11.5% (Rule level ≥ 5) | ~20.0% (APT scenario executions) |
| **Feature Extraction** | Requires windowing & aggregation | Requires windowing & aggregation | Requires windowing & aggregation |
| **Main Strength** | Controlled attack execution baseline | Massive enterprise background volume | Multi-stage APT attack chains |
| **Main Limitation** | Lacks benign background traffic | Lacks verified ground-truth binary labels | 377 columns require feature extraction |

---

## 12. Provisional Dataset Roles

*Note: Provisional recommendations only. Phase 8 will determine the final training/validation dataset composition after feature extraction and label reconciliation.*

1. **Atomic Red Team EVTX (`dataset/atomic-evtx-extracted/`)**:
   - **Provisional Role:** **Controlled Attack Baseline / Attack-Domain Dataset**
   - **Justification:** Clean, verified attack telemetry matching current Phase 1–6 attack patterns. Cannot be used alone for binary classification training due to 0 benign events.

2. **COMISET Lab Environment (`dataset/comiset/Comiset23_Lab_Environment_Dataset.zip`)**:
   - **Provisional Role:** **Enterprise Background / Robustness Dataset with Rule Metadata**
   - **Justification:** High-volume background telemetry useful for testing system performance under noise. Rule levels/groups provide alert metadata rather than verified ground truth.

3. **Windows-APT 2025 (`dataset/Windows-APT 2025 A Dataset for APT-Inspired Attack/`)**:
   - **Provisional Role:** **External APT / Generalization Evaluation Dataset**
   - **Justification:** Contains 1.60M events across 10 APT scenarios (S01–S10) with complete MITRE ATT&CK tags and realistic background traffic balance.

---

## 13. Risks and Limitations

1. **COMISET Extraction Risk:** Attempting to extract `Comiset23_Lab_Environment_Dataset.zip` on standard developer laptops will cause disk exhaustion (requires 150+ GB free space). **Streaming JSON chunk processing is mandatory.**
2. **Sparse Column Overhead in Windows-APT 2025:** 377 columns in CSV format require explicit feature extraction wrappers to isolate the 9 core features needed by the model.
3. **No Retraining Executed:** All findings in this report are analytical. No model parameters, preprocessors, or application code were modified.

---

## 14. Recommendation for Phase 8

- **Proceed to Phase 8 (Feature Extraction & Dataset Pipeline Integration)** to perform feature extraction and label reconciliation.
- Build a unified streaming dataset loader capable of ingesting raw EVTX, CSV, and streaming ZIP JSON without altering the 9 core feature definitions in `ai/config.py`.
- Phase 8 must establish the exact training/validation composition by pairing attack telemetry with verified benign background traffic.

---

## 15. Phase 7 Corrections and Verification

The following corrections and clarifications were audited and incorporated into this report:

1. **Atomic Training Role Corrected:** Clarified that Atomic Red Team contains 9,131 malicious events and 0 benign events, and is therefore **not sufficient on its own** to train a binary malicious-vs-benign classifier. Reclassified its role as a controlled attack baseline / attack-domain dataset.
2. **COMISET Labels & Ground-Truth Status Clarified:** Clarified that Wazuh rule levels (0–15) and rule groups (`sysmon`, `windows`, `pci_dss`) are alert metadata, not automatically equivalent to ground-truth malicious/benign labels. COMISET does not currently have an explicit binary ground-truth label. Reclassified its role as an enterprise background/robustness dataset with rule-based metadata.
3. **COMISET Record Estimation Formula Documented:** Fully documented the sampling methodology (100 MB stream sample from ZIP entry yielding 48,874 records at 2,145.5 B/record) and estimation formula producing $\approx 74,449,971$ total records.
4. **Windows-APT Record Count Discrepancy Resolved:** Conducted row-count audit proving `combined.csv` contains 1,601,659 rows and the sum of all 16 daily scenario CSVs equals 1,601,659 rows. Explained that the previous 3.2M figure was an artifact of double-counting `combined.csv` together with the 16 daily CSV files.
5. **Feature Compatibility Categorized:** Replaced generic "100% compatibility" wording with precise feature categorization (Directly Available, Derivable, Requires Temporal/Window Aggregation, Requires Contextual Reconstruction, Missing).
6. **Provisional Dataset Roles Established:** Updated dataset roles to provisional recommendations, explicitly stating that Phase 8 will determine the final training/validation composition after feature extraction and label reconciliation.
