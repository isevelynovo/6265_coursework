# Zero-Trust Data Gateway

A role-aware, policy-driven data governance platform built with Python and Streamlit. The system enforces zero-trust access control over sensitive datasets by combining attribute-based policies, k-anonymity suppression, differential privacy, and a cryptographically chained audit trail.

---
## Team Contributions

| Member | Contributions |
|--------|--------------|
| Wenlin Zhan | Conceived the project and designed the overall zero-trust architecture. Built the core gateway engine (column-level policy enforcement, k-anonymity, differential privacy), data discovery & cataloguing module, consumer portal, and compliance audit dashboard. Led system integration and the navigation UI refactor. |
| Xinyuan Yu | Designed and implemented the user authentication system (PBKDF2-SHA256, RBAC, permission groups) and the tamper-evident audit log (hash-chained append-only log with chain integrity verification). Co-authored the project report. |
| Zihan Dong | Designed and implemented the Policy Analyzer & Conflict Detection module (dead rule detection, coverage gap analysis, audit chain verifier, role access matrix, policy dry-run diff). Set up the Docker deployment environment. Co-authored the project report. |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                   Streamlit Frontend                    │
│  Data Discovery │ Gateway │ Portal │ Audit │ Analyzer  │
└────────────────────────┬────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
  auth_manager     gateway_engine   policy_analyzer
  (RBAC + auth)   (masking + DP)   (static analysis)
         │               │
         └───────┬───────┘
                 ▼
          shared_data/
    policy.json · data_catalog.json
    audit.log   · users.json
```

The entire application runs as a **single unified service** at `http://localhost:8501`. All modules share state through the `shared_data/` directory, which is mounted as a Docker volume for persistence.

---

## Features

### 1. Data Discovery & Metadata Tagging
Upload any CSV dataset and tag each column with an ontology label. The system auto-profiles column names and proposes tags. Tags drive all downstream access decisions.

| Tag | Meaning |
|-----|---------|
| `PII_Strong` | Direct identifiers (name, email, ID) |
| `Quasi_PII_Age` | Age or date of birth |
| `Quasi_PII_Location` | ZIP code, city, region |
| `Financial` | Salary, revenue, balance |
| `Sensitive_Medical` | Health conditions, diagnoses |
| `Public` | Non-sensitive operational data |

### 2. Zero-Trust Gateway Execution
Every data access request is evaluated against a role-specific policy before any data is returned. The gateway supports two query modes:

- **Raw mode** — per-column masking with configurable algorithms
- **Aggregated mode** — statistical enclave with micro-group suppression

**Masking algorithms available:**

| Algorithm | Description |
|-----------|-------------|
| `redact` | Replace all characters with `*` |
| `hash_string` | SHA-256 prefix hash |
| `mask_string_tail` | Keep N leading characters, mask the rest |
| `generalize_numeric` | Bin into ranges (e.g. `30s`, `40s`) |
| `laplace_noise` | Differentially private additive noise |

**Privacy mechanisms applied after masking:**
- **K-Anonymity** — suppresses rows where the quasi-identifier equivalence class is smaller than the configured threshold `k`
- **Differential Privacy** — Laplace mechanism with configurable privacy budget ε

### 3. Consumer Portal
Authenticated end-users request data under their assigned role and declared access purpose. The gateway selects the query mode automatically based on the declared purpose. All requests are logged to the audit trail.

### 4. Compliance Audit Dashboard
Every gateway execution is written to an append-only, cryptographically chained audit log. Each entry stores:
- SHA-256 hash of the entry content
- `prev_hash` linking to the previous entry
- Authenticated username, role, purpose, and full execution trace

The dashboard displays security trend metrics and the full live audit trail.

### 5. Policy Analyzer & Conflict Detection
Static analysis engine that scans the active policy, data catalog, and audit log without modifying any live state. Five independent detectors run in parallel:

| Detector | What it finds |
|----------|--------------|
| `DeadRuleDetector` | Rules referencing tags no column currently carries |
| `CoverageGapDetector` | (role, tag) pairs with no explicit rule — silent drops or implicit allows |
| `AlgorithmCompatibilityChecker` | Masking algorithm applied to an incompatible column dtype |
| `PolicyCatalogDriftDetector` | Tag changes since the column was last queried in the audit log |
| `AuditChainVerifier` | Hash chain breaks, unexpected resets, and tampered entries |

Also provides:
- **Role Access Matrix** — shows `ALLOW / MASK[algo] / DROP` for every (role, column) pair under the live policy
- **Policy Dry-Run / Diff** — paste a candidate policy JSON and preview every access change before saving, classified as `STRICTER / LOOSER / ALGO/PARAM`

### 6. System Management
Administrators can manage users, roles, and permission groups through the UI without restarting the application.

---

## Default Accounts

| Username | Password | Role | Permission Group |
|----------|----------|------|-----------------|
| `admin` | `admin123` | Administrator | System_Administrators |
| `analyst` | `analyst123` | General_Analyst | Data_Consumers |
| `staff` | `staff123` | Professional_Staff | Data_Consumers |
| `auditor` | `auditor123` | External_Auditor | Compliance_Auditors |

---

## Running the Application

### Option A — Local Python

**Requirements:** Python 3.11+

```bash
pip install -r requirements.txt
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

---

### Option B — Docker (Recommended)

**Requirements:** Docker Desktop installed and running. No Python installation needed on the host.

**Step 1: Build and start**

```bash
docker compose up --build
```

**Step 2: Open the application**

```
http://localhost:8501
```

**Step 3: Stop**

```bash
docker compose down
```

Data persisted during the session (uploaded datasets, policy changes, audit logs, user accounts) is stored in `shared_data/` on your host machine via the Docker volume mount and survives container restarts.

---

## Project File Structure

```
.
├── app.py                  # Main Streamlit application (unified, role-gated)
├── gateway_engine.py       # Core masking, DP, k-anonymity, and audit engine
├── auth_manager.py         # Authentication, RBAC, and user management
├── policy_analyzer.py      # Static policy analysis and conflict detection
├── app_portal.py           # Legacy standalone consumer portal (optional)
├── test_analyzer.py        # CLI smoke test for the policy analyzer
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container image definition
├── docker-compose.yml      # Single-service orchestration
└── shared_data/            # Runtime data directory (auto-created on first run)
    ├── users.json          # Hashed user credentials
    ├── role_permissions.json
    ├── policy.json         # Active access policy
    ├── data_catalog.json   # Column tag metadata
    ├── shared_data.csv     # Last uploaded dataset
    └── audit.log           # Append-only cryptographic audit log
```

---

## CLI Smoke Test

To validate the policy analyzer without the UI:

```bash
python test_analyzer.py
```

Reads `shared_data/policy.json`, `shared_data/data_catalog.json`, and `shared_data/audit.log` and prints the full analysis report to the terminal. Useful after manually editing the policy file.

---

## Technical Notes

**Audit log integrity** — The hash chain uses SHA-256 over the canonical JSON serialisation (sorted keys, no whitespace) of each entry concatenated with the previous entry's hash. The verifier in `policy_analyzer.py` recomputes every hash independently; any mismatch is reported as `CRITICAL`.

**Streamlit compatibility** — Requires Streamlit ≥ 1.40. The deprecated `width="stretch"` parameter has been replaced throughout with `use_container_width=True`.

**Thread safety** — Audit log writes are dispatched to a daemon thread so they do not block the gateway response. The append-only write pattern relies on OS-level atomic appends for consistency.
