# Project Development Rules & Coding Standards

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat Detection and Investigation Dashboard
> **Repository:** [khyati50/Capstone](https://github.com/Samriddhi0112/Capstone)
> **Authors:** khyati50 (primary) · Samriddhi0112 · deshnaajainofficial

---

## 1. Architectural Principles

1. **Phase Compliance** — All code MUST conform to the 19 Phase specification documents in `docs/`.
2. **Unified Pipeline** — Live monitoring and simulation MUST use the exact same preprocessing → prediction → detection → explainability → correlation → risk calculation pipeline. No separate code paths.
3. **3-Tier Service Architecture**:
   | Service | Technology | Port |
   |---|---|---|
   | AI Prediction Engine | Python FastAPI + Uvicorn | 8000 |
   | REST API + WebSockets | Node.js + Express + Socket.IO | 5000 |
   | Database | MySQL 8.0 | 3306 |
   | Frontend Dashboard | Vite + React + Tailwind CSS | 5173 |
4. **3-Agent Governance** — All code changes follow the CEO → Supervisor → Coder workflow defined in `agent.md`.
5. **No Hardcoded Data** — No hardcoded mock events, static node arrays, or fake predictions anywhere in the pipeline.

---

## 2. Python Coding Standards

### 2.1 Environment
- Python 3.11 with local `.venv` (`.\venv\Scripts\activate`).
- All packages pinned in `requirements.txt`.

### 2.2 Code Style — ENFORCED by pre-commit hook
| Tool | Rule |
|---|---|
| `black` | Max line length: 120 characters |
| `flake8` | PEP 8 compliance, max-line-length=120 |
| `isort` | Import ordering: stdlib → third-party → local |
| `mypy` | Static type checking (non-blocking warnings) |

### 2.3 Type Annotations (REQUIRED)
Every function signature **must** include full Python type hints:
```python
# ✅ Correct
def process_event(event: Dict[str, Any]) -> Dict[str, Any]:
    ...

# ❌ Wrong
def process_event(event):
    ...
```

### 2.4 Docstrings (REQUIRED on all public functions, classes, modules)
Use Google-style docstrings:
```python
def calculate_risk_score(alert_object: Dict[str, Any], chain_length: int = 1) -> Dict[str, Any]:
    """Compute cumulative dynamic risk score (0-100).

    Args:
        alert_object: Alert output dictionary from Hybrid Detection Engine.
        chain_length: Number of correlated events in attack chain.

    Returns:
        Dictionary with numeric score, qualitative level, and breakdown.

    Raises:
        ValueError: If alert_object is missing required keys.
    """
```

### 2.5 Error Handling (REQUIRED)
- **No silent exceptions**: `except Exception: pass` is FORBIDDEN.
- All exception blocks MUST log the error with `logging.error()` or `logging.warning()`.
- File parsing errors MUST report filename + exception type.
```python
# ✅ Correct
except json.JSONDecodeError as exc:
    logger.error(f"Malformed JSON in {json_path.name}: {exc}")

# ❌ Wrong
except Exception:
    pass
```

### 2.6 WDAC Compatibility (MANDATORY)
- Pinned versions: `pandas==2.2.3`, `shap==0.43.0`, `numpy==1.26.4`
- No unauthorized native `.pyd` imports.
- Pure-Python stubs must be maintained for blocked helpers (`matplotlib._c_internal_utils`).

### 2.7 Label Generation
- Ground-truth labels MUST be generated **once during preprocessing** in `feature_engineering.py`.
- Training code MUST consume prepared `df['label']` — never create labels inside model training loops.

---

## 3. Node.js & Express Coding Standards

### 3.1 JavaScript Style
- ES6+ syntax only (`async/await`, arrow functions, destructuring, template literals).
- `const` by default, `let` only when reassignment is needed. Never `var`.
- Semicolons required at end of statements.

### 3.2 Express Architecture
- All routes in `backend/routes/` using `express.Router()`.
- All shared business logic in `backend/services/`.
- Centralized error handling via `backend/middleware/errorHandler.js`.
- All DB queries must use parameterized statements — **no string interpolation in SQL**.

### 3.3 Socket.IO Events
All Socket.IO broadcasts are managed exclusively through `backend/services/socketService.js`:
| Event | Trigger |
|---|---|
| `new_alert` | Alert detected in simulation/live pipeline |
| `risk_update` | Risk score recalculated |
| `timeline_update` | New timeline node added |
| `mitre_update` | New MITRE technique activated |
| `reset_state` | Full session reset executed |

---

## 4. React / Frontend Coding Standards

### 4.1 Component Structure
- Functional components only — no class components.
- Hooks: `useState`, `useEffect`, `useCallback`, `useMemo`.
- Component files in `frontend/src/pages/` (full pages) and `frontend/src/components/` (reusable).

### 4.2 Data Flow Rules
- All data MUST come from backend REST API calls or Socket.IO events.
- **No hardcoded fallback node arrays** in any component.
- Empty state: render a descriptive empty-state message (not fake data).
- API client: use `frontend/src/api/client.js` for all HTTP requests.

### 4.3 Styling
- Tailwind CSS utility classes only.
- No inline `style={}` attributes unless computing dynamic pixel coordinates.

---

## 5. Git & Commit Standards

### 5.1 Branch Strategy
| Branch | Purpose |
|---|---|
| `main` | Stable, production-ready releases |
| `develop` | Integration and sprint development |
| `feature/phase-X-name` | Specific phase feature branches |
| `fix/issue-description` | Bug fixes |
| `sprint/sprint-name` | Sprint-scoped work |

### 5.2 Commit Message Format — ENFORCED by commit-msg hook
Every commit MUST follow Conventional Commits with human-readable descriptions:

```
<type>(<scope>): <short human-readable summary in plain English>

<detailed description — what changed and WHY, written in plain English>
- Bullet points for each file/change
- State what the bug was and how it was fixed
- State what feature was added and why

Co-authored-by: Samriddhi0112 <motianisamriddhi2005@gmail.com>
Co-authored-by: deshnaajainofficial <deshnaajainofficial@gmail.com>
```

**Valid types:**
| Type | When to use |
|---|---|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `refactor` | Code restructure without behaviour change |
| `test` | Adding or updating tests |
| `docs` | Documentation only |
| `chore` | Maintenance, dependency updates |
| `sprint` | Sprint completion commit |
| `security` | Security fix or hardening |

**Examples of GOOD commit messages:**
```
fix(timeline): Fix timeline showing stale Failed Login nodes for all simulations

Root cause: getTimeline() in dbService.js always returned incKeys[0],
permanently binding the timeline to the first simulation run (Failed Login Burst).
Subsequent simulations stored nodes under new incident keys that were never fetched.

- event_correlator.py: return incident_events scoped to current scenario only
- dbService.js: track latest_incident_id; getTimeline() returns latest not first
- simulate.js: pass latestIncId to getTimeline() before broadcasting
- Timeline.jsx: remove hardcoded INC-88A12 fallback; dynamic empty state

Co-authored-by: Samriddhi0112 <motianisamriddhi2005@gmail.com>
Co-authored-by: deshnaajainofficial <deshnaajainofficial@gmail.com>
```

```
feat(ai): Add configurable EXPLANATION_TEMPLATES to SecurityIntelligenceLayer

Previously, feature explanations were hardcoded as if-elif chains inside
generate_intelligence_package(). Adding a new security feature required
modifying the engine logic directly.

Added EXPLANATION_TEMPLATES dict mapping feature names to template strings
so new features can be added via config without touching engine code.

- security_intel.py: Added EXPLANATION_TEMPLATES dict at module level
- SecurityIntelligenceLayer.__init__ now accepts optional templates= param

Co-authored-by: Samriddhi0112 <motianisamriddhi2005@gmail.com>
Co-authored-by: deshnaajainofficial <deshnaajainofficial@gmail.com>
```

**Examples of BAD commit messages (REJECTED by hook):**
```
# ❌ Too vague
git commit -m "fix stuff"
git commit -m "update"
git commit -m "changes"
git commit -m "wip"
git commit -m "asdf"
```

### 5.3 Commit Frequency Rules
- Commit after every completed feature, bugfix, or sprint milestone.
- **Do not batch unrelated changes** into a single commit.
- Minimum 1 commit per sprint phase.
- Every AI model artifact update requires its own commit.

### 5.4 Author Attribution (ALWAYS REQUIRED)
- **Primary Author**: `khyati50` (`khyatianand1134@gmail.com`)
- **Co-Author 1**: `Samriddhi0112` (`motianisamriddhi2005@gmail.com`)
- **Co-Author 2**: `deshnaajainofficial` (`deshnaajainofficial@gmail.com`)

Git config must be set:
```bash
git config user.name "khyati50"
git config user.email "khyatianand1134@gmail.com"
```

---

## 6. Testing Requirements

### 6.1 Python Tests (`ai/tests/`)
- Every new Python module MUST have a corresponding test file.
- Tests must cover: happy path, edge cases, and **negative cases** (corrupted input, missing fields, unknown IDs).
- All tests must pass before any commit: `pytest ai/tests/` → 0 failures required.

### 6.2 Test Categories Required
| Category | File |
|---|---|
| API Endpoints | `test_api_endpoints.py` |
| Correlation & MITRE | `test_correlation_mitre.py` |
| Detection Engine | `test_detection.py` |
| Explainability | `test_explainability.py` |
| Integration (full pipeline) | `test_integration.py` |
| Model Training | `test_model_training.py` |
| Negative Cases | `test_negative_cases.py` |
| Prediction Service | `test_prediction_service.py` |
| Preprocessing | `test_preprocessing.py` |
| Security | `test_security.py` |
| Frontend/Backend Structure | `test_frontend_backend_structure.py` |

### 6.3 Pre-commit Checklist (automated via git hooks)
- [ ] `black --check ai/` — Python formatting
- [ ] `flake8 ai/ --max-line-length=120` — Python linting
- [ ] `pytest ai/tests/ -q` — All tests pass

---

## 7. Sprint Governance Rules

1. Each sprint has a specification document in `docs/` (e.g. `Functional_Completion_Sprint.md`).
2. No code changes outside the sprint's defined scope.
3. Prohibited modifications must be explicitly listed in the sprint doc and respected.
4. Sprint completion requires: CEO approval + Supervisor sign-off + all tests passing.
5. Each sprint ends with a completion report artifact and a clean git commit.
