# Project Development Rules & Coding Standards

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat Detection and Investigation Dashboard  
> **Repository:** [Samriddhi0112/Capstone](https://github.com/Samriddhi0112/Capstone)

---

## 1. Architectural Principles

1. **Phase Compliance**: All code must strictly conform to the 19 Phase specification documents located in `docs/`.
2. **Unified Processing Pipeline**: Live monitoring and simulation modes MUST use the exact same preprocessing, prediction, detection, explainability, correlation, and risk calculation pipeline.
3. **Hybrid Architecture**:
   - **Prediction Service**: Python FastAPI + Uvicorn (Port 8000).
   - **Main REST API & WebSockets**: Node.js + Express + Socket.IO (Port 5000).
   - **Database**: MySQL 8.0 (Port 3306).
   - **Frontend Dashboard**: Vite + React.js + Tailwind CSS (Port 5173).

---

## 2. Python Coding Standards

1. **Python Version & Virtual Environment**: Python 3.11 using local `.venv` (`.\.venv\Scripts\activate`).
2. **Code Style**:
   - Maximum line length: 120 characters.
   - Style checker: `flake8` compliance.
   - Formatter: `black` compliance.
3. **Type Annotations**: All function signatures must include Python type hints (`def process_event(event: dict) -> dict:`).
4. **Docstrings**: All modules, classes, and public functions must include Google-style or Sphinx-style docstrings explaining parameters, returns, and raised exceptions.
5. **WDAC Compatibility**:
   - Native `.pyd` dependencies must strictly comply with Windows Defender Application Control (WDAC) rules.
   - Use pinned versions: `pandas==2.2.3`, `shap==0.43.0`, `numpy==1.26.4`.
   - Pure-Python stubs must be maintained for blocked helper modules (e.g., `matplotlib._c_internal_utils`, `numba`).

---

## 3. Node.js & React Coding Standards

1. **Node.js Standards**:
   - Modern ES6+ syntax (`async/await` over raw promises).
   - Modular Express router architecture (`routes/`, `controllers/`, `services/`, `models/`).
   - Centralized error-handling middleware (`middleware/errorHandler.js`).
2. **React Standards**:
   - Functional components with React Hooks (`useState`, `useEffect`, `useCallback`, `useMemo`).
   - Clean component modularity (`components/`, `pages/`, `hooks/`, `api/`).
   - Styling using Tailwind CSS utility classes; no inline style attributes unless calculating dynamic CSS coordinates.

---

## 4. Git & Commit Standards

1. **Branch Strategy**:
   - `main`: Stable production releases.
   - `develop`: Integration and feature development.
   - `feature/phase-X`: Specific phase feature branches.

2. **Commit Message Format**:
   All commits must use Conventional Commits format with explicit author and co-author headers:

```text
<type>(<scope>): <short summary>

<detailed description of changes>

Co-authored-by: Samriddhi0112 <motianisamriddhi2005@gmail.com>
Co-authored-by: deshnaajainofficial <deshnaajainofficial@gmail.com>
```

3. **Author Attribution**:
   - Primary Author: `khyati50` (`khyatianand1134@gmail.com`)
   - Co-Author 1: `Samriddhi0112` (`motianisamriddhi2005@gmail.com`)
   - Co-Author 2: `deshnaajainofficial` (`deshnaajainofficial@gmail.com`)

---

## 5. Testing & Verification Requirements

1. Every phase implementation must include automated tests in `ai/tests/` or backend test scripts.
2. No code is committed until it passes linting, formatting, and unit tests.
