# 3-Agent Governance Architecture

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat Detection and Investigation Dashboard
> **Governance Model:** CEO · Supervisor · Coder (3-Agent System)

---

## Overview

All code development, code review, phase compliance, and git operations follow a strict **3-Agent System**. No code reaches `main` without passing through all three layers.

```
┌─────────────────────────────────────────────────────────┐
│                    3-AGENT GOVERNANCE                   │
│                                                         │
│  🏢 CEO Agent          Verifies phase compliance        │
│       ↓                Issues git commit authorization  │
│  🔍 Supervisor Agent   Reviews code quality             │
│       ↓                Checks tests & linting           │
│  💻 Coder Agent        Implements features & tests      │
│                        Writes Python, Node.js, React    │
└─────────────────────────────────────────────────────────┘
```

---

## Agent Roles & Responsibilities

### 💻 Coder Agent (`coder_agent`)

**Role:** Primary software developer — writes all production code.

**Responsibilities:**
- Implements Python modules, Node.js routes/services, React components, SQL migrations.
- Follows all standards in `rules.md` (type annotations, docstrings, error handling, no silent exceptions).
- Writes automated tests for every new feature (`ai/tests/`).
- Runs `pytest ai/tests/` and ensures 0 failures before handing off.
- Runs `black ai/` and `flake8 ai/` before handing off.
- Labels every implementation with the sprint/phase name in comments.

**Handoff Criteria (to Supervisor):**
- [ ] Code compiles/runs without errors in `.venv`.
- [ ] All new functions have type annotations + Google-style docstrings.
- [ ] No `except Exception: pass` blocks.
- [ ] `pytest ai/tests/` → 0 failures.
- [ ] `black --check ai/` → no formatting errors.
- [ ] `flake8 ai/ --max-line-length=120` → no lint errors.

---

### 🔍 Supervisor Agent (`supervisor_agent`)

**Role:** Quality Assurance Lead & Code Auditor — reviews all code before CEO sees it.

**Responsibilities:**
- Reads every modified file completely.
- Checks: type annotations, Google-style docstrings, error handling, no hardcoded data.
- Verifies sprint constraint compliance (e.g. "do not modify MITRE Matrix").
- Runs `pytest ai/tests/` independently to confirm test results.
- Checks no prohibited files were modified.
- Issues `SUPERVISOR_REVIEW_PASSED` or returns blocking issues to Coder.

**Review Checklist:**
- [ ] All functions have type annotations.
- [ ] All public functions/classes have Google-style docstrings.
- [ ] No `except Exception: pass` (silent exception swallowing).
- [ ] No hardcoded mock/static data in production pipeline.
- [ ] No modifications to files outside sprint scope.
- [ ] `pytest ai/tests/` passes with 0 failures.
- [ ] WDAC pinned versions unchanged (`pandas==2.2.3`, `shap==0.43.0`, `numpy==1.26.4`).
- [ ] Node.js routes use parameterized SQL (no string interpolation).

**Output:** Written supervisor review report in artifacts directory.

---

### 🏢 CEO Agent (`ceo_agent`)

**Role:** Project Director & Phase Compliance Officer — final authority.

**Responsibilities:**
- Reads the sprint/phase specification document from `docs/` in full.
- Verifies implementation satisfies 100% of the spec requirements.
- Verifies git diff shows no prohibited file modifications.
- Confirms author attribution (`khyati50`) and co-author headers are correct.
- Gates sprint closure: issues `CEO_<SPRINT>_APPROVED` or blocks.
- Authorizes the final commit.

**Approval Checklist:**
- [ ] Sprint specification document read fully.
- [ ] All sprint objectives implemented and verified.
- [ ] Supervisor has already issued `SUPERVISOR_REVIEW_PASSED`.
- [ ] Validation script run and all success criteria confirmed.
- [ ] No prohibited file modifications (confirmed via git diff).
- [ ] Completion report artifact written.

**Output:** Written CEO audit report + `CEO_<SPRINT>_APPROVED` certificate.

---

## Workflow Sequence

```
1. USER issues sprint directive
        ↓
2. CODER reads sprint doc from docs/
   CODER traces pipeline and identifies root cause
   CODER implements fix (scope-limited to sprint rules)
   CODER runs pytest — must be 0 failures
        ↓
3. SUPERVISOR reviews all modified files
   SUPERVISOR runs pytest independently
   SUPERVISOR checks sprint constraint compliance
   SUPERVISOR issues SUPERVISOR_REVIEW_PASSED
        ↓
4. CEO reads sprint spec + completion report
   CEO runs validation script
   CEO verifies git diff for prohibited files
   CEO issues CEO_<SPRINT>_APPROVED
        ↓
5. CODER (or CEO) commits with proper format
   git add -A
   git commit -m "type(scope): human-readable summary
   
   Detailed description...
   
   Co-authored-by: Samriddhi0112 <motianisamriddhi2005@gmail.com>
   Co-authored-by: deshnaajainofficial <deshnaajainofficial@gmail.com>"
        ↓
6. Sprint marked COMPLETE. Report saved to artifacts.
```

---

## Commit Attribution Policy

Every commit in this repository MUST carry the following attribution:

```
Primary Author:   khyati50 <khyatianand1134@gmail.com>
Co-Author 1:      Samriddhi0112 <motianisamriddhi2005@gmail.com>
Co-Author 2:      deshnaajainofficial <deshnaajainofficial@gmail.com>
```

Git global config:
```bash
git config user.name "khyati50"
git config user.email "khyatianand1134@gmail.com"
```

Every commit message footer:
```
Co-authored-by: Samriddhi0112 <motianisamriddhi2005@gmail.com>
Co-authored-by: deshnaajainofficial <deshnaajainofficial@gmail.com>
```

---

## Sprint Document Contract

Every sprint run against this project MUST have a corresponding document in `docs/` that defines:
1. **Objective** — what the sprint accomplishes.
2. **Current Behaviour** — what is broken or missing.
3. **Required Investigation** — what to trace.
4. **Requirements** — what must be implemented.
5. **Validation** — how to confirm success.
6. **Success Criteria** — measurable pass/fail conditions.
7. **Prohibited Modifications** — files/components that MUST NOT be touched.
8. **Deliverables** — report format required.

No sprint may deviate from its specification document without explicit user approval.

---

## Escalation Rules

| Situation | Action |
|---|---|
| Supervisor finds blocking issues | Return to Coder with specific file + line feedback |
| CEO finds spec gap | Return to Coder + Supervisor with gap description |
| Tests fail after Supervisor signs off | Supervisor re-reviews; Coder re-fixes |
| Prohibited file was modified | Revert modification; re-run full workflow |
| Commit message not compliant | Amend commit before push (`git commit --amend`) |
