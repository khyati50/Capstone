# Security Policy & Guidelines

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat Detection and Investigation Dashboard
> **Last Updated:** 2026-08-07

---

## 1. Data Protection & Log Handling

1. **No Plaintext Credentials** — Raw Windows Event Logs containing authentication tokens, plaintext passwords, or private keys MUST be sanitized before DB insertion or UI rendering.
2. **Dataset Integrity** — The dataset variant `attacks_by_category_atomic_and_tools_removed` is maintained exclusively. No raw string-signature shortcuts are permitted.
3. **No PII in Logs** — `console.log` and `logging` statements must not print raw user passwords, JWT secrets, or database connection strings.
4. **Environment Variables** — All secrets (DB passwords, JWT secrets) are stored in `.env` files ONLY. `.env` is listed in `.gitignore` and MUST NEVER be committed.

---

## 2. Authentication & Access Control

### 2.1 JWT Authentication
- All REST API routes (except `POST /api/auth/login` and `POST /api/auth/register`) require a valid JWT in `Authorization: Bearer <token>`.
- JWT must be verified using the secret stored in `process.env.JWT_SECRET`.
- Expired or tampered tokens return `403 Forbidden`.

### 2.2 Password Security
- Passwords stored in MySQL `users` table MUST be hashed with `bcrypt` (minimum cost factor: 10).
- Plain-text password comparison is FORBIDDEN.

### 2.3 Role-Based Access Control (RBAC)
| Role | Permissions |
|---|---|
| `analyst` | Read alerts, view timeline, view MITRE, view risk |
| `admin` | All analyst permissions + run simulations + system config |

---

## 3. Network & API Security

### 3.1 CORS Policy
```javascript
// Allowed origin: frontend only
origin: process.env.ALLOWED_ORIGIN || 'http://localhost:5173'
```
Cross-origin requests from unknown origins are rejected.

### 3.2 HTTP Security Headers (Helmet)
The following headers are enforced via `helmet` middleware on every response:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security` (in production)
- `Content-Security-Policy`

### 3.3 SQL Injection Prevention
All MySQL queries MUST use parameterized placeholders. String interpolation in SQL is FORBIDDEN:
```javascript
// ✅ Correct — parameterized
await pool.query('SELECT * FROM users WHERE email = ?', [email]);

// ❌ FORBIDDEN — SQL injection risk
await pool.query(`SELECT * FROM users WHERE email = '${email}'`);
```

### 3.4 Input Sanitization
- All user-supplied Event ID, scenario_type, and username fields are type-validated before use.
- Extreme numeric values and XSS strings in `scenario_id` are handled gracefully (tested in `test_security.py`).

---

## 4. Windows Security & WDAC Compliance

### 4.1 Windows Defender Application Control (WDAC)
The deployment machine enforces WDAC in Enforced Mode. All Python native extensions (`.pyd` files) must be on the WDAC allowlist.

### 4.2 Pinned Dependency Versions (MANDATORY)
```
pandas==2.2.3
shap==0.43.0
numpy==1.26.4
scikit-learn==1.5.0
xgboost==2.0.3
```
Do NOT upgrade these without WDAC re-evaluation and updating `requirements.txt`.

### 4.3 Pure-Python Stubs
Any low-reputation `.pyd` binaries blocked by WDAC are handled via pure-Python stubs:
- `matplotlib._c_internal_utils` → stub in `ai/stubs/`
- `numba` → not installed; no usage permitted

### 4.4 No Dynamic Code Execution
- `eval()`, `exec()`, and `subprocess.Popen()` with shell-interpolated user input are FORBIDDEN in the AI engine.
- `os.system()` is FORBIDDEN.

---

## 5. Python Security Standards

### 5.1 No Silent Exception Swallowing
```python
# ❌ FORBIDDEN — hides security-relevant errors
except Exception:
    pass

# ✅ Required — log and report
except Exception as exc:
    logger.error(f"Processing failed for {event_id}: {exc}")
```

### 5.2 SHAP Defensive Fallback
- `ShapExplainer.explain()` MUST have a try/except around `shap.TreeExplainer`.
- If SHAP fails, log with `logger.warning("SHAP explanation unavailable, using heuristic fallback")`.
- Fallback explanations must be clearly labelled as heuristic.

### 5.3 No Hardcoded Secrets
```python
# ❌ FORBIDDEN
DB_PASSWORD = "admin123"
JWT_SECRET = "supersecret"

# ✅ Required
DB_PASSWORD = os.getenv("DB_PASSWORD")
JWT_SECRET = os.getenv("JWT_SECRET")
```

---

## 6. Frontend Security

### 6.1 No Sensitive Data in LocalStorage
- JWT tokens may be stored in `sessionStorage` (not `localStorage`) to prevent XSS persistence.
- Never store raw passwords or API secrets in the browser.

### 6.2 No Inline Event Handlers
- `onClick="javascript:..."` inline handlers are FORBIDDEN.
- Use React `onClick={handler}` bound to a function.

### 6.3 Sanitise Rendered User Content
- Any user-supplied string rendered in the DOM must be handled through React's safe rendering (no `dangerouslySetInnerHTML` unless absolutely required and sanitized).

---

## 7. Git Security

### 7.1 Files That Must Never Be Committed
`.gitignore` must always contain:
```
.env
.venv/
*.pyc
__pycache__/
ai/models/artifacts/*.pkl
ai/models/artifacts/*.json
node_modules/
```

### 7.2 Secrets Audit
Before any push to `origin`, verify no secrets appear in staged files:
```bash
git diff --cached | grep -iE "(password|secret|token|api_key)" 
```

### 7.3 No Force Push to Main
`git push --force` to the `main` branch is FORBIDDEN. Use `git push --force-with-lease` on feature branches only.
