# Security Policy & Guidelines

> **Project:** Explainable AI-Based Real-Time Enterprise Windows Threat Detection and Investigation Dashboard

---

## 1. Data Protection & Log Handling

1. **No Sensitive Credential Storage**: Raw Windows Event Logs containing sensitive authentication tokens, plaintext passwords, or private SSH keys must be sanitized before DB insertion or UI rendering.
2. **Dataset Integrity**: The dataset variant `attacks_by_category_atomic_and_tools_removed` is strictly maintained to evaluate genuine behavioral anomalies rather than raw string signatures.

---

## 2. Authentication & Access Control

1. **JWT Authentication**: All REST API routes in the Node.js backend (except `/api/auth/login` and `/api/auth/register`) require a valid JSON Web Token (JWT) passed in the `Authorization: Bearer <token>` header.
2. **Password Hashing**: User passwords in the MySQL `users` table must be hashed using `bcrypt` with a minimum cost factor of 10.
3. **Role-Based Access Control (RBAC)**: Support roles `analyst` (read & investigation access) and `admin` (system config & simulation execution access).

---

## 3. Network & API Security

1. **CORS Policy**: Configured to restrict origin requests strictly to trusted frontend origins (`http://localhost:5173`).
2. **HTTP Headers**: Enforce security headers using `helmet` in Node.js (X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security).
3. **Input Sanitization & SQL Injection Prevention**: All MySQL queries must use parameterized statements or ORM binding (`mysql2/promise` with placeholder parameters `?`).

---

## 4. Windows Security & WDAC Compliance

1. **Windows Defender Application Control (WDAC)**: The machine enforces WDAC in Enforced Mode.
2. **Dependency Pins**:
   - `pandas==2.2.3`
   - `shap==0.43.0`
   - `numpy==1.26.4`
3. **Pure-Python Stubs**: Any low-reputation `.pyd` binaries blocked by WDAC (e.g. `numba`, `matplotlib._c_internal_utils`) are safely handled via pure-Python stubs to guarantee system stability without disabling OS security controls.
