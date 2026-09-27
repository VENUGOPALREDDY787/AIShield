# ⚠️ INTENTIONALLY VULNERABLE DEMO APPLICATION (AIShield Debt Benchmark)

> **WARNING:** This repository contains intentionally vulnerable code designed strictly for demonstrating, testing, and benchmarking the **AIShield Security Debt Engine**.
>
> ❌ **DO NOT USE ANY CODE FROM THIS REPOSITORY IN PRODUCTION.**
> ❌ **DO NOT DEPLOY THIS APPLICATION TO PUBLIC NETWORKS.**
> 🔒 **All credentials, tokens, and keys in this repository are synthetic, non-functional dummy fixtures.**

---

## Vulnerabilities Included for AIShield Demonstration

| Vulnerability Class | File / Location | CWE ID | Simulated Severity |
| :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | `src/controllers/user.controller.ts` | CWE-89 | 🔴 CRITICAL |
| **OS Command Injection** | `src/controllers/admin.controller.ts` | CWE-78 | 🔴 CRITICAL |
| **Hardcoded Secret / API Key** | `src/config/auth.config.ts` | CWE-798 | 🔴 CRITICAL |
| **Missing Authorization (IDOR)** | `src/controllers/user.controller.ts` | CWE-285 / CWE-639 | 🟠 HIGH |
| **Reflected Cross-Site Scripting (XSS)** | `src/controllers/search.controller.ts` | CWE-79 | 🟠 HIGH |
| **Weak Cryptography (MD5 / DES)** | `src/controllers/crypto.controller.ts` | CWE-327 / CWE-328 | 🟡 MEDIUM |
| **Path Traversal / Unsafe File Access** | `src/controllers/admin.controller.ts` | CWE-22 | 🔴 CRITICAL |
| **Insecure Error Handling (Stack Trace Leak)** | `src/controllers/user.controller.ts` | CWE-209 | 🟡 MEDIUM |
| **Vulnerable Dependencies (CVEs)** | `package.json` (`lodash@4.17.15`, `jsonwebtoken@8.5.1`) | CWE-1321 | 🟠 HIGH |

---

## Demo Branch Progression & PR Simulation

This repository contains 4 distinct pull request branches showcasing the AIShield workflow:

```
main (Clean Baseline Skeleton) ─────────────────────────────────────────────────────────────┐
  │                                                                                          │
  ├──▶ [PR 1] pr-1-user-portal (Adds User Portal: SQLi, Hardcoded Secret, IDOR)              │
  │    └── Result: Debt increases from 0 -> 48 (Risk: CRITICAL, Policy: FAIL)                │
  │                                                                                          │
  ├──▶ [PR 2] pr-2-admin-diagnostics (Adds Admin Tools: Command Injection, XSS, Weak Crypto)│
  │    └── Result: Debt increases to 84 (Risk: CRITICAL, Policy: FAIL)                       │
  │                                                                                          │
  ├──▶ [PR 3] pr-3-fix-auth-and-sqli (Remediates SQLi with Prepared Statements & Masks Keys) │
  │    └── Result: Debt decreases from 84 -> 38 (Risk: HIGH, Policy: WARN)                   │
  │                                                                                          │
  └──▶ [PR 4] pr-4-full-hardening (Full Remediation: Safe ChildProcess, Argon2, XSS Escaped)│
       └── Result: Debt drops to 0 (Risk: LOW, Policy: PASS) ◀───────────────────────────────┘
```

---

## Running AIShield Analysis on this Demo App

```bash
# Run AIShield worker PR analysis
node apps/worker/dist/github/run-pr-analysis.js
```
