# Semgrep SAST Scanner Service

This service encapsulates deterministic Static Application Security Testing (SAST) for AIShield Debt.

## Responsibilities
- Mounts code changes (diff or repository workspace) as a read-only volume (`-v <repo>:/src:ro`).
- Executes Semgrep with official curated rulesets (`p/security-audit`, `p/owasp-top-ten`, `p/cwe-top-25`) and optional custom debt rules.
- Supports PR-scoped diff analysis via `--include <file>` flags to scan only files altered by a Pull Request.
- Emits structured JSON findings containing file paths, line ranges, matched rules, CWE IDs, and remediation guidance.
- Adheres to zero-execution security principles (AST parsing only; no code execution; network isolation).

## Documentation
- See [RULES_PROVENANCE.md](file:///d:/hakathon/AIShield/services/semgrep/RULES_PROVENANCE.md) for architectural details on rule registry referencing, licensing (LGPL-2.1 / Semgrep Community License), container security hardening, and legal isolation guarantees.
