# Gitleaks Secret Scanner Service

Deterministic secret and credential detection service for AIShield Debt.

## Responsibilities
- Inspects git commit ranges (`--log-opts=base..target`) and Pull Request diffs for API keys, private certificates, JWT tokens, and high-entropy credentials.
- Masks secret values at ingestion (`maskSecret`) and computes cryptographic hashes (`hashSecret`).
- Strictly guarantees that plaintext secrets are never printed in logs, exposed in dashboards, or persisted in MongoDB.
- Generates safe PR review alert comments with zero raw credentials.
- Computes invariant fingerprints stable across line movements and branch rebasing.

## Documentation
- See [SECRET_REDACTION.md](file:///d:/hakathon/AIShield/services/gitleaks/SECRET_REDACTION.md) for full architectural documentation on multi-layer redaction, masking algorithms, database validation hooks, and testing policy.

