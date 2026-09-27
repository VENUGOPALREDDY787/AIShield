# AIShield Secret Redaction & Protection Architecture

## 1. Threat Model & Guiding Principle

Credential leakage is a critical security vulnerability. When developers commit API keys, cloud access tokens, or private keys, automated scanners must detect them without inadvertently proliferating the secret.

> **Guiding Principle**: A security platform designed to detect credential leaks must never become an attack vector or secondary repository of exposed secrets. Plaintext credentials must never enter logs, application caches, pull request comments, dashboards, or persistent MongoDB storage.

---

## 2. Multi-Layer Redaction Architecture

AIShield enforces a **defense-in-depth, five-layer redaction pipeline** that operates from the moment scanner output is ingested through database persistence and UI presentation.

```mermaid
flowchart TD
    A["Gitleaks Output (stdout)"] --> B["Layer 1: Ingestion Redaction (GitleaksScanner)"]
    B --> C["Layer 2: Edge-Preserving Masking & One-Way Hashing"]
    C --> D["Layer 3: Invariant Fingerprinting (Deduplication)"]
    D --> E["Layer 4: PR Comment & Dashboard Sanitization"]
    D --> F["Layer 5: Mongoose Pre-Validate Hook (MongoDB Defense-in-Depth)"]
    F --> G[("MongoDB (Encrypted / Sanitized Only)")]
```

### Layer 1: Ingestion Redaction (`GitleaksScanner`)
- When Gitleaks completes execution, its JSON output is parsed in memory.
- `GitleaksScanner.normalizeResult()` processes each finding immediately.
- The raw secret values (`item.Secret` and `item.Match`) are **mutated in-place** into masked strings.
- Even the internal `rawOutput` payload preserved in the scan envelope contains only sanitized strings, preventing any downstream logger or queue serialiser from inadvertently recording plaintext credentials.

### Layer 2: Edge-Preserving Masking & One-Way Hashing
- **Masking Algorithm (`maskSecret`)**:
  - For secrets $\le 8$ characters: completely replaced by `[REDACTED]`.
  - For secrets $> 8$ characters: the first 4 characters and last 4 characters are preserved, while the entire middle is masked with asterisks (e.g. `AKIAIOSFODNN7EXAMPLE` $\rightarrow$ `AKIA************MPLE`).
  - *Rationale*: Preserving the edge characters enables developers to instantly recognise which key to revoke in their AWS/GCP/GitHub console without exposing the actual credential.
- **Cryptographic Hashing (`hashSecret`)**:
  - The secret is passed through a one-way SHA-256 hash function.
  - Formatted as `[REDACTED_SHA256:d8b74a12093e...]`.
  - Stored in finding metadata for auditability and verification without revealing the secret.

### Layer 3: Invariant Fingerprinting
- Gitleaks native fingerprints are tied to line numbers or commit SHAs. In active pull requests, developer refactoring shifts line numbers, and rebasing changes commit SHAs, which would cause duplicate finding records.
- AIShield computes an invariant fingerprint:
  $$\text{Fingerprint} = \text{SHA-256}(\text{"secret:"} + \text{RuleID} + \text{":"} + \text{FilePath} + \text{":"} + \text{SecretHash})$$
- This fingerprint remains **100% stable** across line shifts, file renames, and branch rebases.

### Layer 4: PR Review Comments & Dashboard Sanitization
- Automated GitHub Pull Request comments are generated via `formatPrSecretAlert()`.
- The comment outputs a structured Markdown alert table containing:
  - Rule identifier (e.g., `aws-access-key-id`, `github-pat`)
  - File path and line number
  - Masked key (e.g. `AKIA************MPLE`)
  - Redacted SHA-256 hash tag
  - Immediate rotation and remediation steps
- Plaintext secrets are strictly prohibited from PR comments.

### Layer 5: Database Persistence Defense-in-Depth (`FindingModel`)
- The Mongoose `findingSchema` enforces a `pre('validate')` hook that intercepts every write to MongoDB.
- Any code context in `location.snippet` is passed through `redactSensitiveText()`, which scans for:
  - Private key blocks (`-----BEGIN PRIVATE KEY-----`)
  - Cloud provider access keys (AWS, Google, OpenAI)
  - Developer tokens (GitHub, Slack, Bearer tokens, JWTs)
  - Key-value credential assignments (`password=...`, `apiKey=...`)
- **Zero Raw Secrets in MongoDB**: The database stores only `maskedSecret`, `secretHash`, and redacted snippets.

---

## 3. Pull Request Scanning & Commit Delta Optimization

When analyzing Pull Requests:
1. **Commit Range Scoping**: If `baseCommit` and `targetCommit` are provided, Gitleaks is invoked with `--log-opts=${baseCommit}..${targetCommit}`, scanning only the commits introduced in the PR.
2. **Changed Files Filter**: If `changedFiles` is specified, `normalizeResult()` filters findings to ensure only secrets introduced in PR-altered files are reported, avoiding alert fatigue from pre-existing repository debt.

---

## 4. Docker Sandboxing

Containerized Gitleaks runs under strict isolation flags:
- `--network none`: Container network stack is completely disabled. Untrusted code cannot phone home or exfiltrate discovered secrets.
- `-v ${targetPath}:/src:ro`: Read-only bind mount. Scanned code cannot be modified.
- `--cap-drop=ALL`: Strips all Linux root capabilities.
- `--security-opt=no-new-privileges`: Prevents privilege escalation.
- `-w /src`: Confines execution to the mounted workspace.

---

## 5. Synthetic Secret Testing Policy

All automated test suites, fixtures, and documentation in AIShield strictly use **synthetic test secrets** (such as official vendor documentation examples and mock tokens):
- AWS: `AKIAIOSFODNN7EXAMPLE` (AWS official documentation sample key)
- GitHub: `ghp_mocktesttoken000000000000000000000`
- Slack: `xoxb-mock-000000000000-0000000000000-mocktoken0000000000000000`

Live credentials, active API tokens, and real private keys must never be committed to test fixtures or repository files.
