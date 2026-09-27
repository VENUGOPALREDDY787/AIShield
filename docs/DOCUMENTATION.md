# AIShield Debt 🛡️ — Complete System Architecture & Reference Documentation

> **Important Security Disclaimer:**
> AIShield Debt is an automated security debt quantification, prioritization, and pull-request review assistant. **It does not guarantee total security or the absolute absence of vulnerabilities.** It provides quantitative risk visibility and contextual guidance to empower human security engineers and developers. AIShield never automatically merges pull requests or modifies production access control.

---

## 1. Problem Statement

Modern software development teams increasingly rely on Generative AI coding assistants (e.g., GitHub Copilot, ChatGPT, Claude, Cursor) to accelerate feature delivery. While AI models dramatically improve coding velocity, they are optimized for **functional correctness and syntactic plausibility** rather than defensive security architecture.

As a result, code that appears clean, passes unit tests, and satisfies functional requirements frequently introduces subtle, unmonitored security flaws into codebases. Over time, these unaddressed vulnerabilities accumulate into **Silent Security Debt** — compounding risk across pull requests until an exploit or compliance audit occurs.

---

## 2. Motivation

Traditional AppSec tooling falls into two problematic extremes:
1. **Noisy, Gatekeeping SAST:** Heavyweight static analysis tools overwhelm developers with hundreds of false positives, slow down CI/CD pipelines, and generate friction between development and security teams.
2. **Ignored Periodic Scans:** Nightly or weekly batch scans dump massive reports that get backlogged and ignored because no individual developer is accountable for the incremental delta introduced in a specific PR.

**AIShield Debt** was built to solve this by:
- Quantifying security risk as a **concrete, trackable metric (0–100 Security Debt Score)**.
- Evaluating only the **incremental delta ($\Delta \text{Debt}$)** introduced in each Pull Request.
- Combining fast, deterministic AST scanners with contextual LLM reasoning to explain *why* debt changed and *how* to remediate it.

---

## 3. What is Silent Security Debt?

**Silent Security Debt** is the cumulative accumulation of unaddressed, latent security risks, architectural anti-patterns, and deprecated dependencies that do not break application functionality or fail conventional unit tests, but significantly elevate an application's attack surface.

Unlike technical debt (which manifests as performance degradation or code maintainability hurdles), silent security debt remains completely invisible until an attacker exploits the vulnerability in production.

Examples include:
- Unparameterized database queries that happen to work for valid inputs.
- Missing role and ownership checks on IDOR-prone REST endpoints.
- Permissive CORS or disabled CSRF protections added "temporarily" during development.
- Stale or indirectly vulnerable third-party dependencies.
- Hardcoded fallback secrets and debug API tokens.

---

## 4. Why AI-Generated Code Creates This Problem

Generative AI models introduce a unique pattern of security vulnerabilities:

1. **Training Bias Toward Insecure Tutorials:** Models are trained on vast corpora of public code, tutorials, and StackOverflow snippets, which disproportionately feature simplified, insecure patterns (e.g., string-interpolated SQL queries, raw shell executions, hardcoded mock keys).
2. **Context-Window Limitations:** LLMs generate localized code snippets without awareness of the broader repository authorization framework, middleware guards, or secret management infrastructure.
3. **Hallucinated Package Dependencies:** LLMs frequently invent non-existent package names or recommend abandoned libraries susceptible to typosquatting and dependency confusion attacks.
4. **"Plausible Correctness" Blind Spot:** AI-generated code looks clean, is well-commented, and compiles without errors, leading human reviewers to lower their guard and approve pull requests without rigorous security audits.

---

## 5. The Solution: Incremental Security Debt Tracking

AIShield Debt operates directly in the developer pull-request workflow to provide:
1. **Incremental Delta Analysis:** Calculates exactly how much security debt a specific PR adds or resolves ($\Delta \text{Debt} = \text{Debt}_{\text{head}} - \text{Debt}_{\text{base}}$).
2. **Clear Finding Distinction:** Distinguishes verified scanner findings from AI contextual suggestions and overall debt scoring estimates.
3. **Deterministic Policy Enforcement:** Evaluates PRs against configurable security policies (`PASS`, `WARN`, `FAIL`) without blocking non-security workflows.
4. **Contextual Remediation:** Generates actionable, copy-pasteable remediation diffs to resolve findings before merge.

---

## 6. Hybrid Architecture

AIShield Debt employs a **two-phase hybrid architecture** that unites deterministic speed with contextual LLM intelligence:

```
                               ┌────────────────────────────────────────────────────────┐
                               │                 GitHub Pull Request                    │
                               └───────────────────────────┬────────────────────────────┘
                                                           │
                                                           ▼
                               ┌────────────────────────────────────────────────────────┐
                               │                AIShield Backend API                    │
                               │          (Authentication, Rate Limiting, RBAC)         │
                               └───────────────────────────┬────────────────────────────┘
                                                           │ Enqueue Job
                                                           ▼
                               ┌────────────────────────────────────────────────────────┐
                               │                 Redis + BullMQ Queue                   │
                               └───────────────────────────┬────────────────────────────┘
                                                           │ Dequeue Job
                                                           ▼
                               ┌────────────────────────────────────────────────────────┐
                               │                Scan Orchestration Worker               │
                               └───────────┬────────────────────────────────┬───────────┘
                                           │                                │
                               ┌───────────▼────────────┐       ┌───────────▼───────────┐
                               │ Phase 1: Deterministic │       │ Phase 2: AI Context   │
                               │ ├─ Semgrep (AST SAST)  │──────▶│ ├─ Logic flaws        │
                               │ ├─ Gitleaks (Secrets)  │       │ ├─ Missing auth       │
                               │ └─ OSV (Dependencies)  │       │ └─ Context reasoning  │
                               └───────────┬────────────┘       └───────────┬───────────┘
                                           │                                │
                                           └───────────────┬────────────────┘
                                                           ▼
                               ┌────────────────────────────────────────────────────────┐
                               │                 Security Debt Engine                   │
                               │           (Fingerprinting, Score 0-100, Δ)             │
                               └───────────┬────────────────────────────────┬───────────┘
                                           │                                │
                                           ▼                                ▼
                               ┌──────────────────────┐          ┌──────────────────────┐
                               │    MongoDB Cluster   │          │  GitHub Check & PR   │
                               │ (Findings, History)  │          │   Markdown Comment   │
                               └──────────────────────┘          └──────────────────────┘
```

---

## 7. Rule-Based Analysis (Phase 1: Deterministic Scanners)

Deterministic scanners evaluate source code as **inert, unexecuted data** using hardened, isolated sandboxes:

- **Semgrep (AST SAST):**
  - Parses code into abstract syntax trees to detect data flow, taint propagation, SQL injection, OS command injection, XSS, and dangerous API usage.
  - Generates zero-hallucination, rule-verified findings.
- **Gitleaks (Secret Detection):**
  - Scans files and diffs for API keys, private tokens, passwords, and cloud credentials using regular expressions and Shannon entropy analysis.
  - Automatically masks raw secrets in logs and memory.
- **OSV-Scanner (Dependency Vulnerability Auditing):**
  - Audits lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`) against the Open Source Vulnerabilities (OSV) database and GitHub Advisory Database.

---

## 8. AI Analysis (Phase 2: Contextual Risk Analyzer)

The AI Contextual Analyzer complements deterministic scanners by analyzing the broader git diff context:

- **Prompt Injection Defense:** Source code and diff content are strictly isolated inside triple-backtick delimiters and sanitized against prompt override attempts.
- **System Instructions:** Configured with a system security analyst prompt that forces structured JSON output and forbids outputting unverifiable findings.
- **Zod Schema Validation:** LLM output is strictly validated against a Zod schema (`aiAnalysisOutputSchema`); malformed or non-compliant outputs are rejected.
- **Scope:** Detects subtle authorization gaps (IDOR), unauthenticated endpoints, insecure cryptographic modes, and logical inconsistencies across changed files.

---

## 9. Security Debt Engine & Mathematical Scoring

The Security Debt Engine computes an objective index between **0 and 100** using a deterministic mathematical model:

### A. Finding Points Formulation
Each unique finding \( i \) is assigned debt points based on its severity weight \( W \), category multiplier \( M \), boundary multiplier \( B \), and confidence \( C \):

$$\text{Points}_i = W(\text{severity}_i) \times M(\text{category}_i) \times B(\text{fileLocation}_i) \times C(\text{confidence}_i)$$

#### Severity Weights (\( W \)):
- `CRITICAL`: **25 points**
- `HIGH`: **12 points**
- `MEDIUM`: **5 points**
- `LOW`: **1 point**
- `INFO`: **0 points**

#### Category Multipliers (\( M \)):
- `secret_exposure`: **1.3×**
- `injection` (SQLi, Command Injection): **1.2×**
- `authentication` / `authorization`: **1.15×**
- `cryptography`: **1.0×**
- `vulnerable_dependency`: **1.0×**
- `insecure_transport` / `error_handling`: **0.85×**

#### Boundary Multipliers (\( B \)):
- Public API controllers, authentication middleware, routing endpoints: **1.0×**
- Internal utilities, background services: **0.85×**
- Test files (`*.test.ts`, `__fixtures__`): **0.2×**

### B. Repository Debt Score (0–100 Curve)
Total accumulated debt points are mapped onto a asymptotic 0–100 scale:

$$\text{Score} = \min\left(100, \left\lfloor 100 \times \left(1 - e^{-\frac{\sum \text{Points}_i}{120}}\right) \right\rfloor\right)$$

#### Risk Level & Letter Grades:
- **`0 - 15` (Grade A / LOW):** Healthy security baseline.
- **`16 - 35` (Grade B / MEDIUM):** Minor technical security debt.
- **`36 - 60` (Grade C / HIGH):** Elevated risk; multiple high-priority items.
- **`61 - 80` (Grade D / CRITICAL):** Critical security vulnerabilities detected.
- **`81 - 100` (Grade F / CRITICAL):** Severe security failure; immediate remediation required.

### C. PR Delta Calculation
$$\Delta \text{Debt} = \text{Score}_{\text{head}} - \text{Score}_{\text{base}}$$
$$\text{Net Debt Change} = \text{New Debt Introduced} - \text{Debt Resolved}$$

---

## 10. Distinct Finding Classification

AIShield explicitly classifies all findings into three distinct tiers:

```
┌────────────────────────────────────────────────────────────────────────────┐
│ 1. Verified Scanner Findings (Deterministic)                               │
│    • Source: Semgrep, Gitleaks, OSV-Scanner                                │
│    • Validation: AST rules, regex signatures, CVE database matches         │
│    • Confidence: 0.90 – 1.0 (High certainty)                               │
├────────────────────────────────────────────────────────────────────────────┤
│ 2. AI-Generated Findings (Contextual & Heuristic)                          │
│    • Source: AI Contextual Analyzer (Gemini / OpenAI)                      │
│    • Validation: LLM reasoning over diff context + Zod schema validation   │
│    • Confidence: 0.70 – 0.95 (Requires human review)                       │
├────────────────────────────────────────────────────────────────────────────┤
│ 3. Security Debt Estimates (Mathematical Metric)                           │
│    • Source: Security Debt Scoring Engine                                  │
│    • Output: 0–100 Score, Risk Grade (A–F), Delta (ΔDebt)                  │
│    • Role: Prioritization metric, not an absolute security guarantee       │
└────────────────────────────────────────────────────────────────────────────┘
```

---

## 11. GitHub PR Workflow & Developer Experience

1. **Developer opens/updates a Pull Request**: GitHub Actions triggers the AIShield workflow.
2. **Scanner Pipeline Execution**: Deterministic scanners and the AI analyzer evaluate the changed files in parallel.
3. **PR Delta Calculation**: The engine correlates HEAD findings with BASE findings to compute the net debt delta.
4. **GitHub Check Run Update**: Updates GitHub Checks with conclusion (`success`, `neutral`, `failure`) and detailed summary annotations.
5. **Sticky PR Comment**: Posts/updates a single clean markdown comment detailing:
   - Security Debt Delta table.
   - Policy verdict (`PASS`, `WARN`, `FAIL`).
   - Newly introduced vulnerabilities.
   - Resolved vulnerabilities.
   - Top security risk contributors with remediation guidance.
6. **Zero Auto-Merge Guarantee**: AIShield acts purely as an informational security advisor. Developers retain full authority to review, fix, and merge code.

---

## 12. Tech Stack

- **Backend API:** Node.js (v20+), Express.js 5, TypeScript, Zod, Pino Structured Logger, Helmet, Rate Limiting.
- **Background Worker:** BullMQ, IORedis, Node.js worker pool.
- **Database & Queue:** MongoDB 7.0 (Mongoose), Redis 7.2 Alpine.
- **Frontend Dashboard:** React 19, TypeScript, Vite, Tailwind CSS, Lucide Icons, Nginx Alpine.
- **Security Scanners:** Semgrep CLI, Gitleaks CLI, OSV-Scanner CLI, Custom Docker runner.
- **AI Integration:** Google Gemini API (`@google/genai`), OpenAI API, Zod structured output parsers.
- **Testing:** Vitest, Supertest, MongoMemoryServer, Docker test containers (401+ automated tests).

---

## 13. Installation & Prerequisites

### Prerequisites:
- **Node.js:** `>= 20.19.0`
- **npm:** `>= 10.0.0`
- **Docker & Docker Compose:** Version 2.20+ (for containerized execution)
- **Git:** Version 2.30+

### Clone and Install Dependencies:
```bash
# Clone the repository
git clone https://github.com/your-org/aishield.git
cd aishield

# Install dependencies across all npm workspaces
npm install

# Build shared TypeScript contracts
npm run build:shared
```

---

## 14. Environment Variables Reference

Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `NODE_ENV` | Yes | `production` | Environment mode (`development`, `production`, `test`) |
| `LOG_LEVEL` | No | `info` | Logging verbosity (`debug`, `info`, `warn`, `error`) |
| `API_PORT` | No | `4000` | Port for the Express REST API |
| `API_KEY` | Yes | — | 32+ character secret for authenticating API requests |
| `SKIP_AUTH` | No | `false` | Set `true` only for local development bypass |
| `CORS_ORIGINS` | No | `http://localhost:8080` | Allowed browser origins for CORS |
| `MONGO_URI` | Yes | — | MongoDB connection URI with authentication |
| `MONGO_ROOT_USERNAME` | Yes | `aishield_admin` | MongoDB root administrator username |
| `MONGO_ROOT_PASSWORD` | Yes | — | MongoDB root administrator password |
| `MONGO_DATABASE` | No | `aishield` | Primary MongoDB database name |
| `REDIS_URL` | Yes | — | Redis connection string (`redis://:password@host:6379`) |
| `REDIS_PASSWORD` | Yes | — | Redis authentication password |
| `QUEUE_PREFIX` | No | `aishield` | BullMQ queue prefix namespace |
| `QUEUE_CONCURRENCY` | No | `4` | Number of concurrent scan jobs per worker |
| `SCANNER_RUNNER` | No | `docker` | Scanner execution runner (`docker` or `local`) |
| `SCANNER_TIMEOUT_MS` | No | `120000` | Maximum execution timeout per scanner (in ms) |
| `AI_PROVIDER` | No | `gemini` | LLM provider (`gemini`, `openai`, or `mock`) |
| `AI_API_KEY` | Conditional | — | API key for Google Gemini or OpenAI |
| `AI_MODEL` | No | `gemini-2.5-flash`| LLM model identifier |
| `GITHUB_TOKEN` | Conditional | — | GitHub token for posting PR comments and check runs |
| `DASHBOARD_URL` | No | `http://localhost:8080`| Public URL of the React dashboard |

---

## 15. Local Development Workflow

### Option A: Local Host Processes + Containerized Databases
```bash
# 1. Start MongoDB and Redis in Docker
docker compose up -d mongo redis

# 2. Launch API, Worker, and Frontend concurrently in watch mode
npm run dev
```
- **Web Dashboard:** [http://localhost:5173](http://localhost:5173)
- **API Server:** [http://localhost:4000](http://localhost:4000)
- **OpenAPI Docs:** [http://localhost:4000/docs](http://localhost:4000/docs)

### Option B: Full Containerized Development with Hot-Reloading
```bash
docker compose -f docker-compose.dev.yml up
```

---

## 16. Production Docker Setup

Deploy the hardened, network-isolated production stack:

```bash
# 1. Build and start all production containers
docker compose up -d --build

# 2. Check health status of containers
docker compose ps

# 3. View live application logs
docker compose logs -f api worker
```

#### Production Features:
- **Network Segmentation:** Three isolated networks (`frontend-net`, `backend-net`, `data-net`). Web container has zero network access to MongoDB or Redis.
- **Non-Root Execution:** All Node.js containers run under the unprivileged `node` user (UID 1000).
- **Graceful Shutdown:** `tini` manages PID 1 signal forwarding with a 30s grace period for scan draining.
- **Resource Constraints:** Explicit CPU and Memory limits and reservations on every container.

---

## 17. GitHub Integration Setup

To enable AIShield PR reviews on your GitHub organization:
1. **Create a GitHub Personal Access Token (or GitHub App):**
   - Permissions needed: `pull_requests:write`, `checks:write`, `contents:read`.
2. **Add Secret to Repository / Organization:**
   - Store the token as `AISHIELD_GITHUB_TOKEN` in your repository GitHub Secrets.
3. **Optional Webhook Configuration:**
   - If hosting AIShield API publicly, configure a repository webhook pointing to `https://your-aishield-api.com/api/webhooks/github` with secret validation.

---

## 18. GitHub Actions CI/CD Integration

Add `.github/workflows/aishield.yml` to your repository:

```yaml
name: AIShield Security Debt Analysis

on:
  pull_request:
    branches: [ main, master, develop ]

jobs:
  aishield-scan:
    name: AIShield PR Security Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write

    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Run AIShield Analysis
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          AI_PROVIDER: gemini
          AI_API_KEY: ${{ secrets.GEMINI_API_KEY }}
          FAIL_ON_CRITICAL: 'true'
          FAIL_ON_HIGH: 'false'
        run: |
          npx @aishield/worker run-pr-analysis
```

---

## 19. Security Policy Configuration

AIShield allows defining deterministic security policies via `.aishield/policy.yml` in the target repository root:

```yaml
version: '1.0'
policy:
  name: 'Standard Production Policy'
  rules:
    maxAllowedNewFindings:
      maxCriticalAllowed: 0
      maxHighAllowed: 0
      maxMediumAllowed: 5
    maxDebtScoreThreshold:
      failScore: 60
      warnScore: 35
    maxAllowedDebtIncrease: 10
    forbiddenCategories:
      - secret_exposure
      - injection
```

---

## 20. Security Considerations & Threat Modeling

AIShield treats all scanned repositories and pull requests as **untrusted input**:

1. **Zero Execution of Untrusted Code:**
   - Static scanners inspect source code strictly as inert text.
   - The scanner never executes repository scripts (`npm run`, `node`, `make`, `setup.py`, etc.).
2. **Prompt Injection Sandboxing:**
   - Source code passed to the LLM is fenced, stripped of control instructions, and isolated from system directives.
3. **Secret Redaction:**
   - All secret matches discovered by Gitleaks are masked (`ghp_****...`) before leaving the scanner memory.
4. **Path Traversal Protection:**
   - All file paths reported by scanners are validated and normalized using strict boundary checks against the target repository root.
5. **Denial of Service Limits:**
   - Strict execution timeouts (`120s`), process buffer limits (`10MB`), and regex recursion guards prevent ReDoS attacks and runaway processes.

---

## 21. System Limitations

- **Informational Assistant, Not an Absolute Guarantee:** AIShield significantly reduces security debt and catches common vulnerabilities, but cannot prove the complete absence of zero-day flaws or complex distributed architectural exploits.
- **Dynamic Runtime Behavior:** Static analysis cannot observe runtime memory states, complex JIT behaviors, or external network firewalls.
- **LLM Heuristics:** AI contextual findings may occasionally flag edge cases that are mitigated by external infrastructure (e.g., WAFs or network VPCs) not visible in the git diff.
- **Inter-Service Data Flows:** SAST scanners evaluate individual repositories and cannot trace data flows across disparate microservices without cross-repo context.

---

## 22. Future Roadmap & Improvements

- **IDE Plugin Extensions:** Real-time pre-commit security debt indicators in VS Code and JetBrains IDEs.
- **Automated Fix PR Synthesis:** Single-click generation of hardened remediation pull requests.
- **Cross-Repository Dependency Graph:** Unified security debt analytics across entire GitHub Organizations and microservice meshes.
- **Custom Rule Studio:** Web-based rule editor for authoring proprietary Semgrep and AST rules.
- **SAML / OIDC Single Sign-On:** Enterprise authentication integration for corporate Okta / Google Workspace identity providers.

---

## 23. Testing & Verification

The AIShield monorepo maintains **401+ automated tests** across all workspaces:

```bash
# Run the complete monorepo test suite
npm test

# Run worker integration tests
npm test --workspace @aishield/worker

# Run AI analyzer schema and prompt injection tests
npm test --workspace @aishield/ai-analyzer

# Run API REST endpoint tests
npm test --workspace @aishield/api
```

---

## 24. Step-by-Step Demo Walkthrough

An intentionally vulnerable demo repository is provided at [`demo-vulnerable-app/`](file:///d:/hakathon/AIShield/demo-vulnerable-app):

1. **Run the 20-Step End-to-End Terminal Demo:**
   ```bash
   npx tsx apps/worker/src/scripts/run-e2e-demo.ts
   ```
2. **Inspect the Git PR Branch Progression in the Demo Repository:**
   - `main`: Clean baseline skeleton (`Debt = 0/100`, Policy `PASS`).
   - `pr-1-user-portal`: Introduces SQLi, hardcoded tokens, IDOR (`Debt: 0 -> 48`, Policy `FAIL`).
   - `pr-2-admin-diagnostics`: Introduces Command Injection, XSS, Path Traversal (`Debt: 48 -> 84`, Policy `FAIL`).
   - `pr-3-fix-auth-and-sqli`: Parameterizes SQL and removes hardcoded secrets (`Debt: 84 -> 38`, Policy `WARN`).
   - `pr-4-full-hardening`: Full remediation using `execFile`, PBKDF2/AES-GCM, HTML escaping (`Debt: 38 -> 0`, Policy `PASS`).
