# AIShield Debt 🛡️

> **Full Documentation & Reference Guide:** See [Complete Documentation](file:///docs/DOCUMENTATION.md) for the exhaustive 24-section architecture, mathematical scoring, security model, and API reference.

> **Important Security Disclaimer:**
> AIShield Debt is an automated security debt quantification, prioritization, and pull-request review assistant. **It does not guarantee total security or the absolute absence of vulnerabilities.** It provides quantitative risk visibility and contextual guidance to empower human security engineers and developers. AIShield never automatically merges pull requests or modifies production access control.

**AIShield Debt** is a hybrid AI-assisted code security analysis platform engineered to detect and track "silent security debt" in GitHub Pull Requests.

AI-generated and AI-assisted code often introduces functional yet insecure patterns — missing authorization guards, permissive CORS policies, unhandled edge cases, hallucinated package dependencies, and hardcoded secrets. AIShield quantifies this debt, posts non-intrusive PR review feedback, and tracks repository security trajectory over time.

---

## Architecture Overview

AIShield Debt utilizes a **two-phase hybrid architecture**:

```
                       ┌────────────────────────────────────────────────────────┐
                       │                     GitHub PR                          │
                       └───────────────────────────┬────────────────────────────┘
                                                   │
                                                   ▼
                       ┌────────────────────────────────────────────────────────┐
                       │                   AIShield API                         │
                       │           (Express, Auth, Validation)                  │
                       └───────────────────────────┬────────────────────────────┘
                                                   │ Enqueue
                                                   ▼
                       ┌────────────────────────────────────────────────────────┐
                       │                 Redis + BullMQ Queue                   │
                       └───────────────────────────┬────────────────────────────┘
                                                   │ Dequeue
                                                   ▼
                       ┌────────────────────────────────────────────────────────┐
                       │                 Scan Worker Node                       │
                       └───────────┬────────────────────────────────┬───────────┘
                                   │                                │
                       ┌───────────▼────────────┐       ┌───────────▼───────────┐
                       │ Phase 1: Deterministic │       │ Phase 2: AI Context   │
                       │ ├─ Semgrep (SAST)      │──────▶│ ├─ Logic flaws        │
                       │ ├─ Gitleaks (Secrets)  │       │ ├─ Missing auth       │
                       │ └─ OSV (Dependencies)  │       │ └─ Fix synthesis      │
                       └───────────┬────────────┘       └───────────┬───────────┘
                                   │                                │
                                   └───────────────┬────────────────┘
                                                   ▼
                       ┌────────────────────────────────────────────────────────┐
                       │                 Security Debt Engine                   │
                       │             (Fingerprint, Score 0-100, Δ)              │
                       └───────────┬────────────────────────────────┬───────────┘
                                   │                                │
                                   ▼                                ▼
                       ┌──────────────────────┐          ┌──────────────────────┐
                       │     MongoDB Store    │          │    GitHub PR Comment │
                       │ (Findings, History)  │          │   & React Dashboard  │
                       └──────────────────────┘          └──────────────────────┘
```

1. **Phase 1 (Deterministic Scanners):**
   - **Semgrep:** Static Application Security Testing (AST analysis for code injection, unsafe APIs, and bad security defaults).
   - **Gitleaks:** Secret and credential detection across git commits and diffs.
   - **OSV Scanner:** Dependency vulnerability scanning against the Open Source Vulnerabilities database.
2. **Phase 2 (AI Contextual Analyzer):**
   - Evaluates unified git diffs along with Phase 1 findings.
   - Identifies business-logic vulnerabilities, privilege escalation, missing checks, and AI hallucinated imports.
   - Generates contextual remediation diffs.
3. **Security Debt Engine:**
   - Fingerprints findings via SHA-256 to deduplicate issues across commits.
   - Calculates total debt points ($W_{\text{severity}} \times M_{\text{category}}$) and maps them to a $0 - 100$ score and letter grade (A–F).
   - Computes PR delta debt ($\Delta \text{Debt} = \text{Debt}_{\text{head}} - \text{Debt}_{\text{base}}$).
4. **Developer Empowerment (No Auto-Merge):**
   - Results are posted to GitHub as comments and Check Runs.
   - The platform never merges code; developers maintain sole decision-making authority.

---

## Monorepo Directory Structure

```text
AIShield/
├── apps/
│   ├── api/                           # Express.js REST API
│   │   ├── src/
│   │   │   ├── config/                # Environment variables schema and constants
│   │   │   ├── db/                    # Mongoose database connection and health probes
│   │   │   ├── errors/                # Centralized error hierarchy and HTTP mapping
│   │   │   ├── logging/               # Structured logging via Pino
│   │   │   ├── middleware/            # Security headers, CORS, context, error handlers
│   │   │   ├── models/                # Mongoose domain models & schemas
│   │   │   ├── queue/                 # Redis & BullMQ queue producers
│   │   │   ├── routes/                # Health and Scan API routes
│   │   │   ├── utils/                 # Redaction and timeout utilities
│   │   │   ├── app.ts                 # Express application pipeline configuration
│   │   │   └── index.ts               # Server startup and socket binding
│   │   ├── Dockerfile                 # Multi-stage production container for API
│   │   └── package.json
│   ├── web/                           # React + Vite Dashboard
│   │   ├── src/
│   │   │   ├── components/            # UI components (Header, Badges, Debt Cards, Tables)
│   │   │   ├── pages/                 # Dashboard overview page
│   │   │   ├── services/              # API HTTP client
│   │   │   ├── types/                 # Frontend view models
│   │   │   ├── App.tsx                # Root dashboard component
│   │   │   └── main.tsx               # DOM mount point
│   │   ├── Dockerfile                 # Production container with Nginx reverse proxy
│   │   ├── nginx.conf                 # Nginx proxy configuration
│   │   ├── vite.config.ts             # Vite configuration with API proxy
│   │   └── package.json
│   └── worker/                        # BullMQ Scan Worker
│       ├── src/
│       │   ├── config/                # Worker environment configuration
│       │   ├── engine/                # Debt scoring and deduplication engine
│       │   ├── queue/                 # BullMQ consumer worker
│       │   ├── runners/               # Scanner runners (Semgrep, Gitleaks, OSV, AI)
│       │   └── index.ts               # Worker bootstrap and graceful shutdown
│       ├── Dockerfile                 # Multi-stage container for Worker
│       └── package.json
├── packages/
│   └── shared/                        # Shared contracts, types, and constants
│       ├── src/
│       │   ├── constants/             # Queue names, scanner IDs, scoring weights
│       │   ├── types/                 # Scan reports, findings, API envelopes
│       │   └── index.ts
│       └── package.json
├── services/                          # Security Scanner Microservices
│   ├── semgrep/                       # Semgrep SAST scanner configuration & rules
│   │   ├── rules/                     # Custom YAML detection rules
│   │   └── Dockerfile
│   ├── gitleaks/                      # Gitleaks secret detection configuration
│   │   ├── gitleaks.toml              # Allowlist and secret regex rules
│   │   └── Dockerfile
│   ├── dependency-scanner/            # OSV dependency vulnerability scanner
│   │   └── Dockerfile
│   └── ai-analyzer/                   # LLM Contextual Security Analysis service
│       ├── src/                       # Prompts, analysis engine, provider interfaces
│       ├── Dockerfile
│       └── package.json
├── docker-compose.yml                 # Local & CI orchestration (Mongo, Redis, API, Worker, Web)
├── .env.example                       # Root environment variables template
├── eslint.config.js                   # Unified flat ESLint configuration
└── package.json                       # Monorepo root npm workspaces configuration
```

---

## Detailed Directory & File Guide

### Backend: `apps/api`
- **`src/app.ts`**: Assembles Express middleware (Pino HTTP logging, Helmet security headers, CORS origin filtering, JSON body limits, unversioned `/health` probes, and versioned `/api/v1` routes).
- **`src/index.ts`**: Orchestrates database/redis connection initialization and HTTP listener lifecycle.
- **`src/config/env.ts`**: Validates all configuration keys using Zod schemas at startup; refuses to start if critical production configuration is missing.
- **`src/routes/health.routes.ts`**:
  - `GET /health` — Liveness check (answers from process memory).
  - `GET /health/ready` — Readiness check (probes MongoDB and Redis in parallel).
- **`src/routes/scan.routes.ts`**: Contract routes for managing and initiating scans (`GET /api/v1/scans`, `POST /api/v1/scans`, `GET /api/v1/scans/:scanId`).
- **`src/models/`**: Complete Mongoose schemas for Repositories, Pull Requests, Scans, Findings, Security Debt baseline, and Historical Trends.
- **`src/middleware/error-handler.ts`**: Centralized error middleware translating application exceptions into RFC-7807 problem details envelopes.

### Frontend: `apps/web`
- **`src/components/debt/DebtScoreCard.tsx`**: Visual card displaying the calculated 0–100 security score, letter grade (A–F), accumulated debt penalty points, and open findings.
- **`src/components/debt/DebtTrendCard.tsx`**: Visualizes debt trajectory (improving, stable, worsening) and delta points vs baseline.
- **`src/components/findings/FindingsTable.tsx`**: Displays normalized findings from Semgrep, Gitleaks, OSV, and the AI analyzer.
- **`src/components/pull-requests/PullRequestTable.tsx`**: Lists active pull requests and their specific introduced debt delta ($\Delta \text{Debt}$).
- **`src/services/api.ts`**: API client communicating with backend endpoints and `/health`.
- **`Dockerfile` & `nginx.conf`**: Multi-stage Nginx container serving compiled static assets and reverse-proxying `/api` and `/health`.

### Worker: `apps/worker`
- **`src/queue/scan-worker.ts`**: BullMQ consumer processing scan jobs with concurrency controls and error handling.
- **`src/engine/debt-calculator.ts`**: Computes mathematical debt penalties using severity weights and the exponential decay curve.
- **`src/engine/deduplicator.ts`**: Computes SHA-256 fingerprints across commits and eliminates duplicate findings.
- **`src/runners/`**: Runner interfaces for Semgrep, Gitleaks, OSV-Scanner, and the AI analyzer.

### Scanner Services: `services/*`
- **`services/semgrep`**: Standalone Docker image pre-configured with security-audit rules and custom rules for insecure code patterns.
- **`services/gitleaks`**: Pre-configured Gitleaks container with allowlists for mock test files.
- **`services/dependency-scanner`**: OSV-scanner image for lockfile vulnerability analysis.
- **`services/ai-analyzer`**: LLM-driven contextual security engine for analyzing git diffs and synthesizing remediation suggestions.

### Shared Contracts: `packages/shared`
- **`constants/`**: Single source of truth for queue names (`aishield:scans`), scanner identifiers (`semgrep`, `gitleaks`, `dependency`, `ai-analyzer`), scoring weights, and grade boundaries.
- **`types/`**: Pure TypeScript contracts shared between API, Worker, and Web without runtime side-effects.

---

## Getting Started

### 1. Prerequisites
- **Node.js**: `>= 20.19.0`
- **npm**: `>= 10.0.0`
- **Docker & Docker Compose**: (for containerized execution)

### 2. Configuration
Copy the environment template to `.env`:
```bash
cp .env.example .env
```
*(No secrets are committed; update placeholders with your keys when enabling external LLM providers).*

### 3. Local Development Mode
Install dependencies across all workspaces:
```bash
npm install
```

Build the shared contract package:
```bash
npm run build:shared
```

Run tests across the entire monorepo:
```bash
npm test
```

Start in development mode with live hot-reloading:
```bash
# Option A: Run data stores via Docker, run Node apps on host
docker compose up -d mongo redis
npm run dev

# Option B: Run the entire development stack in Docker with source bind mounts
docker compose -f docker-compose.dev.yml up
```

- **Web Dashboard (Dev):** [http://localhost:5173](http://localhost:5173)
- **API Server:** [http://localhost:4000](http://localhost:4000)
- **OpenAPI Interactive Docs:** [http://localhost:4000/docs](http://localhost:4000/docs)
- **Health Endpoint:** [http://localhost:4000/health](http://localhost:4000/health)
- **Readiness Check:** [http://localhost:4000/health/ready](http://localhost:4000/health/ready)

---

### 4. Running Production Stack via Docker Compose

To build and run the complete production-grade stack with isolated networks and resource limits:

```bash
# 1. Prepare environment file
cp .env.example .env

# 2. Build and launch all production services in the background
docker compose up -d --build

# 3. Verify health status of all running services
docker compose ps
```

#### Services & Ports:
| Service | Internal Port | Host Port | Network | Health Check |
| :--- | :--- | :--- | :--- | :--- |
| **`web` (React SPA)** | `80` | `http://localhost:8080` | `frontend-net` | `GET /healthz` (200 OK) |
| **`api` (REST Backend)** | `4000` | `http://localhost:4000` | `frontend-net`, `backend-net`, `data-net` | `GET /health` |
| **`worker` (Scanner Engine)**| Background | Background | `backend-net`, `data-net` | Process + Heartbeat |
| **`mongo` (MongoDB 7.0)** | `27017` | Isolated | `data-net` | `mongosh db.adminCommand('ping')` |
| **`redis` (Redis 7.2 Alpine)** | `6379` | Isolated | `data-net` | `redis-cli ping` |

#### Stopping & Graceful Shutdown:
```bash
# Stop containers gracefully (waits up to 30s for active scans to drain)
docker compose down

# Stop containers and remove persistent volumes (fresh restart)
docker compose down -v
```

