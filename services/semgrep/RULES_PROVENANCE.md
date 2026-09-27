# Semgrep Security Rules: Architecture, Provenance & Licensing

## 1. Overview & Role in AIShield Debt

AIShield Debt employs a **hybrid security analysis architecture** to detect silently accumulating vulnerabilities and security debt introduced in Pull Requests:

1. **Deterministic Static Analysis (SAST)**: Evaluates Abstract Syntax Trees (ASTs) against established, peer-reviewed pattern definitions to catch known syntactic vulnerabilities (e.g., raw SQL concatenation, `eval()` execution, permissive CORS wildcards).
2. **Deterministic Secret & Dependency Analysis**: Uses Gitleaks and OSV scanner engines to capture credentials and vulnerable third-party dependencies.
3. **AI Contextual Analysis**: Evaluates high-risk code diffs and findings to identify logic flaws, missing authorization controls, and context-dependent gaps that deterministic AST patterns cannot detect.
4. **Security Debt Engine**: Normalizes findings, deduplicates records, computes debt impact scores, and surfaces actionable remediation.

Semgrep serves as the deterministic SAST engine within this pipeline.

---

## 2. Rule Provenance & Dynamic Reference Architecture

### Curated Registry Rule Packs
AIShield relies on official, battle-tested security rule packs maintained by the Semgrep security community and Semgrep Inc. rather than inventing bespoke, error-prone vulnerability patterns:

- `p/security-audit`: In-depth security audit rules covering major server languages (Node.js/TypeScript, Python, Java, Go, C#, Ruby, PHP). Identifies unsafe deserialization, SSRF, command injection, path traversal, and unsafe cryptographic APIs.
- `p/owasp-top-ten`: Focused detection targeting the OWASP Top 10 Web Application Security Risks (Injection, Broken Authentication, Sensitive Data Exposure, Security Misconfiguration, etc.).
- `p/cwe-top-25`: Targeted detection covering the CWE/SANS Top 25 Most Dangerous Software Weaknesses.
- `p/default`: Core vetted rules with low false-positive rates suitable for rapid automated CI/CD scans.

### Why AIShield Does NOT Vendor / Copy Rule Repositories
AIShield explicitly avoids copying the Semgrep rule repository into this codebase for the following critical technical and architectural reasons:

1. **Rule Staleness & Drift**: Vulnerability research and CVE patterns evolve weekly. Vendoring or snapshotting thousands of YAML rules freezes rules in time, leading to false negatives on newer vulnerability variants and zero-day attack patterns.
2. **Repository Bloat**: The full Semgrep registry comprises tens of thousands of rules across dozens of frameworks, creating unnecessary repository bloat (hundreds of megabytes).
3. **Dynamic Reference Model**: By supplying rule pack slugs (e.g. `p/security-audit`, `p/owasp-top-ten`) via CLI flags (`--config <slug>`), the engine retrieves the most current, verified patterns at scan execution time or from a managed local cache.
4. **Custom Rule Extensibility**: Teams can add organization-specific rules via `customRulePaths` or the `services/semgrep/rules/` directory (e.g., `security-debt.yml`) without modifying the scanner engine.

---

## 3. Licensing & Compliance Considerations

### Engine vs. Rule Licensing
- **Semgrep CLI / Core**: Distributed under the LGPL-2.1 license (and Semgrep Community License for certain advanced features).
- **Semgrep Community Rules**: Rules in the public Semgrep Registry are generally licensed under **LGPL-2.1** or the **Commons Clause** on top of Apache 2.0 / LGPL.

### Legal Isolation via Process Boundaries
- **No In-Process Linkage**: AIShield's Node.js backend and worker communicate with Semgrep strictly across a process boundary via standard CLI execution (`execFile`) or isolated Docker containers, exchanging structured JSON over standard I/O.
- **Copyleft Containment**: Because Semgrep is invoked as an independent external utility tool (equivalent to invoking `git`, `docker`, or `gcc`), AIShield's proprietary and application codebases remain completely unencumbered by LGPL-2.1 copyleft viral provisions.
- **Rule Attribution**: When Semgrep rule findings are displayed, rule IDs (e.g., `javascript.lang.security.audit.sqli.node-postgres-sqli`), shortlinks, and rule author references are fully preserved in finding metadata.

---

## 4. Security Hardening & Zero-Code-Execution Guarantee

Running security analysis on untrusted third-party pull request code requires strict sandboxing. Static analysis must never execute repository code.

### Docker Sandboxing (`SCANNER_RUNNER=docker`)
When running in containerized mode, AIShield enforces strict Linux container isolation:

- **Read-Only Code Mount (`-v ${REPO_PATH}:/src:ro`)**: The scanned repository directory is mounted strictly read-only. Scanned source files cannot be modified, deleted, or written to.
- **Network Isolation (`--network none`)**: Container networking is completely disabled by default during code scanning to prevent SSRF, data exfiltration, or unauthorized outbound requests.
- **Dropped Linux Capabilities (`--cap-drop=ALL`)**: All root capabilities are stripped from the container.
- **No Privilege Escalation (`--security-opt=no-new-privileges`)**: Disallows `setuid` binaries or root escalation inside the container.
- **Unprivileged Working Directory (`-w /src`)**: Analysis runs within a restricted directory context.
- **Pure AST Parsing**: Semgrep does not run build scripts (`npm install`, `make`, `setup.py`), package hooks, or dynamic interpreters. It parses raw source syntax into an AST in memory.

### Path Sanitization
Findings emitted by containerized Semgrep contain container-relative prefixes (e.g. `/src/controllers/auth.ts`). AIShield's `cleanFilePath` normalizer automatically strips container mount prefixes and normalizes backslashes, ensuring that findings match the repository's relative workspace paths identically across Linux, macOS, and Windows.

---

## 5. Configuration & Usage

### Worker Environment Variables
Configure Semgrep behavior in `.env` or container environment:

```env
# Execution mode: 'docker' (recommended for isolation) or 'local' (for development)
SCANNER_RUNNER=docker

# Container image for Semgrep
SCANNER_IMAGE_SEMGREP=returntocorp/semgrep:1.78.0

# Active Semgrep rule packs (comma-separated slugs or file paths)
SEMGREP_RULES=p/security-audit,p/owasp-top-ten

# Scanner execution timeout (in milliseconds)
SCANNER_TIMEOUT_MS=300000
```

### Pull Request Changed Files Optimization
When analyzing Pull Requests, `SemgrepScanner` accepts `changedFiles` in `ScanOptions`:

```typescript
const result = await semgrepScanner.scan({
  targetPath: '/workspaces/repo',
  changedFiles: ['src/auth/jwt.ts', 'src/controllers/user.ts'],
  timeoutMs: 60000,
});
```

The scanner translates this into `--include` flags for each changed file. This allows Semgrep to parse the project while targeting analysis specifically to the lines and files introduced in the PR, minimizing scan latency and focusing on incremental security debt.
