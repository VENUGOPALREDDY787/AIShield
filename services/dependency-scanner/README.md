# Dependency Vulnerability Scanner Service

Software Composition Analysis (SCA) using OSV-Scanner (Open Source Vulnerabilities) for AIShield Debt.

## Responsibilities
- Recursively inspects and parses lockfiles across ecosystems (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `requirements.txt`, `poetry.lock`, `pom.xml`, `build.gradle`, `go.sum`).
- Compares dependency hashes and versions against the distributed OSV database (OSV.dev, GHSA, NVD/CVE).
- Normalizes findings into standard `NormalizedFinding` objects with extracted CVE, GHSA, and CWE identifiers.
- Derives concrete remediation guidance (fixed package versions) from advisory affected ranges.
- Computes invariant fingerprints to track dependency security debt stably across Pull Requests.

## Documentation
- See [DEPENDENCY_ARCHITECTURE.md](file:///d:/hakathon/AIShield/services/dependency-scanner/DEPENDENCY_ARCHITECTURE.md) for full architectural documentation on multi-ecosystem support, vulnerability cross-referencing, severity mapping, and PR delta optimization.
