import { describe, it, expect } from 'vitest';
import { SemgrepScanner } from '../../scanners/semgrep-scanner.js';
import { GitleaksScanner } from '../../scanners/gitleaks-scanner.js';
import { DependencyScanner } from '../../scanners/dependency-scanner.js';
import { ScannerOrchestrator } from '../../scanners/scanner-orchestrator.js';
import { FindingNormalizerEngine } from '../../engine/finding-normalizer-engine.js';
import { SecurityDebtScoringEngine } from '../../engine/debt-scoring-engine.js';
import { PRDeltaAnalyzer } from '../../engine/pr-delta-analyzer.js';
import { evaluateSecurityPolicy, DEFAULT_SECURITY_POLICY } from '../../github/policy-engine.js';
import { formatCheckRun } from '../../github/check-run-formatter.js';
import { formatPRComment } from '../../github/comment-formatter.js';
import { MOCK_OSV_DEPENDENCY_OUTPUT } from '../../__fixtures__/security-fixtures.js';

describe('AIShield End-to-End Pipeline Integration', () => {
  it('integrates Scanner → Normalizer → Scoring Engine seamlessly', async () => {
    // 1. Mock scanners returning raw outputs
    const mockSemgrepOutput = {
      results: [
        {
          check_id: 'typescript.react.security.audit.react-unsanitized-method.react-unsanitized-method',
          path: '/src/components/UserProfile.tsx',
          start: { line: 42 },
          end: { line: 42 },
          extra: {
            message: 'User input passed into dangerous innerHTML function',
            severity: 'ERROR',
            lines: 'element.innerHTML = userParam;',
            metadata: {
              cwe: 'CWE-79',
              impact: 'HIGH',
              likelihood: 'HIGH',
              category: 'security',
            },
          },
        },
      ],
    };

    const mockGitleaksOutput = [
      {
        RuleID: 'generic-api-key',
        File: '/src/config/keys.ts',
        StartLine: 12,
        Secret: 'ghp_000000000000000000000000000000000000',
        Description: 'Generic API Key detected',
      },
    ];

    const semgrep = new SemgrepScanner(async () => ({
      stdout: JSON.stringify(mockSemgrepOutput),
      stderr: '',
      exitCode: 0,
    }));

    const gitleaks = new GitleaksScanner(async () => ({
      stdout: JSON.stringify(mockGitleaksOutput),
      stderr: '',
      exitCode: 0,
    }));

    const dependency = new DependencyScanner(async () => ({
      stdout: JSON.stringify(MOCK_OSV_DEPENDENCY_OUTPUT),
      stderr: '',
      exitCode: 0,
    }));

    const orchestrator = new ScannerOrchestrator([semgrep, gitleaks, dependency]);

    // 2. Execute all scanners
    const scanReport = await orchestrator.runAll({ targetPath: '/workspace' });
    expect(scanReport.allFindings.length).toBe(3);
    expect(scanReport.results.semgrep?.status).toBe('succeeded');
    expect(scanReport.results.gitleaks?.status).toBe('succeeded');
    expect(scanReport.results.dependency?.status).toBe('succeeded');

    // 3. Normalization & Deduplication
    const normalizer = new FindingNormalizerEngine();
    const normalizedResult = normalizer.processFindings({
      allFindings: scanReport.allFindings as unknown as Parameters<typeof normalizer.processFindings>[0]['allFindings'],
      scanId: 'scan-e2e-123',
    });

    expect(normalizedResult.uniqueFindingsCount).toBe(3);
    expect(normalizedResult.bySeverity.CRITICAL).toBeGreaterThanOrEqual(1); // Gitleaks secret
    expect(normalizedResult.bySeverity.HIGH).toBeGreaterThanOrEqual(1); // SQLi / XSS / Dep

    // 4. Scoring Engine Calculation
    const debtEngine = new SecurityDebtScoringEngine(normalizer);
    const debtResult = debtEngine.calculateDebt({
      findings: normalizedResult.unifiedFindings,
      previousScore: 10,
    });

    expect(debtResult.score).toBeGreaterThan(10);
    expect(debtResult.riskLevel).toBe('CRITICAL');
    expect(debtResult.explanation).toBeDefined();
    expect(debtResult.explanation?.mainContributors.length).toBeGreaterThan(0);

    // 5. PR Delta & Policy Evaluation
    const deltaAnalyzer = new PRDeltaAnalyzer(normalizer, debtEngine);
    const deltaResult = deltaAnalyzer.analyzePRDelta({
      baseCommit: 'base-sha-1234567',
      headCommit: 'head-sha-7654321',
      baseFindings: [],
      headFindings: normalizedResult.unifiedFindings,
      diffContent: [
        'diff --git a/components/UserProfile.tsx b/components/UserProfile.tsx',
        '--- a/components/UserProfile.tsx',
        '+++ b/components/UserProfile.tsx',
        '@@ -42,1 +42,1 @@',
        '+ element.innerHTML = userParam;',
        'diff --git a/config/keys.ts b/config/keys.ts',
        '--- a/config/keys.ts',
        '+++ b/config/keys.ts',
        '@@ -12,1 +12,1 @@',
        '+ const key = "ghp_000000000000000000000000000000000000";',
        'diff --git a/package-lock.json b/package-lock.json',
        '--- a/package-lock.json',
        '+++ b/package-lock.json',
        '@@ -1,1 +1,1 @@',
        '+ "lodash": "4.17.15"',
      ].join('\n'),
    });

    expect(deltaResult.findingsIntroduced.length).toBe(3);
    expect(deltaResult.netDebtChange).toBeGreaterThan(0);

    const policyResult = evaluateSecurityPolicy(deltaResult, debtResult, DEFAULT_SECURITY_POLICY);
    expect(policyResult.overallStatus).toBe('FAIL'); // Critical secret introduces policy FAIL

    // 6. GitHub Comment & Check Run Output Formatting
    const comment = formatPRComment(deltaResult, debtResult, {
      dashboardUrl: 'https://aishield.dev/repo/pull/42',
      policyResult,
    });
    expect(comment).toContain('AIShield Security Report');
    expect(comment).toContain('FAIL');
    expect(comment).toContain('Top Security Risks');

    const checkRun = formatCheckRun(deltaResult, debtResult, {
      headSha: 'head-sha-7654321',
      policyResult,
    });
    expect(checkRun.conclusion).toBe('failure');
    expect(checkRun.output.title).toContain('FAIL');
  });

  it('correctly handles clean scan with zero findings resulting in PASS policy', async () => {
    const semgrep = new SemgrepScanner(async () => ({
      stdout: JSON.stringify({ results: [] }),
      stderr: '',
      exitCode: 0,
    }));
    const gitleaks = new GitleaksScanner(async () => ({
      stdout: JSON.stringify([]),
      stderr: '',
      exitCode: 0,
    }));

    const orchestrator = new ScannerOrchestrator([semgrep, gitleaks]);
    const scanReport = await orchestrator.runAll({ targetPath: '/clean-workspace' });

    const normalizer = new FindingNormalizerEngine();
    const normalizedResult = normalizer.processFindings({
      allFindings: scanReport.allFindings as unknown as Parameters<typeof normalizer.processFindings>[0]['allFindings'],
      scanId: 'scan-clean-1',
    });

    const debtEngine = new SecurityDebtScoringEngine(normalizer);
    const debtResult = debtEngine.calculateDebt({
      findings: normalizedResult.unifiedFindings,
      previousScore: 0,
    });

    expect(debtResult.score).toBe(0);
    expect(debtResult.riskLevel).toBe('LOW');

    const deltaAnalyzer = new PRDeltaAnalyzer(normalizer, debtEngine);
    const deltaResult = deltaAnalyzer.analyzePRDelta({
      baseCommit: 'base-sha-1234567',
      headCommit: 'head-sha-7654321',
      baseFindings: [],
      headFindings: [],
    });

    const policyResult = evaluateSecurityPolicy(deltaResult, debtResult, DEFAULT_SECURITY_POLICY);
    expect(policyResult.overallStatus).toBe('PASS');

    const checkRun = formatCheckRun(deltaResult, debtResult, {
      headSha: 'head-sha-7654321',
      policyResult,
    });
    expect(checkRun.conclusion).toBe('success');
  });
});
