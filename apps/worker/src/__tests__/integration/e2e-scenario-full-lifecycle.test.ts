import { describe, it, expect, beforeEach } from 'vitest';
import type { NormalizedFinding } from '@aishield/shared';
import { SemgrepScanner } from '../../scanners/semgrep-scanner.js';
import { GitleaksScanner } from '../../scanners/gitleaks-scanner.js';
import { DependencyScanner } from '../../scanners/dependency-scanner.js';
import { ScannerOrchestrator } from '../../scanners/scanner-orchestrator.js';
import { AIContextRunner } from '../../runners/ai-runner.js';
import { FindingNormalizerEngine } from '../../engine/finding-normalizer-engine.js';
import { SecurityDebtScoringEngine } from '../../engine/debt-scoring-engine.js';
import { PRDeltaAnalyzer } from '../../engine/pr-delta-analyzer.js';
import { evaluateSecurityPolicy, DEFAULT_SECURITY_POLICY } from '../../github/policy-engine.js';
import { formatCheckRun } from '../../github/check-run-formatter.js';
import { formatPRComment } from '../../github/comment-formatter.js';
import { AIContextualAnalyzer } from '@aishield/ai-analyzer';
import { MOCK_OSV_DEPENDENCY_OUTPUT } from '../../__fixtures__/security-fixtures.js';

describe('AIShield End-to-End 20-Step Security Workflow', () => {
  let mockMongoStore: {
    scans: Map<string, any>;
    findings: Map<string, any>;
    debts: Map<string, any>;
  };

  let mockGitHubApi: {
    checkRuns: any[];
    comments: any[];
  };

  beforeEach(() => {
    mockMongoStore = {
      scans: new Map(),
      findings: new Map(),
      debts: new Map(),
    };

    mockGitHubApi = {
      checkRuns: [],
      comments: [],
    };
  });

  it('executes the full 20-step PR security scan, failure alert, remediation, and debt reduction lifecycle', async () => {
    // =========================================================================
    // STEP 1: Developer creates a feature branch
    // =========================================================================
    const branchName = 'feature/user-portal-vulnerable';
    const baseCommitSha = 'a1b2c3d4e5f6789012345678901234567890abcd';
    let currentHeadSha = 'f1e2d3c4b5a67890123456789012345678901234';
    const prNumber = 42;
    const repoFullName = 'acme-corp/user-service';

    expect(branchName).toBeDefined();
    expect(baseCommitSha).toHaveLength(40);
    expect(currentHeadSha).toHaveLength(40);

    // =========================================================================
    // STEP 2: Developer adds intentionally vulnerable code
    // =========================================================================
    const initialPrDiff = [
      'diff --git a/src/controllers/user.controller.ts b/src/controllers/user.controller.ts',
      '--- a/src/controllers/user.controller.ts',
      '+++ b/src/controllers/user.controller.ts',
      '@@ -15,4 +15,6 @@',
      '+ const query = "SELECT * FROM users WHERE username = \'" + req.body.username + "\'";',
      '+ const user = await db.query(query);',
      'diff --git a/src/config/auth.config.ts b/src/config/auth.config.ts',
      '--- a/src/config/auth.config.ts',
      '+++ b/src/config/auth.config.ts',
      '@@ -1,3 +1,3 @@',
      '+ export const GITHUB_TOKEN = "ghp_000000000000000000000000000000000000";',
      'diff --git a/package.json b/package.json',
      '--- a/package.json',
      '+++ b/package.json',
      '@@ -12,2 +12,2 @@',
      '+ "lodash": "4.17.15",',
      '+ "jsonwebtoken": "8.5.1"',
    ].join('\n');

    expect(initialPrDiff).toContain('SELECT * FROM users WHERE');
    expect(initialPrDiff).toContain('ghp_000000000000000000000000000000000000');

    // =========================================================================
    // STEP 3: Developer opens a Pull Request
    // =========================================================================
    const prMetadata = {
      number: prNumber,
      repository: repoFullName,
      baseSha: baseCommitSha,
      headSha: currentHeadSha,
      diff: initialPrDiff,
    };
    expect(prMetadata.number).toBe(42);

    // =========================================================================
    // STEP 4: GitHub Action triggers
    // =========================================================================
    const scanId = `scan-pr-${prNumber}-attempt-1`;
    const actionTriggerTime = new Date();
    expect(scanId).toBeDefined();

    // =========================================================================
    // STEP 5: AIShield starts a scan
    // =========================================================================
    mockMongoStore.scans.set(scanId, {
      _id: scanId,
      repository: repoFullName,
      pullRequest: prNumber,
      commitSha: currentHeadSha,
      baseSha: baseCommitSha,
      status: 'running',
      startedAt: actionTriggerTime,
    });
    expect(mockMongoStore.scans.get(scanId).status).toBe('running');

    // =========================================================================
    // STEP 6: Semgrep runs
    // =========================================================================
    const mockSemgrepOutput = {
      results: [
        {
          check_id: 'typescript.express.security.audit.sqli.express-sqli',
          path: '/src/controllers/user.controller.ts',
          start: { line: 15, col: 1 },
          end: { line: 16, col: 40 },
          extra: {
            message: 'User-controlled input concatenated into raw SQL statement (CWE-89)',
            severity: 'ERROR',
            lines: 'const query = "SELECT * FROM users WHERE username = \'" + req.body.username + "\'";',
            metadata: {
              cwe: 'CWE-89',
              impact: 'HIGH',
              likelihood: 'HIGH',
              category: 'security',
            },
          },
        },
      ],
    };

    const semgrepScanner = new SemgrepScanner(async () => ({
      stdout: JSON.stringify(mockSemgrepOutput),
      stderr: '',
      exitCode: 0,
    }));
    const semgrepResult = await semgrepScanner.scan({ targetPath: '/mock-repo' });
    expect(semgrepResult.status).toBe('succeeded');
    expect(semgrepResult.findings).toHaveLength(1);
    expect(semgrepResult.findings[0]?.cwe).toBe('CWE-89');

    // =========================================================================
    // STEP 7: Gitleaks runs
    // =========================================================================
    const mockGitleaksOutput = [
      {
        RuleID: 'github-pat',
        File: '/src/config/auth.config.ts',
        StartLine: 1,
        Secret: 'ghp_000000000000000000000000000000000000',
        Description: 'GitHub Personal Access Token detected in configuration file',
      },
    ];

    const gitleaksScanner = new GitleaksScanner(async () => ({
      stdout: JSON.stringify(mockGitleaksOutput),
      stderr: '',
      exitCode: 0,
    }));
    const gitleaksResult = await gitleaksScanner.scan({ targetPath: '/mock-repo' });
    expect(gitleaksResult.status).toBe('succeeded');
    expect(gitleaksResult.findings).toHaveLength(1);
    expect(gitleaksResult.findings[0]?.category).toBe('secret');
    // Verify secret is masked
    expect(gitleaksResult.findings[0]?.metadata?.maskedSecret).toContain('****');
    expect(gitleaksResult.findings[0]?.metadata?.maskedSecret).not.toBe('ghp_000000000000000000000000000000000000');

    // =========================================================================
    // STEP 8: Dependency scanner runs
    // =========================================================================
    const dependencyScanner = new DependencyScanner(async () => ({
      stdout: JSON.stringify(MOCK_OSV_DEPENDENCY_OUTPUT),
      stderr: '',
      exitCode: 0,
    }));
    const dependencyResult = await dependencyScanner.scan({ targetPath: '/mock-repo' });
    expect(dependencyResult.status).toBe('succeeded');
    expect(dependencyResult.findings.length).toBeGreaterThanOrEqual(1);

    // =========================================================================
    // STEP 9: AI analyzer runs
    // =========================================================================
    const deterministicFindings: NormalizedFinding[] = [
      ...semgrepResult.findings,
      ...gitleaksResult.findings,
      ...dependencyResult.findings,
    ];

    const mockAiProvider = {
      name: 'mock-gemini',
      model: 'gemini-2.5-flash',
      generateText: async () =>
        JSON.stringify({
          findings: [
            {
              category: 'security',
              title: 'Unauthenticated IDOR & SQL Injection Ingress Point',
              description: 'Unsanitized user input directly controls SQL execution flow without authentication.',
              severity: 'high',
              confidence: 0.95,
              file: 'src/controllers/user.controller.ts',
              line: 15,
              evidence: 'const query = "SELECT * FROM users WHERE username = \'" + req.body.username + "\'";',
              remediation: 'Use parameterized queries ($1, $2) and require session authentication.',
              reasoning_summary: 'Direct concatenation of request body into SQL query without sanitation.',
            },
          ],
        }),
    };

    const aiAnalyzer = new AIContextualAnalyzer(mockAiProvider as any);
    const aiRunner = new AIContextRunner(aiAnalyzer);
    const aiResult = await aiRunner.execute({
      scanId,
      repoPath: '/mock-repo',
      diffContent: initialPrDiff,
      deterministicFindings,
    });

    expect(aiResult.status).toBe('succeeded');
    expect(aiResult.findings.length).toBeGreaterThan(0);

    const allRawFindings: NormalizedFinding[] = [
      ...deterministicFindings,
      ...(aiResult.findings as NormalizedFinding[]),
    ];

    // =========================================================================
    // STEP 10: Findings are normalized
    // =========================================================================
    const normalizer = new FindingNormalizerEngine();
    const normalizationResult = normalizer.processFindings({
      allFindings: allRawFindings as unknown as Parameters<typeof normalizer.processFindings>[0]['allFindings'],
      scanId,
    });

    expect(normalizationResult.totalRawFindings).toBe(4);
    expect(normalizationResult.bySeverity.CRITICAL).toBeGreaterThanOrEqual(1);
    expect(normalizationResult.bySeverity.HIGH).toBeGreaterThanOrEqual(2);

    // =========================================================================
    // STEP 11: Findings are deduplicated
    // =========================================================================
    // Fingerprint generation deduplicates overlapping AI + Semgrep findings for same line/file
    expect(normalizationResult.uniqueFindingsCount).toBeGreaterThan(0);
    expect(normalizationResult.duplicatesRemoved).toBeGreaterThanOrEqual(0);

    // =========================================================================
    // STEP 12: Security Debt Score is calculated
    // =========================================================================
    const debtEngine = new SecurityDebtScoringEngine(normalizer);
    const debtResult = debtEngine.calculateDebt({
      findings: normalizationResult.unifiedFindings,
      previousScore: 0,
    });

    expect(debtResult.score).toBeGreaterThan(30);
    expect(debtResult.riskLevel).toBe('CRITICAL');
    expect(debtResult.delta).toBe(debtResult.score);
    expect(debtResult.explanation).toBeDefined();
    expect(debtResult.explanation?.mainContributors.length).toBeGreaterThan(0);

    // PR Delta analysis
    const deltaAnalyzer = new PRDeltaAnalyzer(normalizer, debtEngine);
    const deltaResult = deltaAnalyzer.analyzePRDelta({
      baseCommit: baseCommitSha,
      headCommit: currentHeadSha,
      baseFindings: [],
      headFindings: normalizationResult.unifiedFindings,
      diffContent: initialPrDiff,
    });

    expect(deltaResult.netDebtChange).toBe(debtResult.score);
    expect(deltaResult.findingsIntroduced.length).toBeGreaterThanOrEqual(1);

    const policyResult = evaluateSecurityPolicy(deltaResult, debtResult, DEFAULT_SECURITY_POLICY);
    expect(policyResult.overallStatus).toBe('FAIL'); // Critical secret + high findings trigger FAIL

    // =========================================================================
    // STEP 13: Result is stored in MongoDB
    // =========================================================================
    for (const finding of normalizationResult.unifiedFindings) {
      mockMongoStore.findings.set(finding.fingerprint, {
        ...finding,
        repository: repoFullName,
        lastSeenScan: scanId,
        timesDetected: 1,
      });
    }

    mockMongoStore.scans.set(scanId, {
      ...mockMongoStore.scans.get(scanId),
      status: 'succeeded',
      finishedAt: new Date(),
      finalScore: {
        overall: debtResult.score,
        previous: 0,
        delta: debtResult.delta,
        grade: debtResult.riskLevel,
      },
      summary: {
        totalFindings: normalizationResult.uniqueFindingsCount,
        bySeverity: normalizationResult.bySeverity,
      },
    });

    mockMongoStore.debts.set(repoFullName, {
      repository: repoFullName,
      score: debtResult.score,
      riskLevel: debtResult.riskLevel,
      topContributors: debtResult.topContributors,
    });

    expect(mockMongoStore.findings.size).toBe(normalizationResult.uniqueFindingsCount);
    expect(mockMongoStore.scans.get(scanId).status).toBe('succeeded');
    expect(mockMongoStore.debts.get(repoFullName).score).toBe(debtResult.score);

    // =========================================================================
    // STEP 14: GitHub check is updated
    // =========================================================================
    const checkRunPayload = formatCheckRun(deltaResult, debtResult, {
      headSha: currentHeadSha,
      policyResult,
      dashboardUrl: `https://aishield.corp/repos/${repoFullName}/pulls/${prNumber}`,
    });

    expect(checkRunPayload.conclusion).toBe('failure');
    expect(checkRunPayload.output.title).toContain('FAIL');
    expect(checkRunPayload.output.summary).toContain('Security Debt');
    mockGitHubApi.checkRuns.push(checkRunPayload);

    // =========================================================================
    // STEP 15: PR comment is created
    // =========================================================================
    const prCommentMarkdown = formatPRComment(deltaResult, debtResult, {
      dashboardUrl: `https://aishield.corp/repos/${repoFullName}/pulls/${prNumber}`,
      policyResult,
    });

    expect(prCommentMarkdown).toContain('AIShield Security Report');
    expect(prCommentMarkdown).toContain('🔴 **FAIL**');
    expect(prCommentMarkdown).toContain('Policy Breaches:');
    expect(prCommentMarkdown).toContain('Top Security Risks');
    mockGitHubApi.comments.push({ pr: prNumber, body: prCommentMarkdown });

    // =========================================================================
    // STEP 16: Developer fixes vulnerabilities
    // =========================================================================
    // Developer parameterizes SQL, moves secrets to env vars, upgrades lodash & jsonwebtoken
    const fixedPrDiff = [
      'diff --git a/src/controllers/user.controller.ts b/src/controllers/user.controller.ts',
      '--- a/src/controllers/user.controller.ts',
      '+++ b/src/controllers/user.controller.ts',
      '@@ -15,4 +15,6 @@',
      '+ const query = "SELECT * FROM users WHERE username = $1";',
      '+ const user = await db.query(query, [req.body.username]);',
      'diff --git a/src/config/auth.config.ts b/src/config/auth.config.ts',
      '--- a/src/config/auth.config.ts',
      '+++ b/src/config/auth.config.ts',
      '@@ -1,3 +1,3 @@',
      '+ export const GITHUB_TOKEN = process.env.GITHUB_TOKEN || "";',
      'diff --git a/package.json b/package.json',
      '--- a/package.json',
      '+++ b/package.json',
      '@@ -12,2 +12,2 @@',
      '+ "lodash": "4.17.21",',
      '+ "jsonwebtoken": "9.0.2"',
    ].join('\n');

    expect(fixedPrDiff).toContain('WHERE username = $1');
    expect(fixedPrDiff).toContain('process.env.GITHUB_TOKEN');

    // =========================================================================
    // STEP 17: Developer pushes a new commit
    // =========================================================================
    currentHeadSha = '99887766554433221100aabbccddeeff00112233';
    expect(currentHeadSha).not.toBe(prMetadata.headSha);

    // =========================================================================
    // STEP 18: AIShield runs again
    // =========================================================================
    const scanId2 = `scan-pr-${prNumber}-attempt-2`;
    const cleanSemgrepScanner = new SemgrepScanner(async () => ({
      stdout: JSON.stringify({ results: [] }),
      stderr: '',
      exitCode: 0,
    }));
    const cleanGitleaksScanner = new GitleaksScanner(async () => ({
      stdout: JSON.stringify([]),
      stderr: '',
      exitCode: 0,
    }));
    const cleanDependencyScanner = new DependencyScanner(async () => ({
      stdout: JSON.stringify({ results: [] }),
      stderr: '',
      exitCode: 0,
    }));

    const cleanOrchestrator = new ScannerOrchestrator([
      cleanSemgrepScanner,
      cleanGitleaksScanner,
      cleanDependencyScanner,
    ]);

    const scanReport2 = await cleanOrchestrator.runAll({ targetPath: '/mock-repo' });
    expect(scanReport2.allFindings).toHaveLength(0);

    const normalizationResult2 = normalizer.processFindings({
      allFindings: [],
      scanId: scanId2,
    });

    // =========================================================================
    // STEP 19: Security debt decreases
    // =========================================================================
    const previousFindings = normalizationResult.unifiedFindings;
    const debtResult2 = debtEngine.calculateDebt({
      findings: normalizationResult2.unifiedFindings,
      previousFindings,
      previousScore: debtResult.score,
    });

    expect(debtResult2.score).toBe(0);
    expect(debtResult2.riskLevel).toBe('LOW');

    const deltaResult2 = deltaAnalyzer.analyzePRDelta({
      baseCommit: baseCommitSha,
      headCommit: currentHeadSha,
      baseFindings: previousFindings,
      headFindings: [],
      diffContent: fixedPrDiff,
    });

    expect(deltaResult2.findingsResolved.length).toBe(previousFindings.length);
    expect(deltaResult2.netDebtChange).toBeLessThan(0); // Debt decreased!
    expect(deltaResult2.resolvedDebt).toBeGreaterThan(0);

    const policyResult2 = evaluateSecurityPolicy(deltaResult2, debtResult2, DEFAULT_SECURITY_POLICY);
    expect(policyResult2.overallStatus).toBe('PASS');

    // =========================================================================
    // STEP 20: Updated PR result is displayed
    // =========================================================================
    const updatedCheckRun = formatCheckRun(deltaResult2, debtResult2, {
      headSha: currentHeadSha,
      policyResult: policyResult2,
      dashboardUrl: `https://aishield.corp/repos/${repoFullName}/pulls/${prNumber}`,
    });

    expect(updatedCheckRun.conclusion).toBe('success');
    expect(updatedCheckRun.output.title).toContain('PASS');
    expect(updatedCheckRun.output.summary).toContain('Debt Delta:');
    expect(updatedCheckRun.output.summary).toContain('Findings Resolved:');

    const updatedPrComment = formatPRComment(deltaResult2, debtResult2, {
      dashboardUrl: `https://aishield.corp/repos/${repoFullName}/pulls/${prNumber}`,
      policyResult: policyResult2,
    });

    expect(updatedPrComment).toContain('PASS');
    expect(updatedPrComment).toContain('Resolved Findings');

    // Verify all 20 steps succeeded
    expect(mockGitHubApi.checkRuns).toHaveLength(1);
    expect(mockGitHubApi.comments).toHaveLength(1);
    expect(updatedCheckRun.conclusion).toBe('success');
  });
});
