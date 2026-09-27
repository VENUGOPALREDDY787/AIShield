/**
 * AIShield 5-Minute Hackathon Demonstration Script
 *
 * Designed specifically for a rapid 5-minute pitch:
 * 1. Initial clean state (Score: 0/100, Grade A, LOW)
 * 2. AI-assisted code ingress (SQLi + Secret + Dep CVE + IDOR)
 * 3. PR Scan: Deterministic Scanners + AI Context Analyzer
 * 4. Security Debt Score computation (Score: 84/100, CRITICAL, +84 Delta)
 * 5. PR Check FAIL & Sticky Markdown Comment
 * 6. Developer fixes vulnerabilities & pushes new commit
 * 7. Security Debt decreases (Score: 0/100, -84 Delta, Policy PASS)
 * 8. Dashboard history updated
 */
import { SemgrepScanner } from '../apps/worker/src/scanners/semgrep-scanner.js';
import { GitleaksScanner } from '../apps/worker/src/scanners/gitleaks-scanner.js';
import { DependencyScanner } from '../apps/worker/src/scanners/dependency-scanner.js';
import { ScannerOrchestrator } from '../apps/worker/src/scanners/scanner-orchestrator.js';
import { AIContextRunner } from '../apps/worker/src/runners/ai-runner.js';
import { FindingNormalizerEngine } from '../apps/worker/src/engine/finding-normalizer-engine.js';
import { SecurityDebtScoringEngine } from '../apps/worker/src/engine/debt-scoring-engine.js';
import { PRDeltaAnalyzer } from '../apps/worker/src/engine/pr-delta-analyzer.js';
import { evaluateSecurityPolicy, DEFAULT_SECURITY_POLICY } from '../apps/worker/src/github/policy-engine.js';
import { formatCheckRun } from '../apps/worker/src/github/check-run-formatter.js';
import { formatPRComment } from '../apps/worker/src/github/comment-formatter.js';
import { MOCK_OSV_DEPENDENCY_OUTPUT } from '../apps/worker/src/__fixtures__/security-fixtures.js';
import { AIContextualAnalyzer } from '@aishield/ai-analyzer';
import type { NormalizedFinding } from '@aishield/shared';

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function header(title: string) {
  const line = '━'.repeat(74);
  console.log(`\n\x1b[36m${line}\x1b[0m`);
  console.log(`\x1b[1m\x1b[32m🛡️  AIShield Debt — 5-Minute Hackathon Demo\x1b[0m`);
  console.log(`\x1b[1m\x1b[37m   ${title}\x1b[0m`);
  console.log(`\x1b[36m${line}\x1b[0m\n`);
}

function step(num: number, title: string, takeaway: string) {
  console.log(`\x1b[1m\x1b[33m[STEP ${num}/13]\x1b[0m \x1b[1m\x1b[37m${title}\x1b[0m`);
  console.log(`  \x1b[90m💡 Key Concept: ${takeaway}\x1b[0m`);
}

async function run5MinDemo() {
  header('Live End-to-End Security Debt Quantification Demo');

  // STEP 1 & 2: Clean baseline
  step(1, 'Repository Initial Clean State', 'Clean baseline skeleton on main branch');
  step(2, 'Initial Security Debt Score', 'Repository starts with clean baseline');
  console.log('  ➜ Baseline Commit: \x1b[32m47bc9b6\x1b[0m (main)');
  console.log('  ➜ Initial Debt Score: \x1b[32m0 / 100\x1b[0m (Grade: \x1b[32mA\x1b[0m, Risk: \x1b[32mLOW\x1b[0m, Active Findings: 0)\n');
  await sleep(600);

  // STEP 3 & 4: Developer adds AI-assisted code & creates PR
  step(3, 'Developer Adds AI-Generated Code', 'Copilot/ChatGPT generated functional code with hidden vulnerabilities');
  step(4, 'Developer Opens PR #101', 'PR "feat: add user authentication and portal"');
  console.log('  ➜ Branch: \x1b[33mfeature/user-portal-vulnerable\x1b[0m (Head: 80a59a1)');
  console.log('  ➜ Files Changed: user.controller.ts, auth.config.ts, package.json\n');
  await sleep(600);

  // STEP 5: GitHub Action Triggers
  step(5, 'GitHub Action Automatically Triggers AIShield', 'CI runner executes deterministic & AI analyzers in parallel');
  console.log('  ➜ GitHub Actions workflow started: .github/workflows/aishield.yml\n');
  await sleep(400);

  // STEP 6: Rule-based deterministic scanners run
  step(6, 'Rule-Based Scanners Detect Deterministic Vulnerabilities', 'Semgrep + Gitleaks + OSV run without executing untrusted code');
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
          metadata: { cwe: 'CWE-89', impact: 'HIGH', likelihood: 'HIGH', category: 'security' },
        },
      },
    ],
  };
  const mockGitleaksOutput = [
    {
      RuleID: 'github-pat',
      File: '/src/config/auth.config.ts',
      StartLine: 1,
      Secret: 'ghp_000000000000000000000000000000000000',
      Description: 'GitHub Personal Access Token detected in configuration file',
    },
  ];
  const semgrep = new SemgrepScanner(async () => ({ stdout: JSON.stringify(mockSemgrepOutput), stderr: '', exitCode: 0 }));
  const gitleaks = new GitleaksScanner(async () => ({ stdout: JSON.stringify(mockGitleaksOutput), stderr: '', exitCode: 0 }));
  const depScanner = new DependencyScanner(async () => ({ stdout: JSON.stringify(MOCK_OSV_DEPENDENCY_OUTPUT), stderr: '', exitCode: 0 }));

  const [semgrepRes, gitleaksRes, depRes] = await Promise.all([
    semgrep.scan({ targetPath: '/repo' }),
    gitleaks.scan({ targetPath: '/repo' }),
    depScanner.scan({ targetPath: '/repo' }),
  ]);

  console.log('  ✓ \x1b[31m[Semgrep SAST]\x1b[0m CWE-89 SQL Injection on user.controller.ts:15');
  console.log('  ✓ \x1b[31m[Gitleaks Secret]\x1b[0m CWE-798 Hardcoded Token on auth.config.ts:1 (Masked: ghp_****)');
  console.log('  ✓ \x1b[33m[OSV Dependency]\x1b[0m CWE-1321 lodash@4.17.15 Prototype Pollution in package.json\n');
  await sleep(600);

  // STEP 7: AI Contextual Analyzer runs
  step(7, 'AI Analyzer Identifies Contextual Logic Gap', 'LLM reasons over PR diff and detects missing authorization guard');
  const mockAiProvider = {
    name: 'mock-gemini',
    model: 'gemini-2.5-flash',
    generateText: async () =>
      JSON.stringify({
        findings: [
          {
            category: 'security',
            title: 'Unauthenticated IDOR & Multi-Tenant Exposure',
            description: 'User input directly accesses billing records without verifying ownership or active session.',
            severity: 'high',
            confidence: 0.95,
            file: 'src/controllers/user.controller.ts',
            line: 44,
            evidence: 'export async function getUserBilling(req: Request, res: Response) { const target = req.params.userId; ... }',
            remediation: 'Verify req.user.id matches req.params.userId or require administrator role.',
            reasoning_summary: 'Missing authorization check on sensitive billing endpoint.',
          },
        ],
      }),
  };
  const aiAnalyzer = new AIContextualAnalyzer(mockAiProvider as any);
  const aiRunner = new AIContextRunner(aiAnalyzer);
  const aiRes = await aiRunner.execute({
    scanId: 'pr-101',
    repoPath: '/repo',
    diffContent: 'diff --git a/src/controllers/user.controller.ts b/src/controllers/user.controller.ts ...',
    deterministicFindings: [...semgrepRes.findings, ...gitleaksRes.findings, ...depRes.findings],
  });

  console.log('  ✓ \x1b[35m[AI Contextual Analyzer]\x1b[0m CWE-285 IDOR on user.controller.ts:44 (Missing Auth Guard)\n');
  await sleep(600);

  // STEP 8: Security Debt Engine combines findings
  step(8, 'Security Debt Engine Calculates PR Delta', 'Combines deterministic + AI findings with exponential curve');
  const normalizer = new FindingNormalizerEngine();
  const rawFindings = [...semgrepRes.findings, ...gitleaksRes.findings, ...depRes.findings, ...(aiRes.findings as NormalizedFinding[])];
  const normResult = normalizer.processFindings({ allFindings: rawFindings as any, scanId: 'pr-101' });

  const debtEngine = new SecurityDebtScoringEngine(normalizer);
  const debtResult = debtEngine.calculateDebt({ findings: normResult.unifiedFindings, previousScore: 0 });
  const deltaAnalyzer = new PRDeltaAnalyzer(normalizer, debtEngine);
  const deltaResult = deltaAnalyzer.analyzePRDelta({
    baseCommit: '47bc9b6',
    headCommit: '80a59a1',
    baseFindings: [],
    headFindings: normResult.unifiedFindings,
  });
  const policyResult = evaluateSecurityPolicy(deltaResult, debtResult, DEFAULT_SECURITY_POLICY);

  console.log(`  ➜ Total Security Debt: \x1b[31m${debtResult.score} / 100\x1b[0m (Grade: \x1b[31mD\x1b[0m, Risk: \x1b[31mCRITICAL\x1b[0m)`);
  console.log(`  ➜ PR Delta: \x1b[31m+${deltaResult.netDebtChange} Debt Points\x1b[0m`);
  console.log(`  ➜ Security Policy Verdict: \x1b[31m🔴 ${policyResult.overallStatus}\x1b[0m (${policyResult.summary})\n`);
  await sleep(600);

  // STEP 9: PR receives report
  step(9, 'PR Receives AIShield Check & Sticky Comment', 'GitHub Check set to FAILURE, developer receives actionable remediation table');
  const checkRun = formatCheckRun(deltaResult, debtResult, { headSha: '80a59a1', policyResult });
  console.log(`  ➜ GitHub Check Status: \x1b[31m${checkRun.conclusion.toUpperCase()}\x1b[0m ("${checkRun.output.title}")`);
  console.log('  ➜ Sticky PR Comment: Posted with Debt Breakdown Table & Remediation Diffs\n');
  await sleep(600);

  // STEP 10 & 11: Developer fixes issues & pushes new commit
  step(10, 'Developer Applies Remediations', 'Parameterizes SQL ($1), moves secrets to env vars, adds IDOR guard, upgrades deps');
  step(11, 'Developer Pushes Commit a0ce028', 'Pushed to branch; GitHub Action triggers Scan #2');
  console.log('  ➜ New Commit: \x1b[32ma0ce028\x1b[0m ("fix: full application security hardening")\n');
  await sleep(600);

  // STEP 12: Security debt decreases
  step(12, 'Security Debt Decreases to 0', 'PR Delta Analyzer recognizes 4 resolved vulnerabilities');
  const normResult2 = normalizer.processFindings({ allFindings: [], scanId: 'pr-102' });
  const debtResult2 = debtEngine.calculateDebt({
    findings: normResult2.unifiedFindings,
    previousFindings: normResult.unifiedFindings,
    previousScore: debtResult.score,
  });
  const deltaResult2 = deltaAnalyzer.analyzePRDelta({
    baseCommit: '47bc9b6',
    headCommit: 'a0ce028',
    baseFindings: normResult.unifiedFindings,
    headFindings: [],
  });
  const policyResult2 = evaluateSecurityPolicy(deltaResult2, debtResult2, DEFAULT_SECURITY_POLICY);

  console.log(`  ➜ Updated Security Debt: \x1b[32m${debtResult2.score} / 100\x1b[0m (Grade: \x1b[32mA\x1b[0m, Risk: \x1b[32mLOW\x1b[0m)`);
  console.log(`  ➜ PR Net Delta: \x1b[32m${deltaResult2.netDebtChange} Points (4 Resolved Findings)\x1b[0m`);
  console.log(`  ➜ Updated Policy Verdict: \x1b[32m🟢 ${policyResult2.overallStatus}\x1b[0m`);
  console.log('  ➜ Updated GitHub Check: \x1b[32mSUCCESS\x1b[0m\n');
  await sleep(600);

  // STEP 13: Dashboard displays history
  step(13, 'Dashboard Displays Security Debt Trajectory', 'React Dashboard shows historical trajectory & metrics');
  console.log('  ➜ Dashboard URL: \x1b[36mhttp://localhost:5173\x1b[0m (or http://localhost:8080)');
  console.log('  ➜ Historical Trajectory: Baseline (0) ➔ Ingress (84) ➔ Hardened (0)\n');

  console.log('\x1b[1m\x1b[32m🎉 5-MINUTE DEMO COMPLETED SUCCESSFULLY!\x1b[0m\n');
}

run5MinDemo().catch((err) => {
  console.error('Demo encountered an error:', err);
  process.exit(1);
});
