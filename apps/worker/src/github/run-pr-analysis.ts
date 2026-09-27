import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import {
  isValidGitRef,
  isValidGitSha,
  type NormalizedFinding,
  type PolicyEvaluationResult,
  type PRDeltaAnalysisResult,
  type PRReportResult,
  type SecurityDebtResult,
  type SecurityPolicyConfig,
} from '@aishield/shared';
import { childLogger } from '../logging/logger.js';
import { createDefaultOrchestrator } from '../scanners/index.js';
import { FindingNormalizerEngine } from '../engine/finding-normalizer-engine.js';
import {
  SecurityDebtScoringEngine,
  type ScoringFindingInput,
} from '../engine/debt-scoring-engine.js';
import { PRDeltaAnalyzer } from '../engine/pr-delta-analyzer.js';
import { GitHubClient } from './github-client.js';
import { PRReporter } from './pr-reporter.js';
import { evaluateSecurityPolicy, loadPolicyConfig, DEFAULT_SECURITY_POLICY } from './policy-engine.js';
import { AIContextRunner } from '../runners/ai-runner.js';

const log = childLogger({ component: 'github-action-pr-analysis' });

export interface AnalysisConfig {
  githubToken?: string;
  eventPath?: string;
  repository?: string;
  prNumber?: number;
  baseSha?: string;
  headSha?: string;
  repoPath?: string;
  diffContent?: string;
  dashboardUrl?: string;
  failOnCritical?: boolean;
  failOnHigh?: boolean;
  dryRun?: boolean;
  baseFindingsPath?: string;
}

/**
 * Parses GitHub Actions environment and pull_request event payload safely.
 */
export function resolveConfigFromEnv(overrides: Partial<AnalysisConfig> = {}): AnalysisConfig {
  const token = overrides.githubToken || process.env.GITHUB_TOKEN || process.env.INPUT_GITHUB_TOKEN || '';
  const eventPath = overrides.eventPath || process.env.GITHUB_EVENT_PATH || '';
  const repository = overrides.repository || process.env.GITHUB_REPOSITORY || '';

  let prNumber = overrides.prNumber;
  let baseSha = overrides.baseSha;
  let headSha = overrides.headSha;

  if (eventPath && existsSync(eventPath)) {
    try {
      const raw = readFileSync(eventPath, 'utf-8');
      const eventData = JSON.parse(raw);
      if (eventData.pull_request) {
        prNumber = prNumber || eventData.pull_request.number;
        baseSha = baseSha || eventData.pull_request.base?.sha;
        headSha = headSha || eventData.pull_request.head?.sha;
      }
    } catch (err) {
      log.warn({ err }, 'Failed to parse GITHUB_EVENT_PATH event payload');
    }
  }

  // Fallback to explicit env vars if available
  if (!prNumber && process.env.PR_NUMBER) {
    prNumber = parseInt(process.env.PR_NUMBER, 10);
  }
  if (!baseSha && process.env.BASE_SHA) {
    baseSha = process.env.BASE_SHA;
  }
  if (!headSha && (process.env.HEAD_SHA || process.env.GITHUB_SHA)) {
    headSha = process.env.HEAD_SHA || process.env.GITHUB_SHA;
  }

  const failOnCritical =
    overrides.failOnCritical !== undefined
      ? overrides.failOnCritical
      : process.env.FAIL_ON_CRITICAL !== undefined
        ? process.env.FAIL_ON_CRITICAL === 'true'
        : process.env.INPUT_FAIL_ON_CRITICAL !== undefined
          ? process.env.INPUT_FAIL_ON_CRITICAL === 'true'
          : undefined;

  const failOnHigh =
    overrides.failOnHigh !== undefined
      ? overrides.failOnHigh
      : process.env.FAIL_ON_HIGH !== undefined
        ? process.env.FAIL_ON_HIGH === 'true'
        : process.env.INPUT_FAIL_ON_HIGH !== undefined
          ? process.env.INPUT_FAIL_ON_HIGH === 'true'
          : undefined;

  const dryRun =
    overrides.dryRun ??
    (process.env.DRY_RUN === 'true' || process.env.INPUT_DRY_RUN === 'true');

  return {
    githubToken: token,
    eventPath,
    repository,
    prNumber,
    baseSha: baseSha || 'unknown-base',
    headSha: headSha || 'unknown-head',
    repoPath: overrides.repoPath || process.env.GITHUB_WORKSPACE || process.cwd(),
    diffContent: overrides.diffContent,
    dashboardUrl: overrides.dashboardUrl || process.env.DASHBOARD_URL || process.env.INPUT_DASHBOARD_URL,
    failOnCritical,
    failOnHigh,
    dryRun,
    baseFindingsPath: overrides.baseFindingsPath || process.env.BASE_FINDINGS_PATH,
  };
}

/**
 * Safely fetches the Git diff between base and head.
 * Tries GitHub API first (if token and PR number exist), then falls back to local git CLI.
 */
export async function getDiffSafely(
  client: GitHubClient | null,
  owner: string,
  repo: string,
  prNumber: number | undefined,
  baseSha: string,
  headSha: string,
  cwd: string,
): Promise<string> {
  // Option 1: GitHub API (most accurate unified PR diff directly from GitHub)
  if (client && prNumber && owner && repo) {
    try {
      const apiDiff = await client.getPullRequestDiff(owner, repo, prNumber);
      if (apiDiff && apiDiff.trim().length > 0) {
        log.info({ prNumber }, 'Obtained PR diff safely from GitHub API');
        return apiDiff;
      }
    } catch (err) {
      log.warn({ err }, 'Failed to fetch PR diff via GitHub API; falling back to git diff CLI');
    }
  }

  // Option 2: Local git diff if repository is checked out with history
  // Validate input git refs to prevent flag injection or shell tampering
  const isBaseValid = isValidGitSha(baseSha) || isValidGitRef(baseSha);
  const isHeadValid = isValidGitSha(headSha) || isValidGitRef(headSha);

  if (!isBaseValid || !isHeadValid) {
    log.warn(
      { baseSha, headSha },
      'Invalid or potentially unsafe git revisions provided; skipping local git diff CLI',
    );
    return '';
  }

  try {
    const diff = execFileSync('git', ['diff', '--', `${baseSha}...${headSha}`], {
      cwd,
      encoding: 'utf-8',
      timeout: 15000,
      maxBuffer: 10 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    return diff;
  } catch {
    // If 3-dot diff fails (shallow clone), try 2-dot diff or HEAD diff
    try {
      return execFileSync('git', ['diff', '--', baseSha, headSha], {
        cwd,
        encoding: 'utf-8',
        timeout: 15000,
        maxBuffer: 10 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'ignore'],
      });
    } catch {
      log.warn('Could not extract git diff locally; running in full-file scan mode');
      return '';
    }
  }
}

/**
 * Main entry point for AIShield PR Security Analysis.
 *
 * Security Guarantee:
 * - Scanners perform static inspection of code as inert data.
 * - Never executes repository scripts (`npm run`, `node`, `make`, etc.).
 * - Masks tokens and secret findings.
 * - Does NOT auto-merge PRs.
 */
export async function runPRAnalysis(
  userConfig: Partial<AnalysisConfig> = {},
): Promise<{
  deltaResult: PRDeltaAnalysisResult;
  debtResult: SecurityDebtResult;
  policyResult: PolicyEvaluationResult;
  reportResult?: PRReportResult;
}> {
  const config = resolveConfigFromEnv(userConfig);

  // Mask token in GitHub Actions logs if running under Actions runner
  if (config.githubToken && process.env.GITHUB_ACTIONS === 'true') {
    // eslint-disable-next-line no-console
    console.log(`::add-mask::${config.githubToken}`);
  }

  log.info(
    {
      repository: config.repository,
      prNumber: config.prNumber,
      baseSha: config.baseSha,
      headSha: config.headSha,
    },
    'Starting AIShield PR Security Debt Analysis',
  );

  const [owner, repo] = (config.repository || '').split('/');

  let client: GitHubClient | null = null;
  if (config.githubToken) {
    client = new GitHubClient({ token: config.githubToken });
  }

  // 1. Get PR Diff
  const diffContent =
    config.diffContent ??
    (await getDiffSafely(
      client,
      owner || '',
      repo || '',
      config.prNumber,
      config.baseSha!,
      config.headSha!,
      config.repoPath!,
    ));

  // 2. Run Deterministic Scanners on HEAD working directory
  const orchestrator = createDefaultOrchestrator();
  log.info({ repoPath: config.repoPath }, 'Running scanners on working tree');

  const scanReport = await orchestrator.runAll({
    targetPath: resolve(config.repoPath!),
  });

  const rawHeadFindings: NormalizedFinding[] = [...scanReport.allFindings];
  log.info(
    {
      totalFindings: rawHeadFindings.length,
      durationMs: scanReport.durationMs,
    },
    'Scanner execution completed',
  );

  // 2b. Run AI Contextual Risk Analyzer on PR Diff if available
  if (diffContent && diffContent.trim().length > 0) {
    try {
      const aiRunner = new AIContextRunner();
      log.info('Running AI Contextual Risk Analyzer on PR diff');
      const aiResult = await aiRunner.execute({
        scanId: `pr-${config.prNumber || 'analysis'}`,
        repoPath: config.repoPath!,
        diffContent,
        deterministicFindings: rawHeadFindings,
      });
      if (aiResult.status === 'succeeded' && aiResult.findings && aiResult.findings.length > 0) {
        rawHeadFindings.push(...(aiResult.findings as NormalizedFinding[]));
        log.info({ aiFindings: aiResult.findings.length }, 'AI Contextual Analyzer added findings');
      }
    } catch (err) {
      log.warn({ err }, 'AI runner encountered non-fatal error during PR analysis (pipeline continues)');
    }
  }

  // 3. Load or initialize BASE findings
  let rawBaseFindings: NormalizedFinding[] = [];
  if (config.baseFindingsPath && existsSync(config.baseFindingsPath)) {
    try {
      const data = readFileSync(config.baseFindingsPath, 'utf-8');
      rawBaseFindings = JSON.parse(data);
      log.info({ count: rawBaseFindings.length }, 'Loaded BASE findings from fixture/cache');
    } catch (err) {
      log.warn({ err }, 'Failed to read BASE_FINDINGS_PATH');
    }
  }

  // 4. Run PR Delta Analysis
  const normalizer = new FindingNormalizerEngine();
  const debtEngine = new SecurityDebtScoringEngine(normalizer);
  const deltaAnalyzer = new PRDeltaAnalyzer(normalizer, debtEngine);

  const deltaResult = deltaAnalyzer.analyzePRDelta({
    baseCommit: config.baseSha!,
    headCommit: config.headSha!,
    baseFindings: rawBaseFindings as unknown as ScoringFindingInput[],
    headFindings: rawHeadFindings as unknown as ScoringFindingInput[],
    diffContent,
  });

  // 5. Calculate head debt score
  const debtResult = debtEngine.calculateDebt({
    findings: rawHeadFindings as unknown as ScoringFindingInput[],
    previousFindings: rawBaseFindings as unknown as ScoringFindingInput[],
    previousScore: deltaResult.baseScore,
  });

  log.info(
    {
      headScore: debtResult.score,
      baseScore: debtResult.previousScore,
      netChange: deltaResult.netDebtChange,
      riskLevel: debtResult.riskLevel,
      newFindings: deltaResult.findingsIntroduced.length,
      resolvedFindings: deltaResult.findingsResolved.length,
    },
    'PR Security Debt Calculation Complete',
  );

  // 6. Evaluate Security Policy (PASS, WARN, FAIL) based on configurable thresholds
  const policyOverrides: Partial<SecurityPolicyConfig> =
    config.failOnCritical !== undefined || config.failOnHigh !== undefined
      ? {
          maxAllowedNewFindings: {
            maxCriticalAllowed:
              config.failOnCritical === false
                ? 999
                : (config.failOnCritical ? 0 : (DEFAULT_SECURITY_POLICY.maxAllowedNewFindings?.maxCriticalAllowed ?? 0)),
            maxHighAllowed:
              config.failOnHigh === true
                ? 0
                : (config.failOnHigh === false ? 999 : (DEFAULT_SECURITY_POLICY.maxAllowedNewFindings?.maxHighAllowed ?? 0)),
          },
        }
      : {};

  const policyConfig = loadPolicyConfig({
    workspaceRoot: config.repoPath,
    overrides: policyOverrides,
  });

  const policyResult = evaluateSecurityPolicy(deltaResult, debtResult, policyConfig);

  log.info(
    {
      status: policyResult.overallStatus,
      policyName: policyResult.policyName,
      summary: policyResult.summary,
    },
    'Security Policy Evaluation Complete',
  );

  // 7. Report to GitHub (Comment, Check Run, and Actions Step Summary)
  let reportResult: PRReportResult | undefined;

  if (client && owner && repo && config.prNumber && !config.dryRun) {
    const reporter = new PRReporter(client);
    reportResult = await reporter.reportPullRequest(deltaResult, debtResult, {
      owner,
      repo,
      pullNumber: config.prNumber,
      headSha: config.headSha!,
      dashboardUrl: config.dashboardUrl,
      failOnCritical: config.failOnCritical,
      failOnHigh: config.failOnHigh,
      policyResult,
    });
    log.info(
      {
        status: reportResult.status,
        commentAction: reportResult.commentResult?.action,
        checkRunId: reportResult.checkRunId,
        warnings: reportResult.warnings,
      },
      'PR Report published to GitHub',
    );
  } else {
    log.info(
      'GitHub reporting skipped (missing token, dryRun=true, or missing PR context)',
    );
  }

  return { deltaResult, debtResult, policyResult, reportResult };
}

// CLI entry point
if (process.argv[1] && process.argv[1].endsWith('run-pr-analysis.js')) {
  runPRAnalysis()
    .then(({ reportResult, policyResult }) => {
      const status = reportResult?.status || policyResult.overallStatus;
      const failOnPolicyFail =
        process.env.FAIL_ON_POLICY_FAIL === 'true' ||
        process.env.INPUT_FAIL_ON_POLICY_FAIL === 'true' ||
        process.env.FAIL_ON_CRITICAL === 'true';

      if (failOnPolicyFail && status === 'FAIL') {
        log.error({ status }, 'Failing step due to security policy FAIL');
        process.exit(1);
      }
      process.exit(0);
    })
    .catch((err) => {
      log.error({ err }, 'Fatal error during AIShield PR analysis');
      process.exit(1);
    });
}
