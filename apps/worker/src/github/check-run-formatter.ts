import type {
  GitHubAnnotationLevel,
  GitHubCheckAnnotation,
  GitHubCheckConclusion,
  GitHubCheckRunPayload,
  PolicyEvaluationResult,
  PRDeltaAnalysisResult,
  SecurityCheckStatus,
  SecurityDebtResult,
  UnifiedFinding,
} from '@aishield/shared';
import { redactSensitivePatterns } from '@aishield/shared';
import { evaluateSecurityPolicy } from './policy-engine.js';

export interface CheckRunFormatterOptions {
  readonly headSha: string;
  readonly checkName?: string;
  readonly failOnCritical?: boolean;
  readonly failOnHigh?: boolean;
  readonly maxAnnotations?: number;
  readonly policyResult?: PolicyEvaluationResult;
}

/**
 * Maps unified finding severity to GitHub check annotation levels.
 */
export function mapSeverityToAnnotationLevel(severity: string): GitHubAnnotationLevel {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return 'failure';
    case 'MEDIUM':
      return 'warning';
    case 'LOW':
    case 'INFO':
    default:
      return 'notice';
  }
}

/**
 * Maps a SecurityCheckStatus (PASS, WARN, FAIL) to a GitHub Check Run conclusion.
 */
export function mapPolicyStatusToConclusion(
  status: SecurityCheckStatus,
): GitHubCheckConclusion {
  switch (status) {
    case 'PASS':
      return 'success';
    case 'WARN':
      return 'neutral';
    case 'FAIL':
      return 'failure';
  }
}

/**
 * Computes GitHub Check Run conclusion based on configurable policy thresholds.
 * Evaluates PASS, WARN, or FAIL.
 * Strict Invariant: AIShield evaluates security risk; it NEVER auto-merges PRs.
 */
export function determineCheckConclusion(
  deltaResult: PRDeltaAnalysisResult,
  debtResult: SecurityDebtResult,
  options: {
    failOnCritical?: boolean;
    failOnHigh?: boolean;
    policyResult?: PolicyEvaluationResult;
  } = {},
): GitHubCheckConclusion {
  if (options.policyResult) {
    return mapPolicyStatusToConclusion(options.policyResult.overallStatus);
  }

  const policyResult = evaluateSecurityPolicy(deltaResult, debtResult, {
    maxAllowedNewFindings: {
      maxCriticalAllowed: options.failOnCritical === false ? 999 : 0,
      maxHighAllowed: options.failOnHigh ? 0 : 999,
    },
    warnOnHigh: !options.failOnHigh,
  });

  return mapPolicyStatusToConclusion(policyResult.overallStatus);
}

/**
 * Builds GitHub check annotation for a newly introduced finding.
 */
function createAnnotation(finding: UnifiedFinding): GitHubCheckAnnotation {
  const safeFile = redactSensitivePatterns(finding.file).text;
  const safeTitle = redactSensitivePatterns(finding.title).text;
  const safeDesc = redactSensitivePatterns(finding.description).text;
  const safeRemediation = finding.remediation
    ? redactSensitivePatterns(finding.remediation).text
    : '';

  const line = Math.max(1, finding.line || 1);
  const messageParts = [
    `[${finding.severity}] ${safeTitle}`,
    safeDesc,
  ];

  if (safeRemediation) {
    messageParts.push(`\nSuggested Remediation: ${safeRemediation}`);
  }

  return {
    path: safeFile.replace(/^[./\\]+/, ''),
    start_line: line,
    end_line: line,
    annotation_level: mapSeverityToAnnotationLevel(finding.severity),
    title: `[${finding.severity}] ${finding.ruleId || finding.category}`,
    message: messageParts.join('\n\n'),
  };
}

/**
 * Formats the GitHub Check Run payload for AIShield analysis.
 * Incorporates PASS, WARN, FAIL verdict and audit details.
 */
export function formatCheckRun(
  deltaResult: PRDeltaAnalysisResult,
  debtResult: SecurityDebtResult,
  options: CheckRunFormatterOptions,
): GitHubCheckRunPayload {
  const checkName = options.checkName || 'AIShield Security Debt';
  const maxAnnotations = options.maxAnnotations ?? 50;

  const policyResult: PolicyEvaluationResult =
    options.policyResult ||
    evaluateSecurityPolicy(deltaResult, debtResult, {
      maxAllowedNewFindings: {
        maxCriticalAllowed: options.failOnCritical === false ? 999 : 0,
        maxHighAllowed: options.failOnHigh ? 0 : 999,
      },
      warnOnHigh: !options.failOnHigh,
    });

  const conclusion = mapPolicyStatusToConclusion(policyResult.overallStatus);
  const policyStatus = policyResult.overallStatus;

  const formattedDelta =
    deltaResult.netDebtChange > 0
      ? `+${deltaResult.netDebtChange}`
      : `${deltaResult.netDebtChange}`;

  const title = `[${policyStatus}] Security Debt: ${debtResult.score}/100 (${debtResult.riskLevel}) | Delta: ${formattedDelta}`;

  const statusEmoji =
    policyStatus === 'PASS'
      ? '🟢'
      : policyStatus === 'WARN'
        ? '🟡'
        : '🔴';

  const summaryLines: string[] = [
    `### Security Check Verdict: ${statusEmoji} **${policyStatus}**`,
    `**Policy:** ${policyResult.policyName}`,
    `**Summary:** ${policyResult.summary}\n`,
  ];

  if (policyResult.failReasons.length > 0) {
    summaryLines.push('#### ❌ Policy Failures:');
    for (const reason of policyResult.failReasons) {
      summaryLines.push(`- ${reason}`);
    }
    summaryLines.push('');
  }

  if (policyResult.warnReasons.length > 0) {
    summaryLines.push('#### ⚠️ Advisory Warnings (Review Required):');
    for (const reason of policyResult.warnReasons) {
      summaryLines.push(`- ${reason}`);
    }
    summaryLines.push('');
  }

  summaryLines.push('---');
  summaryLines.push('#### Security Debt Metrics');
  summaryLines.push(`- **Overall Security Debt:** ${debtResult.score}/100 (${debtResult.riskLevel} Risk)`);
  summaryLines.push(`- **Previous Score:** ${debtResult.previousScore}/100`);
  summaryLines.push(`- **Debt Delta:** ${formattedDelta}`);
  summaryLines.push(`- **New Findings Introduced:** ${deltaResult.findingsIntroduced.length}`);
  summaryLines.push(`- **Findings Resolved:** ${deltaResult.findingsResolved.length}`);

  // Annotations limited to GitHub Checks API maximum of 50
  const annotations: GitHubCheckAnnotation[] = deltaResult.findingsIntroduced
    .slice(0, maxAnnotations)
    .map((item) => createAnnotation(item.finding));

  const textLines: string[] = [
    `## Severity Breakdown`,
    `- **Critical:** ${debtResult.severityBreakdown.CRITICAL}`,
    `- **High:** ${debtResult.severityBreakdown.HIGH}`,
    `- **Medium:** ${debtResult.severityBreakdown.MEDIUM}`,
    `- **Low:** ${debtResult.severityBreakdown.LOW}`,
    `- **Info:** ${debtResult.severityBreakdown.INFO}`,
    '',
    `## Category Breakdown`,
    ...Object.entries(debtResult.categoryBreakdown)
      .filter(([, count]) => count > 0)
      .map(([cat, count]) => `- **${cat}:** ${count}`),
    '',
    `## Policy Rule Evaluation Details`,
    ...policyResult.ruleEvaluations.map(
      (r) => `- **[${r.status}]** ${r.description}: ${r.message}`,
    ),
    '',
    `*Analysis completed deterministically by AIShield. AIShield never automatically merges PRs.*`,
  ];

  return {
    name: checkName,
    head_sha: options.headSha,
    status: 'completed',
    conclusion,
    completed_at: new Date().toISOString(),
    output: {
      title,
      summary: summaryLines.join('\n'),
      text: textLines.join('\n'),
      annotations,
    },
  };
}
