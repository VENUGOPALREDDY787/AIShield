import type {
  DebtRiskLevel,
  PolicyEvaluationResult,
  PRCommentOptions,
  PRDeltaAnalysisResult,
  SecurityDebtResult,
  UnifiedFinding,
} from '@aishield/shared';
import { redactSensitivePatterns } from '@aishield/shared';
import { evaluateSecurityPolicy } from './policy-engine.js';

export const AISHIELD_COMMENT_MARKER = '<!-- aishield-security-report -->';

/**
 * Returns a visual emoji badge for the risk level.
 */
function getRiskBadge(risk: DebtRiskLevel): string {
  switch (risk) {
    case 'CRITICAL':
      return '🔴 CRITICAL';
    case 'HIGH':
      return '🟠 HIGH';
    case 'MEDIUM':
      return '🟡 MEDIUM';
    case 'LOW':
      return '🟢 LOW';
    default:
      return risk;
  }
}

/**
 * Returns a severity badge with emoji.
 */
function getSeverityBadge(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
      return '🔴 CRITICAL';
    case 'HIGH':
      return '🟠 HIGH';
    case 'MEDIUM':
      return '🟡 MEDIUM';
    case 'LOW':
      return '🟢 LOW';
    default:
      return '⚪ INFO';
  }
}

/**
 * Formats a single finding into safe, concise markdown.
 */
function formatFindingItem(finding: UnifiedFinding): string {
  const safeTitle = redactSensitivePatterns(finding.title).text;
  const safeFile = redactSensitivePatterns(finding.file).text;
  const cweText = finding.cwe ? ` | **CWE:** ${finding.cwe}` : '';
  const ruleIdText = finding.ruleId ? `\`${finding.ruleId}\`` : '';
  const location = `${safeFile}:${finding.line}`;

  let line = `- ${getSeverityBadge(finding.severity)} **${safeTitle}** (${ruleIdText})\n`;
  line += `  - **Location:** \`${location}\` | **Category:** \`${finding.category}\`${cweText}\n`;

  if (finding.remediation) {
    const safeRemediation = redactSensitivePatterns(finding.remediation).text;
    line += `  - **Remediation:** ${safeRemediation}\n`;
  }

  return line;
}

/**
 * Generates dynamic, context-aware suggested actions based on the PR delta findings.
 */
function generateSuggestedActions(
  deltaResult: PRDeltaAnalysisResult,
  debtResult: SecurityDebtResult,
  policyResult: PolicyEvaluationResult,
): string[] {
  const actions: string[] = [];
  const introducedFindings = deltaResult.findingsIntroduced.map((d) => d.finding);
  const categories = new Set(introducedFindings.map((f) => f.category));

  if (policyResult.overallStatus === 'FAIL') {
    actions.push(
      '**Block Merge until Policy Resolved:** The security check returned **FAIL**. Resolve all flagged critical vulnerabilities or debt overruns before merging.',
    );
  } else if (policyResult.overallStatus === 'WARN') {
    actions.push(
      '**Request Security Review:** The check returned **WARN**. A peer or security team member should inspect the introduced medium/high items before merging.',
    );
  }

  if (categories.has('secrets')) {
    actions.push(
      '**Rotate Exposed Credentials:** Secrets or API tokens were detected in the PR. Revoke and rotate them immediately. Note that deleting secrets in subsequent commits does not purge them from Git history.',
    );
  }

  if (categories.has('injection') || categories.has('command_execution')) {
    actions.push(
      '**Parameterize Dynamic Inputs:** Injection vulnerabilities were detected. Replace dynamic string concatenation in queries or system commands with parameterized APIs or prepared statements.',
    );
  }

  if (categories.has('authorization') || categories.has('authentication')) {
    actions.push(
      '**Verify Access Controls:** Authentication or authorization logic was modified. Verify that role checks and session validation are enforced server-side for all affected routes.',
    );
  }

  if (categories.has('dependency')) {
    actions.push(
      '**Upgrade Vulnerable Dependencies:** Outdated packages with known vulnerabilities were introduced. Review your lockfile and upgrade to safe patched versions.',
    );
  }

  if (deltaResult.newDebt > 0) {
    actions.push(
      `**Remediate New Debt:** This PR introduces **+${deltaResult.newDebt}** new security debt. Resolve the flagged items before merging to prevent increasing default branch debt.`,
    );
  }

  if (debtResult.riskLevel === 'CRITICAL' || debtResult.riskLevel === 'HIGH') {
    actions.push(
      '**Security Review Required:** High or critical security debt was identified. Request an explicit review from the security team prior to landing this pull request.',
    );
  }

  if (actions.length === 0) {
    actions.push(
      '**Maintain Secure Hygiene:** No new security debt was introduced. Continue applying secure coding standards and principle of least privilege.',
    );
  }

  return actions;
}

/**
 * Formats the complete GitHub Pull Request comment following AIShield specification.
 *
 * Requirements:
 * - AIShield Security Report header
 * - Security Check: PASS | WARN | FAIL
 * - Overall Security Debt: XX/100
 * - Previous: XX/100
 * - Change: +XX
 * - Risk: LOW/MEDIUM/HIGH/CRITICAL
 * - New Findings: ...
 * - Resolved Findings: ...
 * - Top Security Risks: ...
 * - Suggested Actions: ...
 * - Link to full dashboard
 * - Stable marker for sticky updates
 * - No plain-text leaked secrets
 * - Never auto-merge PRs
 */
export function formatPRComment(
  deltaResult: PRDeltaAnalysisResult,
  debtResult: SecurityDebtResult,
  options: PRCommentOptions = {},
): string {
  const maxDisplay = options.maxNewFindingsToDisplay ?? 10;
  const maxRisks = options.maxTopRisksToDisplay ?? 5;
  const dashboardUrl =
    options.dashboardUrl ||
    (options.repoFullName && options.prNumber
      ? `https://aishield.dev/${options.repoFullName}/pull/${options.prNumber}`
      : 'https://aishield.dev/dashboard');

  const policyResult =
    options.policyResult ||
    evaluateSecurityPolicy(deltaResult, debtResult);

  const formattedDelta =
    deltaResult.netDebtChange > 0
      ? `+${deltaResult.netDebtChange}`
      : `${deltaResult.netDebtChange}`;

  const lines: string[] = [];

  // 1. Stable anchor for sticky comment updating
  lines.push(AISHIELD_COMMENT_MARKER);
  lines.push('## AIShield Security Report\n');

  // 2. Prominent Security Check Status (PASS / WARN / FAIL)
  const statusEmoji =
    policyResult.overallStatus === 'PASS'
      ? '🟢'
      : policyResult.overallStatus === 'WARN'
        ? '🟡'
        : '🔴';

  lines.push('### Security Check:');
  lines.push(`${statusEmoji} **${policyResult.overallStatus}** — ${policyResult.summary}\n`);

  if (policyResult.failReasons.length > 0) {
    lines.push('> ❌ **Policy Breaches:**');
    for (const r of policyResult.failReasons) {
      lines.push(`> - ${r}`);
    }
    lines.push('');
  } else if (policyResult.warnReasons.length > 0) {
    lines.push('> ⚠️ **Advisory Warnings (Review Required):**');
    for (const r of policyResult.warnReasons) {
      lines.push(`> - ${r}`);
    }
    lines.push('');
  }

  // 3. High-level metric summary adhering strictly to requested field labels
  lines.push('### Overall Security Debt:');
  lines.push(`${debtResult.score}/100\n`);

  lines.push('### Previous:');
  lines.push(`${debtResult.previousScore}/100\n`);

  lines.push('### Change:');
  lines.push(`${formattedDelta}\n`);

  lines.push('### Risk:');
  lines.push(`${debtResult.riskLevel}\n`);

  // Summary Table for visual clarity
  lines.push('| Metric | Value |');
  lines.push('| :--- | :--- |');
  lines.push(`| **Security Check** | ${statusEmoji} **${policyResult.overallStatus}** |`);
  lines.push(`| **Overall Security Debt** | **${debtResult.score}/100** |`);
  lines.push(`| **Previous** | ${debtResult.previousScore}/100 |`);
  lines.push(`| **Change** | \`${formattedDelta}\` |`);
  lines.push(`| **Risk** | **${getRiskBadge(debtResult.riskLevel)}** |`);
  lines.push(`| **New Debt Introduced** | +${deltaResult.newDebt} |`);
  lines.push(`| **Debt Resolved** | -${deltaResult.resolvedDebt} |\n`);

  // 4. New Findings section
  lines.push(`### New Findings:\n`);
  if (deltaResult.findingsIntroduced.length === 0) {
    lines.push('✅ No new security findings introduced in this pull request.\n');
  } else {
    const toShow = deltaResult.findingsIntroduced.slice(0, maxDisplay);
    for (const item of toShow) {
      lines.push(formatFindingItem(item.finding));
    }
    if (deltaResult.findingsIntroduced.length > maxDisplay) {
      const remaining = deltaResult.findingsIntroduced.length - maxDisplay;
      lines.push(
        `<details><summary>... and ${remaining} more new finding(s)</summary>\n`,
      );
      for (const item of deltaResult.findingsIntroduced.slice(maxDisplay)) {
        lines.push(formatFindingItem(item.finding));
      }
      lines.push('</details>\n');
    }
  }

  // 5. Resolved Findings section
  lines.push(`### Resolved Findings:\n`);
  if (deltaResult.findingsResolved.length === 0) {
    lines.push('None resolved in this pull request.\n');
  } else {
    for (const item of deltaResult.findingsResolved) {
      const safeTitle = redactSensitivePatterns(item.finding.title).text;
      const safeFile = redactSensitivePatterns(item.finding.file).text;
      lines.push(
        `- 🟢 ~~[${item.finding.severity}] **${safeTitle}**~~ in \`${safeFile}:${item.finding.line}\` *(Resolved)*`,
      );
    }
    lines.push('');
  }

  // 6. Top Security Risks section
  lines.push('### Top Security Risks:\n');
  if (debtResult.topContributors.length === 0) {
    lines.push('No significant security debt contributors identified.\n');
  } else {
    const topRisks = debtResult.topContributors.slice(0, maxRisks);
    topRisks.forEach((contributor, idx) => {
      const safeTitle = redactSensitivePatterns(contributor.title).text;
      const safeFile = redactSensitivePatterns(contributor.file).text;
      const safeReason = redactSensitivePatterns(contributor.reason).text;
      lines.push(
        `${idx + 1}. ${getSeverityBadge(contributor.severity)} **${safeTitle}** in \`${safeFile}:${contributor.line}\` (Debt Points: ${contributor.debtPoints})\n   - *Impact:* ${safeReason}`,
      );
    });
    lines.push('');
  }

  // 7. Suggested Actions section
  lines.push('### Suggested Actions:\n');
  const suggestions = generateSuggestedActions(deltaResult, debtResult, policyResult);
  suggestions.forEach((action, idx) => {
    lines.push(`${idx + 1}. ${action}`);
  });
  lines.push('');

  // 8. Link to full dashboard
  lines.push(`---\n🔗 **[Link to full dashboard](${dashboardUrl})**\n`);

  // 9. Explicit Non-Auto-Merge Disclaimer
  lines.push(
    '> ℹ️ *AIShield is an informational security advisor. AIShield never automatically merges or approves pull requests.*\n',
  );

  return lines.join('\n');
}
