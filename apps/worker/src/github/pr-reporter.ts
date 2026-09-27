import { appendFileSync } from 'node:fs';
import type {
  PolicyEvaluationResult,
  PRCommentOptions,
  PRDeltaAnalysisResult,
  PRReportResult,
  SecurityDebtResult,
  SecurityPolicyConfig,
} from '@aishield/shared';
import { formatPRComment } from './comment-formatter.js';
import { formatCheckRun } from './check-run-formatter.js';
import { GitHubApiError, type GitHubClient } from './github-client.js';
import { evaluateSecurityPolicy } from './policy-engine.js';

export interface PRReporterOptions extends PRCommentOptions {
  readonly owner: string;
  readonly repo: string;
  readonly pullNumber: number;
  readonly headSha: string;
  readonly failOnCritical?: boolean;
  readonly failOnHigh?: boolean;
  readonly stepSummaryPath?: string;
  readonly policyConfig?: Partial<SecurityPolicyConfig>;
  readonly policyResult?: PolicyEvaluationResult;
}

/**
 * Orchestrates GitHub PR reporting:
 * - Evaluates security policy (PASS, WARN, FAIL)
 * - Upserts the single sticky PR comment
 * - Creates/updates the GitHub Check Run
 * - Writes to GitHub Actions Step Summary
 * - Handles fork PR permission restrictions gracefully
 * - Strict Invariant: NEVER auto-merges or auto-approves PRs
 */
export class PRReporter {
  private readonly client: GitHubClient;

  constructor(client: GitHubClient) {
    this.client = client;
  }

  /**
   * Generates and publishes the complete security debt report to GitHub.
   */
  async reportPullRequest(
    deltaResult: PRDeltaAnalysisResult,
    debtResult: SecurityDebtResult,
    options: PRReporterOptions,
  ): Promise<PRReportResult> {
    const warnings: string[] = [];
    const { owner, repo, pullNumber, headSha } = options;
    const repoFullName = `${owner}/${repo}`;

    // 1. Evaluate policy thresholds (PASS, WARN, FAIL)
    const policyResult =
      options.policyResult ||
      evaluateSecurityPolicy(deltaResult, debtResult, {
        ...options.policyConfig,
        maxAllowedNewFindings: {
          maxCriticalAllowed: options.failOnCritical === false ? 999 : 0,
          maxHighAllowed: options.failOnHigh ? 0 : 999,
          ...options.policyConfig?.maxAllowedNewFindings,
        },
      });

    // 2. Format concise, actionable PR comment with prominent check status
    const commentBody = formatPRComment(deltaResult, debtResult, {
      ...options,
      repoFullName,
      prNumber: pullNumber,
      policyResult,
    });

    // 3. Format Check Run payload
    const checkPayload = formatCheckRun(deltaResult, debtResult, {
      headSha,
      failOnCritical: options.failOnCritical,
      failOnHigh: options.failOnHigh,
      policyResult,
    });

    let commentResult;
    // 4. Upsert Sticky Comment
    try {
      commentResult = await this.client.upsertStickyComment(
        owner,
        repo,
        pullNumber,
        commentBody,
      );
    } catch (err) {
      if (err instanceof GitHubApiError && err.isPermissionError) {
        warnings.push(
          `Unable to post PR comment (${err.status}): Token lacks pull-requests write permissions. ` +
            `This typically occurs on forked PRs with read-only tokens.`,
        );
      } else {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push(`Failed to upsert PR comment: ${msg}`);
      }
    }

    let checkRunId: number | undefined;
    // 5. Create Check Run
    try {
      const checkResponse = await this.client.createCheckRun(owner, repo, checkPayload);
      checkRunId = checkResponse.id;
    } catch (err) {
      if (err instanceof GitHubApiError && err.isPermissionError) {
        warnings.push(
          `Unable to create Check Run (${err.status}): Token lacks checks write permissions. ` +
            `This typically occurs on forked PRs with read-only tokens.`,
        );
      } else {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push(`Failed to create Check Run: ${msg}`);
      }
    }

    // 6. Always attempt to write to GitHub Actions Step Summary
    let stepSummaryWritten = false;
    const summaryFile = options.stepSummaryPath || process.env.GITHUB_STEP_SUMMARY;
    if (summaryFile) {
      try {
        appendFileSync(summaryFile, `${commentBody}\n\n`, 'utf-8');
        stepSummaryWritten = true;
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        warnings.push(`Failed to write GitHub Step Summary: ${msg}`);
      }
    }

    return {
      success: checkPayload.conclusion === 'success',
      conclusion: checkPayload.conclusion || 'success',
      status: policyResult.overallStatus,
      riskLevel: debtResult.riskLevel,
      headScore: debtResult.score,
      baseScore: debtResult.previousScore,
      netDebtChange: deltaResult.netDebtChange,
      newFindingsCount: deltaResult.findingsIntroduced.length,
      resolvedFindingsCount: deltaResult.findingsResolved.length,
      commentResult,
      checkRunId,
      stepSummaryWritten,
      warnings,
      policyResult,
    };
  }
}
