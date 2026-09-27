import type { DebtRiskLevel } from './debt.js';
import type { PolicyEvaluationResult, SecurityCheckStatus } from './policy.js';

/**
 * GitHub Check Run conclusion status values.
 */
export type GitHubCheckConclusion =
  | 'success'
  | 'failure'
  | 'neutral'
  | 'cancelled'
  | 'timed_out'
  | 'action_required'
  | 'skipped';

/**
 * GitHub Check Run annotation level.
 */
export type GitHubAnnotationLevel = 'notice' | 'warning' | 'failure';

/**
 * GitHub Check Run annotation structure adhering to GitHub REST API.
 */
export interface GitHubCheckAnnotation {
  readonly path: string;
  readonly start_line: number;
  readonly end_line: number;
  readonly start_column?: number;
  readonly end_column?: number;
  readonly annotation_level: GitHubAnnotationLevel;
  readonly message: string;
  readonly title?: string;
  readonly raw_details?: string;
}

/**
 * Check Run output payload.
 */
export interface GitHubCheckRunOutput {
  readonly title: string;
  readonly summary: string;
  readonly text?: string;
  readonly annotations?: readonly GitHubCheckAnnotation[];
}

/**
 * Payload sent to GitHub Checks API (POST /repos/:owner/:repo/check-runs).
 */
export interface GitHubCheckRunPayload {
  readonly name: string;
  readonly head_sha: string;
  readonly status: 'completed' | 'in_progress' | 'queued';
  readonly conclusion?: GitHubCheckConclusion;
  readonly completed_at?: string;
  readonly output: GitHubCheckRunOutput;
}

/**
 * Options for generating PR Security Debt Comments.
 */
export interface PRCommentOptions {
  readonly dashboardUrl?: string;
  readonly repoFullName?: string;
  readonly prNumber?: number;
  readonly maxNewFindingsToDisplay?: number;
  readonly maxTopRisksToDisplay?: number;
  readonly policyResult?: PolicyEvaluationResult;
}

/**
 * Result of upserting a sticky PR comment.
 */
export interface UpsertCommentResult {
  readonly commentId: number;
  readonly action: 'created' | 'updated';
  readonly url?: string;
}

/**
 * Result of posting a PR report (both comment and check run).
 */
export interface PRReportResult {
  readonly success: boolean;
  readonly conclusion: GitHubCheckConclusion;
  readonly status?: SecurityCheckStatus;
  readonly riskLevel: DebtRiskLevel;
  readonly headScore: number;
  readonly baseScore: number;
  readonly netDebtChange: number;
  readonly newFindingsCount: number;
  readonly resolvedFindingsCount: number;
  readonly commentResult?: UpsertCommentResult;
  readonly checkRunId?: number;
  readonly stepSummaryWritten?: boolean;
  readonly warnings: readonly string[];
  readonly policyResult?: PolicyEvaluationResult;
}
