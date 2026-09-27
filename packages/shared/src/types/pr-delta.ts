import type { UnifiedFinding } from './finding.js';

/**
 * Status of a finding relative to a Pull Request's changes.
 */
export type FindingDeltaStatus =
  | 'new'        // Introduced specifically by this PR's code modifications
  | 'resolved'   // Existed in BASE and was fixed/eliminated in this PR
  | 'modified'   // Existed in BASE; line or context was shifted/touched, but issue pre-dated PR
  | 'unchanged'; // Existed in BASE and remains completely untouched in HEAD

/**
 * Audit record of a finding classified within the PR delta lifecycle.
 */
export interface CategorizedFindingDelta {
  readonly finding: UnifiedFinding;
  readonly status: FindingDeltaStatus;
  /** True strictly when evidence proves the finding was introduced by changed lines/files in this PR */
  readonly isIntroducedByPR: boolean;
  /** Fingerprint of the matching BASE finding if modified or unchanged */
  readonly matchedBaseFingerprint?: string;
  /** Evidence-based justification explaining why this status was assigned */
  readonly reason: string;
}

/**
 * Complete Pull Request Security Debt Delta analysis output.
 */
export interface PRDeltaAnalysisResult {
  readonly baseCommit: string;
  readonly headCommit: string;
  readonly baseScore: number;
  readonly headScore: number;
  readonly newDebt: number;
  readonly resolvedDebt: number;
  /** `headScore - baseScore`. Positive means PR increased debt; negative means PR reduced debt. */
  readonly netDebtChange: number;
  /** Findings confirmed to have been introduced by this PR */
  readonly findingsIntroduced: readonly CategorizedFindingDelta[];
  /** Findings confirmed to have been resolved by this PR */
  readonly findingsResolved: readonly CategorizedFindingDelta[];
  /** Pre-existing findings modified or line-shifted by this PR without being newly introduced */
  readonly findingsModified: readonly CategorizedFindingDelta[];
  /** Pre-existing findings untouched and identical across BASE and HEAD */
  readonly findingsUnchanged: readonly CategorizedFindingDelta[];
  readonly totalHeadFindings: number;
  readonly totalBaseFindings: number;
  readonly changedFilesCount: number;
  readonly summary: string;
}
