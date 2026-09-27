import type { NormalizedCategory, NormalizedSeverity } from './finding.js';

/**
 * Standard risk levels for AIShield Debt scores.
 */
export const DEBT_RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type DebtRiskLevel = (typeof DEBT_RISK_LEVELS)[number];

/**
 * Summary of a single finding contributing significantly to the debt score.
 */
export interface TopDebtContributor {
  readonly id: string;
  readonly fingerprint: string;
  readonly title: string;
  readonly file: string;
  readonly line: number;
  readonly severity: NormalizedSeverity;
  readonly category: NormalizedCategory;
  readonly confidence: number;
  readonly debtPoints: number;
  readonly reason: string;
}

/**
 * Detailed contributor item within a Security Debt explanation.
 */
export interface DebtExplanationContributor {
  readonly rank: number;
  readonly severity: NormalizedSeverity;
  readonly category: NormalizedCategory;
  readonly title: string;
  readonly file?: string;
  readonly line?: number;
  readonly debtPoints: number;
  readonly description: string;
}

/**
 * Concise deterministic explanation generated from structured findings.
 */
export interface DebtExplanation {
  /** Top-level summary, e.g. "Security Debt increased from 31 to 54." */
  readonly summary: string;
  /** Delta explanation statement, e.g. "Security Debt increased from 31 to 54 (+23 pts)." */
  readonly deltaStatement: string;
  /** Risk level assessment, e.g. "Risk Level: HIGH" */
  readonly riskStatement: string;
  /** Top ranked contributors strictly derived from structured findings */
  readonly mainContributors: readonly DebtExplanationContributor[];
  /** Breakdown explanation of new debt introduced */
  readonly newDebtExplanation?: string;
  /** Breakdown explanation of debt resolved */
  readonly resolvedDebtExplanation?: string;
  /** Complete plain-text formatted explanation */
  readonly textExplanation: string;
  /** Complete markdown formatted explanation for GitHub PR comments & dashboard */
  readonly markdownExplanation: string;
  /** Indicates if this explanation was generated/refined with AI assistance */
  readonly isAiAssisted?: boolean;
}

/**
 * Complete output of the Security Debt Scoring Engine.
 */
export interface SecurityDebtResult {
  /** Estimated security debt score from 0 to 100. (0 means no detected debt, NOT "perfect security"). */
  readonly score: number;
  /** Overall risk level derived from the score thresholds. */
  readonly riskLevel: DebtRiskLevel;
  /** Previous debt score for baseline comparison. */
  readonly previousScore: number;
  /** Delta: `score - previousScore`. Positive means debt increased; negative means debt improved. */
  readonly delta: number;
  /** Points/score of new debt introduced specifically by new or PR findings. */
  readonly newDebt: number;
  /** Points/score of debt resolved by findings that have been fixed or removed. */
  readonly resolvedDebt: number;
  /** Count of active findings broken down by canonical severity. */
  readonly severityBreakdown: Readonly<Record<NormalizedSeverity, number>>;
  /** Count of active findings broken down by canonical category. */
  readonly categoryBreakdown: Readonly<Record<NormalizedCategory, number>>;
  /** The most severe findings driving the debt score. */
  readonly topContributors: readonly TopDebtContributor[];
  /** Total raw debt points prior to asymptotic saturation. */
  readonly totalDebtPoints: number;
  /** Concise human-readable explanation of the scoring methodology. */
  readonly formulaSummary: string;
  /** Concise deterministic explanation derived from actual findings. */
  readonly explanation?: DebtExplanation;
}
