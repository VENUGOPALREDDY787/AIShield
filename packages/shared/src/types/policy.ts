/**
 * Security check verdict reported to GitHub.
 *
 * PASS: All policy criteria met; no critical findings and debt delta within threshold.
 * WARN: Advisory issues identified (e.g. medium/high findings, debt increase) requiring human review.
 * FAIL: Severe policy breach (critical vulnerability, secrets exposed, or debt threshold exceeded).
 */
export type SecurityCheckStatus = 'PASS' | 'WARN' | 'FAIL';

/**
 * Maximum allowed new findings per severity level before triggering FAIL.
 */
export interface SeverityThresholds {
  /** Maximum allowable new CRITICAL findings (default: 0) */
  readonly maxCriticalAllowed: number;
  /** Maximum allowable new HIGH findings before FAIL (default: 0) */
  readonly maxHighAllowed: number;
  /** Optional maximum allowable new MEDIUM findings before FAIL */
  readonly maxMediumAllowed?: number;
  /** Optional maximum allowable new LOW findings before FAIL */
  readonly maxLowAllowed?: number;
}

/**
 * Configurable security policy thresholds for AIShield GitHub check runs.
 * Enables teams to adapt thresholds to their specific risk tolerance.
 */
export interface SecurityPolicyConfig {
  /** Check run name displayed in GitHub Checks (default: 'AIShield Security Debt') */
  readonly checkName?: string;
  /** Name of the policy configuration (default: 'Default Policy') */
  readonly policyName?: string;
  /** Maximum allowable new findings per severity before FAIL */
  readonly maxAllowedNewFindings?: SeverityThresholds;
  /** Maximum new debt points allowed in a single PR before FAIL */
  readonly maxNewDebtPoints?: number;
  /** Maximum net debt score change (headScore - baseScore) allowed before FAIL */
  readonly maxNetDebtChange?: number;
  /** Maximum absolute HEAD score allowed before FAIL (0-100) */
  readonly maxHeadScore?: number;
  /** If true, immediately FAIL if any secrets or credentials are introduced (default: true) */
  readonly failOnSecrets?: boolean;
  /** If true, require confirmed scanner findings for FAIL, treating AI findings as WARN */
  readonly requireConfirmedScannerForFail?: boolean;

  // Warning thresholds
  /** Whether new HIGH findings under FAIL limit trigger a WARN (default: true) */
  readonly warnOnHigh?: boolean;
  /** Whether new MEDIUM findings trigger a WARN (default: true) */
  readonly warnOnMedium?: boolean;
  /** Net debt change delta that triggers a WARN (e.g. +5) */
  readonly warnDebtDeltaThreshold?: number;
  /** Absolute HEAD score that triggers a WARN (e.g. 40) */
  readonly warnHeadScoreThreshold?: number;
  /** Warn if AI suggests high/critical vulnerabilities above confidence threshold (0.0 - 1.0) */
  readonly warnOnAIFindingsConfidence?: number;
}

/**
 * Individual evaluated policy rule condition.
 */
export interface PolicyRuleEvaluation {
  readonly ruleId: string;
  readonly description: string;
  readonly status: SecurityCheckStatus;
  readonly actualValue: number | string | boolean;
  readonly thresholdValue: number | string | boolean;
  readonly message: string;
}

/**
 * Complete evaluation result produced by the AIShield Policy Engine.
 */
export interface PolicyEvaluationResult {
  readonly overallStatus: SecurityCheckStatus;
  readonly policyName: string;
  readonly summary: string;
  readonly failReasons: readonly string[];
  readonly warnReasons: readonly string[];
  readonly passReasons: readonly string[];
  readonly ruleEvaluations: readonly PolicyRuleEvaluation[];
  readonly evaluatedAt: string;
}
