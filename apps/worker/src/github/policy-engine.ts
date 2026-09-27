import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type {
  PolicyEvaluationResult,
  PolicyRuleEvaluation,
  PRDeltaAnalysisResult,
  SecurityCheckStatus,
  SecurityDebtResult,
  SecurityPolicyConfig,
} from '@aishield/shared';
import { childLogger } from '../logging/logger.js';

const log = childLogger({ component: 'policy-engine' });

/**
 * Standard baseline security policy:
 * - 0 tolerance for CRITICAL issues and hardcoded secrets
 * - 0 tolerance for HIGH issues (can be overridden by repo policy)
 * - Configurable debt limits (thresholds are not hardcoded universally)
 * - Warns on MEDIUM issues requiring review
 */
export const DEFAULT_SECURITY_POLICY: SecurityPolicyConfig = {
  checkName: 'AIShield Security Debt',
  policyName: 'Standard Policy',
  maxAllowedNewFindings: {
    maxCriticalAllowed: 0,
    maxHighAllowed: 0,
    maxMediumAllowed: undefined,
  },
  maxNewDebtPoints: undefined,
  maxNetDebtChange: undefined,
  maxHeadScore: undefined,
  failOnSecrets: true,
  requireConfirmedScannerForFail: false,
  warnOnHigh: true,
  warnOnMedium: true,
  warnDebtDeltaThreshold: undefined,
  warnHeadScoreThreshold: undefined,
  warnOnAIFindingsConfidence: 0.8,
};

export interface LoadPolicyOptions {
  workspaceRoot?: string;
  configPath?: string;
  overrides?: Partial<SecurityPolicyConfig>;
}

/**
 * Evaluates PR security debt metrics and findings against a configurable security policy.
 * Produces a clear PASS, WARN, or FAIL status with audit details.
 *
 * Rules:
 * - PASS: No critical findings and debt change within acceptable threshold.
 * - WARN: Medium/high findings requiring review, or advisory debt delta exceeded.
 * - FAIL: Critical confirmed vulnerability, hardcoded secrets, or configurable debt threshold exceeded.
 */
export function evaluateSecurityPolicy(
  deltaResult: PRDeltaAnalysisResult,
  debtResult: SecurityDebtResult,
  customPolicy?: Partial<SecurityPolicyConfig>,
): PolicyEvaluationResult {
  const policy: SecurityPolicyConfig = {
    ...DEFAULT_SECURITY_POLICY,
    ...customPolicy,
    maxAllowedNewFindings: {
      maxCriticalAllowed:
        customPolicy?.maxAllowedNewFindings?.maxCriticalAllowed ??
        DEFAULT_SECURITY_POLICY.maxAllowedNewFindings?.maxCriticalAllowed ??
        0,
      maxHighAllowed:
        customPolicy?.maxAllowedNewFindings?.maxHighAllowed ??
        DEFAULT_SECURITY_POLICY.maxAllowedNewFindings?.maxHighAllowed ??
        0,
      maxMediumAllowed:
        customPolicy?.maxAllowedNewFindings?.maxMediumAllowed ??
        DEFAULT_SECURITY_POLICY.maxAllowedNewFindings?.maxMediumAllowed,
      maxLowAllowed:
        customPolicy?.maxAllowedNewFindings?.maxLowAllowed ??
        DEFAULT_SECURITY_POLICY.maxAllowedNewFindings?.maxLowAllowed,
    },
  };

  const policyName = policy.policyName || 'Custom Policy';
  const failReasons: string[] = [];
  const warnReasons: string[] = [];
  const passReasons: string[] = [];
  const ruleEvaluations: PolicyRuleEvaluation[] = [];

  const introduced = deltaResult.findingsIntroduced.map((d) => d.finding);

  // Filter findings based on confirmed scanner vs AI distinction
  const requireConfirmed = policy.requireConfirmedScannerForFail ?? false;
  const failCandidateFindings = requireConfirmed
    ? introduced.filter(
        (f) =>
          f.distinction === 'confirmed_scanner_finding' ||
          f.distinction === 'correlated_finding',
      )
    : introduced;

  const aiOnlyFindings = introduced.filter(
    (f) => f.distinction === 'ai_suggested_finding',
  );

  // 1. Secrets check
  const failOnSecrets = policy.failOnSecrets ?? true;
  const newSecrets = introduced.filter((f) => f.category === 'secrets');
  if (failOnSecrets) {
    if (newSecrets.length > 0) {
      const msg = `Exposed ${newSecrets.length} secret(s) or credential(s) in Pull Request. Zero secrets allowed.`;
      failReasons.push(msg);
      ruleEvaluations.push({
        ruleId: 'no-secrets',
        description: 'Pull Request must not introduce hardcoded secrets or credentials',
        status: 'FAIL',
        actualValue: newSecrets.length,
        thresholdValue: 0,
        message: msg,
      });
    } else {
      passReasons.push('No hardcoded secrets detected.');
      ruleEvaluations.push({
        ruleId: 'no-secrets',
        description: 'Pull Request must not introduce hardcoded secrets or credentials',
        status: 'PASS',
        actualValue: 0,
        thresholdValue: 0,
        message: 'No credentials or secrets introduced.',
      });
    }
  }

  // 2. Critical findings threshold
  const maxCritical = policy.maxAllowedNewFindings?.maxCriticalAllowed ?? 0;
  const newCritical = failCandidateFindings.filter((f) => f.severity === 'CRITICAL');
  if (newCritical.length > maxCritical) {
    const msg = `Introduced ${newCritical.length} new CRITICAL finding(s) (threshold: ${maxCritical}).`;
    failReasons.push(msg);
    ruleEvaluations.push({
      ruleId: 'max-critical-findings',
      description: 'Maximum allowable new CRITICAL findings',
      status: 'FAIL',
      actualValue: newCritical.length,
      thresholdValue: maxCritical,
      message: msg,
    });
  } else {
    passReasons.push(
      `New CRITICAL findings count (${newCritical.length}) within threshold (${maxCritical}).`,
    );
    ruleEvaluations.push({
      ruleId: 'max-critical-findings',
      description: 'Maximum allowable new CRITICAL findings',
      status: 'PASS',
      actualValue: newCritical.length,
      thresholdValue: maxCritical,
      message: 'CRITICAL finding count within threshold.',
    });
  }

  // 3. High findings threshold
  const maxHigh = policy.maxAllowedNewFindings?.maxHighAllowed ?? 0;
  const newHigh = failCandidateFindings.filter((f) => f.severity === 'HIGH');
  if (newHigh.length > maxHigh) {
    const msg = `Introduced ${newHigh.length} new HIGH finding(s) (threshold: ${maxHigh}).`;
    failReasons.push(msg);
    ruleEvaluations.push({
      ruleId: 'max-high-findings',
      description: 'Maximum allowable new HIGH findings',
      status: 'FAIL',
      actualValue: newHigh.length,
      thresholdValue: maxHigh,
      message: msg,
    });
  } else if (maxHigh > 0) {
    passReasons.push(
      `New HIGH findings count (${newHigh.length}) within threshold (${maxHigh}).`,
    );
    ruleEvaluations.push({
      ruleId: 'max-high-findings',
      description: 'Maximum allowable new HIGH findings',
      status: 'PASS',
      actualValue: newHigh.length,
      thresholdValue: maxHigh,
      message: 'HIGH finding count within threshold.',
    });
  }

  // 4. Net Debt Change threshold (if configured)
  if (policy.maxNetDebtChange !== undefined) {
    if (deltaResult.netDebtChange > policy.maxNetDebtChange) {
      const msg = `Net debt change (+${deltaResult.netDebtChange}) exceeded maximum allowed threshold (+${policy.maxNetDebtChange}).`;
      failReasons.push(msg);
      ruleEvaluations.push({
        ruleId: 'max-net-debt-change',
        description: 'Maximum allowable net debt change',
        status: 'FAIL',
        actualValue: deltaResult.netDebtChange,
        thresholdValue: policy.maxNetDebtChange,
        message: msg,
      });
    } else {
      passReasons.push(
        `Net debt change (${deltaResult.netDebtChange > 0 ? `+${deltaResult.netDebtChange}` : deltaResult.netDebtChange}) within allowable threshold (+${policy.maxNetDebtChange}).`,
      );
      ruleEvaluations.push({
        ruleId: 'max-net-debt-change',
        description: 'Maximum allowable net debt change',
        status: 'PASS',
        actualValue: deltaResult.netDebtChange,
        thresholdValue: policy.maxNetDebtChange,
        message: 'Net debt change within threshold.',
      });
    }
  }

  // 5. Absolute HEAD Score threshold (if configured)
  if (policy.maxHeadScore !== undefined) {
    if (debtResult.score > policy.maxHeadScore) {
      const msg = `Overall security debt score (${debtResult.score}/100) exceeded maximum policy cap (${policy.maxHeadScore}/100).`;
      failReasons.push(msg);
      ruleEvaluations.push({
        ruleId: 'max-head-score',
        description: 'Maximum allowable absolute debt score',
        status: 'FAIL',
        actualValue: debtResult.score,
        thresholdValue: policy.maxHeadScore,
        message: msg,
      });
    } else {
      passReasons.push(
        `Head security score (${debtResult.score}/100) under maximum cap (${policy.maxHeadScore}/100).`,
      );
      ruleEvaluations.push({
        ruleId: 'max-head-score',
        description: 'Maximum allowable absolute debt score',
        status: 'PASS',
        actualValue: debtResult.score,
        thresholdValue: policy.maxHeadScore,
        message: 'Overall score within threshold.',
      });
    }
  }

  // 6. Overall Risk Level evaluation
  if (debtResult.riskLevel === 'CRITICAL') {
    failReasons.push(`Overall repository security risk level is CRITICAL (${debtResult.score}/100).`);
  } else if (debtResult.riskLevel === 'HIGH') {
    if (policy.maxAllowedNewFindings?.maxHighAllowed === 0 && !policy.warnOnHigh) {
      failReasons.push(`Overall security debt risk is HIGH (${debtResult.score}/100).`);
    } else {
      warnReasons.push(`Overall security debt risk is HIGH (${debtResult.score}/100).`);
    }
  }

  // 6. Evaluate WARN conditions (only if not failed on that dimension)
  if (failReasons.length === 0) {
    // Warn on High findings if allowed under FAIL limit
    if (policy.warnOnHigh && newHigh.length > 0) {
      const msg = `${newHigh.length} new HIGH severity finding(s) introduced requiring security review.`;
      warnReasons.push(msg);
      ruleEvaluations.push({
        ruleId: 'warn-on-high',
        description: 'Warn when HIGH findings require review',
        status: 'WARN',
        actualValue: newHigh.length,
        thresholdValue: 0,
        message: msg,
      });
    }

    // Warn on Medium findings
    const newMedium = introduced.filter((f) => f.severity === 'MEDIUM');
    if (policy.warnOnMedium && newMedium.length > 0) {
      const msg = `${newMedium.length} new MEDIUM severity finding(s) introduced requiring security review.`;
      warnReasons.push(msg);
      ruleEvaluations.push({
        ruleId: 'warn-on-medium',
        description: 'Warn when MEDIUM findings require review',
        status: 'WARN',
        actualValue: newMedium.length,
        thresholdValue: 0,
        message: msg,
      });
    }

    // Warn on Debt delta threshold (if configured)
    if (
      policy.warnDebtDeltaThreshold !== undefined &&
      deltaResult.netDebtChange > policy.warnDebtDeltaThreshold
    ) {
      const msg = `Net debt increase (+${deltaResult.netDebtChange}) exceeds advisory review threshold (+${policy.warnDebtDeltaThreshold}).`;
      warnReasons.push(msg);
      ruleEvaluations.push({
        ruleId: 'warn-debt-delta',
        description: 'Warn when debt increase exceeds advisory threshold',
        status: 'WARN',
        actualValue: deltaResult.netDebtChange,
        thresholdValue: policy.warnDebtDeltaThreshold,
        message: msg,
      });
    }

    // Warn on elevated head score (if configured)
    if (
      policy.warnHeadScoreThreshold !== undefined &&
      debtResult.score >= policy.warnHeadScoreThreshold
    ) {
      const msg = `Overall security debt score (${debtResult.score}/100) is in elevated risk zone (>= ${policy.warnHeadScoreThreshold}).`;
      warnReasons.push(msg);
      ruleEvaluations.push({
        ruleId: 'warn-head-score',
        description: 'Warn when absolute debt is elevated',
        status: 'WARN',
        actualValue: debtResult.score,
        thresholdValue: policy.warnHeadScoreThreshold,
        message: msg,
      });
    }

    // Warn on AI-suggested findings if scanner confirmation is required for failure
    if (requireConfirmed && aiOnlyFindings.length > 0) {
      const severeAi = aiOnlyFindings.filter(
        (f) => f.severity === 'CRITICAL' || f.severity === 'HIGH',
      );
      if (severeAi.length > 0) {
        const msg = `AI analyzer identified ${severeAi.length} potential high/critical issue(s) requiring human verification.`;
        warnReasons.push(msg);
        ruleEvaluations.push({
          ruleId: 'warn-ai-findings',
          description: 'Warn on AI-suggested high/critical findings',
          status: 'WARN',
          actualValue: severeAi.length,
          thresholdValue: 0,
          message: msg,
        });
      }
    }
  }

  // Determine overall status
  let overallStatus: SecurityCheckStatus = 'PASS';
  let summary = 'PASS: No critical findings and debt change within acceptable threshold.';

  if (failReasons.length > 0) {
    overallStatus = 'FAIL';
    summary = `FAIL: ${failReasons.join('; ')}`;
  } else if (warnReasons.length > 0) {
    overallStatus = 'WARN';
    summary = `WARN: ${warnReasons.join('; ')}`;
  }

  return {
    overallStatus,
    policyName,
    summary,
    failReasons,
    warnReasons,
    passReasons,
    ruleEvaluations,
    evaluatedAt: new Date().toISOString(),
  };
}

/**
 * Loads and merges security policy configuration from:
 * 1. Explicit file path or workspace `.aishieldrc.json` / `.aishield.json`
 * 2. Environment variables (AISHIELD_POLICY_*)
 * 3. Default fallback thresholds
 */
export function loadPolicyConfig(options: LoadPolicyOptions = {}): SecurityPolicyConfig {
  const root = options.workspaceRoot || process.cwd();
  let fileConfig: Partial<SecurityPolicyConfig> = {};

  const candidatePaths = [
    options.configPath,
    process.env.AISHIELD_CONFIG_PATH,
    resolve(root, '.aishieldrc.json'),
    resolve(root, '.aishield.json'),
    resolve(root, '.github/aishield-policy.json'),
  ].filter(Boolean) as string[];

  for (const p of candidatePaths) {
    if (existsSync(p)) {
      try {
        const raw = readFileSync(p, 'utf-8');
        fileConfig = JSON.parse(raw);
        log.info({ configPath: p }, 'Loaded policy configuration from file');
        break;
      } catch (err) {
        log.warn({ err, configPath: p }, 'Failed to parse policy configuration file');
      }
    }
  }

  // Parse environment overrides
  const envOverrides: {
    maxCriticalAllowed?: number;
    maxHighAllowed?: number;
    maxNewDebtPoints?: number;
    maxNetDebtChange?: number;
    failOnSecrets?: boolean;
    warnOnMedium?: boolean;
    warnDebtDeltaThreshold?: number;
  } = {};

  if (process.env.AISHIELD_MAX_CRITICAL !== undefined) {
    envOverrides.maxCriticalAllowed = parseInt(process.env.AISHIELD_MAX_CRITICAL, 10);
  }

  if (process.env.AISHIELD_MAX_HIGH !== undefined) {
    envOverrides.maxHighAllowed = parseInt(process.env.AISHIELD_MAX_HIGH, 10);
  }

  if (process.env.AISHIELD_MAX_NEW_DEBT !== undefined) {
    envOverrides.maxNewDebtPoints = parseFloat(process.env.AISHIELD_MAX_NEW_DEBT);
  }

  if (process.env.AISHIELD_MAX_NET_DEBT !== undefined) {
    envOverrides.maxNetDebtChange = parseFloat(process.env.AISHIELD_MAX_NET_DEBT);
  }

  if (process.env.AISHIELD_FAIL_ON_SECRETS !== undefined) {
    envOverrides.failOnSecrets = process.env.AISHIELD_FAIL_ON_SECRETS === 'true';
  }

  if (process.env.AISHIELD_WARN_ON_MEDIUM !== undefined) {
    envOverrides.warnOnMedium = process.env.AISHIELD_WARN_ON_MEDIUM === 'true';
  }

  if (process.env.AISHIELD_WARN_DEBT_DELTA !== undefined) {
    envOverrides.warnDebtDeltaThreshold = parseFloat(process.env.AISHIELD_WARN_DEBT_DELTA);
  }

  const mergedMaxFindings = {
    maxCriticalAllowed:
      envOverrides.maxCriticalAllowed ??
      options.overrides?.maxAllowedNewFindings?.maxCriticalAllowed ??
      fileConfig.maxAllowedNewFindings?.maxCriticalAllowed ??
      DEFAULT_SECURITY_POLICY.maxAllowedNewFindings?.maxCriticalAllowed ??
      0,
    maxHighAllowed:
      envOverrides.maxHighAllowed ??
      options.overrides?.maxAllowedNewFindings?.maxHighAllowed ??
      fileConfig.maxAllowedNewFindings?.maxHighAllowed ??
      DEFAULT_SECURITY_POLICY.maxAllowedNewFindings?.maxHighAllowed ??
      0,
    maxMediumAllowed:
      options.overrides?.maxAllowedNewFindings?.maxMediumAllowed ??
      fileConfig.maxAllowedNewFindings?.maxMediumAllowed ??
      DEFAULT_SECURITY_POLICY.maxAllowedNewFindings?.maxMediumAllowed,
    maxLowAllowed:
      options.overrides?.maxAllowedNewFindings?.maxLowAllowed ??
      fileConfig.maxAllowedNewFindings?.maxLowAllowed ??
      DEFAULT_SECURITY_POLICY.maxAllowedNewFindings?.maxLowAllowed,
  };

  return {
    ...DEFAULT_SECURITY_POLICY,
    ...fileConfig,
    ...envOverrides,
    ...options.overrides,
    maxAllowedNewFindings: mergedMaxFindings,
  };
}
