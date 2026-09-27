import type {
  DebtRiskLevel,
  NormalizedCategory,
  NormalizedSeverity,
  SecurityDebtResult,
  TopDebtContributor,
  UnifiedFinding,
} from '@aishield/shared';
import {
  NORMALIZED_CATEGORIES,
  NORMALIZED_SEVERITIES,
} from '@aishield/shared';
import {
  FindingNormalizerEngine,
  type FindingInput,
} from './finding-normalizer-engine.js';
import { normalizeCategory, normalizeSeverity } from './normalizer.js';
import { defaultDebtExplanationService } from './debt-explanation-service.js';

export interface ScoringFindingInput {
  id?: string;
  fingerprint?: string;
  title?: string;
  file?: string;
  line?: number;
  severity?: unknown;
  category?: unknown;
  confidence?: unknown;
  cwe?: string;
  remediation?: string;
  distinction?: string;
  contributingSources?: readonly string[];
  sources?: readonly unknown[];
  aiInsights?: {
    reasoningSummary?: string;
    suggestedRemediation?: string;
    confidence?: number;
    suggestedSeverity?: NormalizedSeverity;
  };
  metadata?: Record<string, unknown>;
  /** Indicates if this finding was introduced by the current Pull Request */
  isNewInPR?: boolean;
  /** Whether the finding was already open prior to this scan */
  isExisting?: boolean;
  /** How many consecutive scans this finding has persisted */
  timesDetected?: number;
  /** Exploitability rating if available: 'HIGH' | 'MEDIUM' | 'LOW' | 'POC' */
  exploitability?: string;
  [key: string]: unknown;
}

export interface CalculateDebtOptions {
  /** The current set of open findings in this scan/PR */
  findings: readonly (UnifiedFinding | ScoringFindingInput)[];
  /** Historical findings from the previous scan or target base branch (for delta and resolved debt) */
  previousFindings?: readonly (UnifiedFinding | ScoringFindingInput)[];
  /** Previous calculated debt score (if known, 0-100) */
  previousScore?: number;
  /** List of files modified in the Pull Request */
  prChangedFiles?: readonly string[];
  /** Maximum number of top contributors to return (default: 5) */
  maxTopContributors?: number;
}

/**
 * Base debt points by canonical severity.
 */
export const SEVERITY_BASE_POINTS: Readonly<Record<NormalizedSeverity, number>> = {
  CRITICAL: 25.0,
  HIGH: 12.0,
  MEDIUM: 5.0,
  LOW: 1.5,
  INFO: 0.3,
};

/**
 * Scale parameter K for the exponential debt saturation curve:
 * Score = 100 * (1 - e^(-TotalPoints / K))
 */
export const DEBT_SATURATION_SCALE_K = 50.0;

/**
 * Risk level thresholds based on the 0-100 debt score.
 */
export const RISK_THRESHOLDS = {
  LOW_MAX: 15,
  MEDIUM_MAX: 40,
  HIGH_MAX: 70,
} as const;

export class SecurityDebtScoringEngine {
  private readonly normalizerEngine: FindingNormalizerEngine;

  constructor(normalizerEngine?: FindingNormalizerEngine) {
    this.normalizerEngine = normalizerEngine || new FindingNormalizerEngine();
  }

  /**
   * Calculates the reproducible, deterministic Security Debt score (0-100),
   * risk level, PR delta, new debt, resolved debt, breakdowns, and top contributors.
   */
  calculateDebt(options: CalculateDebtOptions): SecurityDebtResult {
    // Step 1: Normalize and deduplicate current findings so duplicates never double-count
    const currentDedupResult = this.normalizerEngine.processFindings({
      allFindings: options.findings as unknown as readonly FindingInput[],
    });
    const activeFindings = currentDedupResult.unifiedFindings;

    // Step 2: Normalize and deduplicate previous findings (if provided)
    const prevFindings = options.previousFindings
      ? this.normalizerEngine.processFindings({
          allFindings: options.previousFindings as unknown as readonly FindingInput[],
        }).unifiedFindings
      : [];

    const prChangedSet = new Set(
      (options.prChangedFiles || []).map((f) => f.replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase()),
    );

    // Step 3: Compute individual finding debt points with all context multipliers
    const evaluatedFindings = activeFindings.map((finding) => {
      const originalInput = options.findings.find(
        (f) => (f.fingerprint && f.fingerprint === finding.fingerprint) || f.file === finding.file,
      ) as ScoringFindingInput | undefined;

      const isNewInPR =
        originalInput?.isNewInPR === true ||
        (prChangedSet.size > 0 && prChangedSet.has(finding.file.toLowerCase()));

      const timesDetected = originalInput?.timesDetected ?? 1;
      const exploitability = originalInput?.exploitability || (finding.metadata?.exploitability as string | undefined);

      const evaluation = this.evaluateFindingDebt(finding, {
        isNewInPR,
        timesDetected,
        exploitability,
      });

      return {
        finding,
        isNewInPR,
        ...evaluation,
      };
    });

    // Step 4: Systemic blast radius penalty based on number of affected files
    const affectedFiles = new Set(activeFindings.map((f) => f.file).filter(Boolean));
    const fileCount = affectedFiles.size;
    const blastRadiusMultiplier = fileCount > 1 ? 1 + 0.05 * Math.min(fileCount - 1, 10) : 1.0;

    let totalRawPoints = 0;
    for (const item of evaluatedFindings) {
      totalRawPoints += item.debtPoints;
    }
    totalRawPoints = Number((totalRawPoints * blastRadiusMultiplier).toFixed(2));

    // Step 5: Asymptotic saturation curve mapping to [0, 100]
    const currentScore = this.rawPointsToScore(totalRawPoints);
    const riskLevel = this.determineRiskLevel(currentScore);

    // Step 6: Compute Previous Score, PR Delta, New Debt, and Resolved Debt
    let previousScore = options.previousScore;
    if (previousScore === undefined) {
      if (prevFindings.length > 0) {
        // Calculate previous score directly from previous findings
        const prevEvaluated = prevFindings.map((pf) => this.evaluateFindingDebt(pf));
        let prevRaw = prevEvaluated.reduce((acc, curr) => acc + curr.debtPoints, 0);
        const prevFileCount = new Set(prevFindings.map((f) => f.file).filter(Boolean)).size;
        if (prevFileCount > 1) prevRaw *= 1 + 0.05 * Math.min(prevFileCount - 1, 10);
        previousScore = this.rawPointsToScore(prevRaw);
      } else {
        previousScore = 0;
      }
    }

    const delta = Number((currentScore - previousScore).toFixed(2));

    // Calculate New Debt introduced in this scan/PR
    const currentFpSet = new Set(prevFindings.map((f) => f.fingerprint));
    const newItems = evaluatedFindings.filter(
      (item) => item.isNewInPR || !currentFpSet.has(item.finding.fingerprint),
    );
    const newRawPoints = newItems.reduce((acc, curr) => acc + curr.debtPoints, 0);
    const newDebt = this.rawPointsToScore(newRawPoints);

    // Calculate Resolved Debt (findings in previous scan that are no longer in current scan)
    const activeFpSet = new Set(activeFindings.map((f) => f.fingerprint));
    const resolvedFindings = prevFindings.filter((pf) => !activeFpSet.has(pf.fingerprint));
    let resolvedRawPoints = 0;
    for (const rf of resolvedFindings) {
      const evalResult = this.evaluateFindingDebt(rf);
      resolvedRawPoints += evalResult.debtPoints;
    }
    const resolvedDebt = this.rawPointsToScore(resolvedRawPoints);

    // Step 7: Breakdowns by Severity and Category
    const severityBreakdown = this.createEmptySeverityBreakdown();
    const categoryBreakdown = this.createEmptyCategoryBreakdown();

    for (const f of activeFindings) {
      severityBreakdown[f.severity] = (severityBreakdown[f.severity] || 0) + 1;
      categoryBreakdown[f.category] = (categoryBreakdown[f.category] || 0) + 1;
    }

    // Step 8: Top Contributors
    const maxContributors = options.maxTopContributors ?? 5;
    const sortedEvaluations = [...evaluatedFindings].sort((a, b) => b.debtPoints - a.debtPoints);
    const topContributors: TopDebtContributor[] = sortedEvaluations
      .slice(0, maxContributors)
      .map((item) => ({
        id: item.finding.id,
        fingerprint: item.finding.fingerprint,
        title: item.finding.title,
        file: item.finding.file,
        line: item.finding.line,
        severity: item.finding.severity,
        category: item.finding.category,
        confidence: item.finding.confidence,
        debtPoints: Number(item.debtPoints.toFixed(2)),
        reason: item.reason,
      }));

    const formulaSummary =
      `Score = round(100 * (1 - e^(-TotalPoints / ${DEBT_SATURATION_SCALE_K}))). ` +
      `TotalPoints incorporates severity base weights, confidence, exploitability, ` +
      `security boundary exposure, sensitive data context, control gaps, and blast radius. ` +
      `A score of 0 indicates zero detected debt, not absolute security.`;

    const explanation = defaultDebtExplanationService.generateExplanation({
      debtResult: {
        score: currentScore,
        riskLevel,
        previousScore,
        delta,
        newDebt,
        resolvedDebt,
        severityBreakdown,
        categoryBreakdown,
        topContributors,
        totalDebtPoints: totalRawPoints,
        formulaSummary,
      },
      findings: activeFindings,
      previousFindings: prevFindings,
      maxContributors: options.maxTopContributors ?? 5,
    });

    return {
      score: currentScore,
      riskLevel,
      previousScore,
      delta,
      newDebt,
      resolvedDebt,
      severityBreakdown,
      categoryBreakdown,
      topContributors,
      totalDebtPoints: totalRawPoints,
      formulaSummary,
      explanation,
    };
  }

  /**
   * Calculates the weighted debt points for an individual finding.
   */
  evaluateFindingDebt(
    finding: UnifiedFinding | ScoringFindingInput,
    context?: {
      isNewInPR?: boolean;
      timesDetected?: number;
      exploitability?: string;
    },
  ): { debtPoints: number; reason: string } {
    const sev = normalizeSeverity(finding.severity);
    const cat = normalizeCategory({
      category: finding.category,
      ruleId: finding.ruleId,
      cwe: finding.cwe,
      title: finding.title,
    });
    const confidence = typeof finding.confidence === 'number' ? Math.min(1.0, Math.max(0.1, finding.confidence)) : 0.8;

    // 1. Base Points from Severity
    const baseWeight = SEVERITY_BASE_POINTS[sev] ?? 5.0;

    // 2. Exploitability Multiplier
    const exploitMultiplier = this.getExploitabilityMultiplier(context?.exploitability, finding);

    // 3. Security Boundary Multiplier
    const boundaryMultiplier = this.getSecurityBoundaryMultiplier(finding.file);

    // 4. Sensitive Data Multiplier
    const dataMultiplier = this.getSensitiveDataMultiplier(cat, finding);

    // 5. Missing Controls Multiplier
    const controlMultiplier = this.getMissingControlsMultiplier(cat, finding);

    // 6. Recurrence Multiplier
    const timesDetected = context?.timesDetected ?? 1;
    const recurrenceMultiplier = timesDetected >= 5 ? 1.3 : timesDetected >= 2 ? 1.15 : 1.0;

    // 7. PR Context Multiplier (elevates priority for findings introduced in active PR)
    const prMultiplier = context?.isNewInPR ? 1.2 : 1.0;

    const debtPoints =
      baseWeight *
      confidence *
      exploitMultiplier *
      boundaryMultiplier *
      dataMultiplier *
      controlMultiplier *
      recurrenceMultiplier *
      prMultiplier;

    // Generate descriptive reason for audits and tooltips
    const factors: string[] = [`${sev} severity (${baseWeight}pts)`];
    factors.push(`${Math.round(confidence * 100)}% confidence`);
    if (boundaryMultiplier > 1.0) factors.push('public/core boundary');
    if (dataMultiplier > 1.0) factors.push('sensitive data exposed');
    if (controlMultiplier > 1.0) factors.push('missing security control');
    if (exploitMultiplier > 1.0) factors.push('high exploitability');
    if (context?.isNewInPR) factors.push('newly introduced in PR');
    if (recurrenceMultiplier > 1.0) factors.push(`recurred ${timesDetected}x`);

    const reason = factors.join(', ');

    return {
      debtPoints: Number(debtPoints.toFixed(2)),
      reason,
    };
  }

  /**
   * Exploitability multiplier based on public PoCs, CISA KEV, or CVSS exploitability ratings.
   */
  private getExploitabilityMultiplier(
    rating?: string,
    finding?: UnifiedFinding | ScoringFindingInput,
  ): number {
    const rate = String(rating || finding?.metadata?.exploitability || '').toUpperCase();
    if (rate === 'HIGH' || rate === 'POC' || rate === 'ACTIVE' || rate === 'KEV') {
      return 1.4;
    }
    if (rate === 'MEDIUM' || rate === 'REMOTE') {
      return 1.2;
    }
    if (rate === 'LOW' || rate === 'LOCAL') {
      return 0.9;
    }
    return 1.0;
  }

  /**
   * Affected security boundary multiplier derived from file path and route context.
   */
  private getSecurityBoundaryMultiplier(filePath?: string): number {
    if (!filePath) return 1.0;
    const norm = filePath.replace(/\\/g, '/').toLowerCase();

    // Test and fixture files have significantly reduced debt impact
    if (/(^|\/)test(s)?\/|__test(s)?__\/|\.test\.|\.spec\.|fixture(s)?\//.test(norm)) {
      return 0.4;
    }

    // Public API, Ingress, Controllers, Auth, and Gateway
    if (/(^|\/)(routes|controllers|handlers|api|gateway|auth|middleware)\//.test(norm)) {
      return 1.3;
    }

    // Core domain models and database
    if (/(^|\/)(models|db|database|services|entities)\//.test(norm)) {
      return 1.1;
    }

    // Background workers and internal scripts
    if (/(^|\/)(workers|jobs|tasks|scripts|tools)\//.test(norm)) {
      return 0.95;
    }

    return 1.0;
  }

  /**
   * Sensitive data exposure multiplier.
   */
  private getSensitiveDataMultiplier(
    category: NormalizedCategory,
    finding: UnifiedFinding | ScoringFindingInput,
  ): number {
    if (category === 'secrets') {
      return 1.35;
    }
    if (category === 'data_exposure') {
      return 1.25;
    }
    const text = `${finding.title || ''} ${finding.description || ''}`.toLowerCase();
    if (/(api[-_]?key|secret|token|password|credential|pii|ssn|credit[-_]?card)/i.test(text)) {
      return 1.25;
    }
    return 1.0;
  }

  /**
   * Missing fundamental security controls multiplier.
   */
  private getMissingControlsMultiplier(
    category: NormalizedCategory,
    finding: UnifiedFinding | ScoringFindingInput,
  ): number {
    if (category === 'authorization') {
      return 1.25; // IDOR, missing ownership/role checks
    }
    if (category === 'authentication') {
      return 1.25; // Missing auth, session weaknesses
    }
    if (category === 'configuration') {
      return 1.15; // Missing security headers, CORS wildcard
    }
    const text = `${finding.title || ''} ${finding.description || ''}`.toLowerCase();
    if (/(missing|bypass|disabled|unprotected|unverified)\s+(auth|check|validation|control|protection)/i.test(text)) {
      return 1.2;
    }
    return 1.0;
  }

  /**
   * Maps raw cumulative debt points to a bounded 0-100 score using exponential saturation.
   * Score = round(100 * (1 - e^(-TotalPoints / K)))
   */
  rawPointsToScore(rawPoints: number): number {
    if (rawPoints <= 0) return 0;
    const score = 100 * (1 - Math.exp(-rawPoints / DEBT_SATURATION_SCALE_K));
    return Math.min(100, Math.max(0, Math.round(score)));
  }

  /**
   * Determines risk level from score using clearly defined thresholds.
   */
  determineRiskLevel(score: number): DebtRiskLevel {
    if (score <= RISK_THRESHOLDS.LOW_MAX) return 'LOW';
    if (score <= RISK_THRESHOLDS.MEDIUM_MAX) return 'MEDIUM';
    if (score <= RISK_THRESHOLDS.HIGH_MAX) return 'HIGH';
    return 'CRITICAL';
  }

  private createEmptySeverityBreakdown(): Record<NormalizedSeverity, number> {
    const acc = {} as Record<NormalizedSeverity, number>;
    for (const sev of NORMALIZED_SEVERITIES) {
      acc[sev] = 0;
    }
    return acc;
  }

  private createEmptyCategoryBreakdown(): Record<NormalizedCategory, number> {
    const acc = {} as Record<NormalizedCategory, number>;
    for (const cat of NORMALIZED_CATEGORIES) {
      acc[cat] = 0;
    }
    return acc;
  }
}

export const defaultSecurityDebtScoringEngine = new SecurityDebtScoringEngine();

/**
 * Functional entry point for debt scoring.
 */
export function calculateSecurityDebtScore(
  options: CalculateDebtOptions,
): SecurityDebtResult {
  return defaultSecurityDebtScoringEngine.calculateDebt(options);
}

export const calculateDebtScore = calculateSecurityDebtScore;
