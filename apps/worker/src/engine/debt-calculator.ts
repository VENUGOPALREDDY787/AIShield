import {
  type DebtGrade,
  type Severity,
  SEVERITY_WEIGHTS,
  DEBT_SCORE_MAX,
  DEBT_SCORE_MIN,
  gradeForScore,
} from '@aishield/shared';
import type { ScanFinding } from '@aishield/shared';

export interface CalculatedDebtSummary {
  overallScore: number;
  grade: DebtGrade;
  totalDebtPoints: number;
  severityBreakdown: Record<Severity, number>;
  deltaPoints?: number;
  deltaScore?: number;
}

/**
 * Calculates security debt points and the 0-100 score based on normalized findings.
 */
export function calculateSecurityDebt(
  findings: ScanFinding[],
  baselineScore: number = DEBT_SCORE_MAX,
): CalculatedDebtSummary {
  const severityBreakdown: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  let totalDebtPoints = 0;

  for (const finding of findings) {
    severityBreakdown[finding.severity] = (severityBreakdown[finding.severity] || 0) + 1;
    const weight = SEVERITY_WEIGHTS[finding.severity] ?? 1;
    totalDebtPoints += weight;
  }

  // Exponential decay model: Score = round(100 * e^(-k * totalPoints))
  const k = 0.035;
  const rawScore = 100 * Math.exp(-k * totalDebtPoints);
  const overallScore = Math.min(
    DEBT_SCORE_MAX,
    Math.max(DEBT_SCORE_MIN, Math.round(rawScore)),
  );

  const grade = gradeForScore(overallScore);
  const deltaScore = overallScore - baselineScore;

  return {
    overallScore,
    grade,
    totalDebtPoints: Number(totalDebtPoints.toFixed(2)),
    severityBreakdown,
    deltaScore,
  };
}
