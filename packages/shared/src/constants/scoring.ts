import type { Severity } from '../types/scan.js';

/**
 * Debt-scoring constants.
 *
 * The score is a product-level contract: the API ranks repositories by it, the
 * worker writes it, and the dashboard explains it to a user. The weights,
 * grade bands and methodology version therefore live in the shared package so
 * every process agrees on what a score means — and so a scoring change is a
 * visible, versioned event rather than a silent drift.
 *
 * Convention: **higher is better.** 100 is a clean repository, 0 is the worst
 * possible. A *positive* delta therefore means the score improved.
 *
 * This module deliberately holds constants and pure lookups only; the actual
 * scoring pass belongs to the scoring service.
 */

/** Relative penalty weight applied to each open finding, by severity. */
export const SEVERITY_WEIGHTS: Readonly<Record<Severity, number>> = {
  critical: 10,
  high: 5,
  medium: 2,
  low: 0.5,
  info: 0.1,
};

export const DEBT_SCORE_MIN = 0;
export const DEBT_SCORE_MAX = 100;

/** Grade ladder. Evaluated top-down: the first band whose `min` is met wins. */
export const GRADE_BANDS = [
  { grade: 'A', min: 90 },
  { grade: 'B', min: 80 },
  { grade: 'C', min: 70 },
  { grade: 'D', min: 60 },
  { grade: 'F', min: 0 },
] as const;

export const DEBT_GRADES = ['A', 'B', 'C', 'D', 'F'] as const;
export type DebtGrade = (typeof DEBT_GRADES)[number];

/**
 * Bumped whenever the weights, the formula or the normalisation changes.
 * Stored on every score document so historical scores stay interpretable.
 */
export const SCORING_METHODOLOGY_VERSION = 'weighted-severity-v1';

/** Letter grade for a numeric score. Out-of-range input is clamped. */
export function gradeForScore(score: number): DebtGrade {
  const clamped = Math.min(DEBT_SCORE_MAX, Math.max(DEBT_SCORE_MIN, score));
  for (const band of GRADE_BANDS) {
    if (clamped >= band.min) return band.grade;
  }
  return 'F';
}
