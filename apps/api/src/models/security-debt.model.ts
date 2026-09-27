/**
 * SecurityDebt — the *current* debt position of one repository.
 *
 * Exactly one document per repository (unique index), upserted after each scan.
 * It exists so that "what is our worst repository?" and a repository header card
 * are single indexed reads rather than an aggregation over every scan ever run.
 *
 * The append-only counterpart is `SecurityDebtHistory`: this document answers
 * "where are we now", that collection answers "how did we get here".
 *
 * ## Score convention
 *
 * 100 = clean, 0 = worst. Therefore a **positive `delta` is an improvement**.
 * `trend` spells that out so no consumer has to remember the convention.
 *
 * `scoreExplanation` is mandatory, not decorative: a score a team cannot argue
 * with is a score they will ignore. Every number is explained by the weights
 * that produced it and the factors that moved it.
 */
import { Schema, type HydratedDocument, type InferSchemaType } from 'mongoose';
import { DEBT_GRADES, SCORING_METHODOLOGY_VERSION, gradeForScore } from '@aishield/shared';
import { DEBT_TRENDS } from './enums.js';
import { toJsonPlugin } from './plugins/to-json.plugin.js';
import { defineModel } from './registry.js';
import {
  categoryBreakdownSchema,
  scoreFactorSchema,
  severityBreakdownSchema,
  severityPenaltySchema,
} from './schemas/breakdowns.js';

/** Deltas smaller than this are reported as `stable` rather than a direction. */
export const STABLE_TREND_THRESHOLD = 0.5;

/** The human-auditable derivation of `overallScore`. */
const scoreExplanationSchema = new Schema(
  {
    methodology: { type: String, trim: true, default: SCORING_METHODOLOGY_VERSION },
    /** The formula as text, so a report can print it verbatim. */
    formula: { type: String, trim: true, maxlength: 500 },
    summary: { type: String, trim: true, maxlength: 2000 },
    /** Weights in force when the score was computed. */
    weights: { type: severityPenaltySchema, default: () => ({}) },
    /** Weighted penalty contributed by each severity. */
    penaltyBySeverity: { type: severityPenaltySchema, default: () => ({}) },
    totalPenalty: { type: Number, min: 0, default: 0 },
    /** Why the score is where it is — the bullets shown in the UI. */
    factors: { type: [scoreFactorSchema], default: [], validate: { validator: (value: unknown[] | undefined) => !value || value.length <= 20, message: 'At most 20 score factors' } },
  },
  { _id: false },
);

/** Provenance of the calculation, so a stale score is detectable. */
const debtCalculationSchema = new Schema(
  {
    /** Scan that produced this score. */
    scan: { type: Schema.Types.ObjectId, ref: 'Scan' },
    /** Scan that produced the score it is being compared against. */
    previousScan: { type: Schema.Types.ObjectId, ref: 'Scan' },
    openFindingCount: { type: Number, min: 0, default: 0 },
    calculatedAt: { type: Date, default: () => new Date() },
    modelVersion: { type: String, trim: true, maxlength: 50, default: SCORING_METHODOLOGY_VERSION },
  },
  { _id: false },
);

export const securityDebtSchema = new Schema(
  {
    repository: {
      type: Schema.Types.ObjectId,
      ref: 'Repository',
      required: [true, 'repository is required'],
    },

    overallScore: {
      type: Number,
      required: [true, 'overallScore is required'],
      min: [0, 'overallScore cannot be negative'],
      max: [100, 'overallScore cannot exceed 100'],
    },
    previousScore: { type: Number, min: 0, max: 100 },
    /** `overallScore - previousScore`. Positive means the score improved. */
    delta: { type: Number, min: -100, max: 100 },
    grade: { type: String, enum: [...DEBT_GRADES], default: undefined },
    trend: { type: String, enum: [...DEBT_TRENDS] },

    /** Open findings per severity — the inputs to the penalty. */
    severityBreakdown: { type: severityBreakdownSchema, default: () => ({}) },
    /** Open findings per origin — answers "is our debt mostly dependencies?". */
    categoryBreakdown: { type: categoryBreakdownSchema, default: () => ({}) },

    scoreExplanation: { type: scoreExplanationSchema, default: () => ({}) },
    calculation: { type: debtCalculationSchema, default: () => ({}) },
  },
  { collection: 'security_debts', timestamps: true },
);

toJsonPlugin(securityDebtSchema);

/**
 * Derives the redundant-but-always-consumed fields (`delta`, `grade`, `trend`)
 * so they can never disagree with `overallScore` / `previousScore`.
 */
securityDebtSchema.pre('validate', function deriveDebtDerivatives() {
  const overallScore = this.get('overallScore') as number | undefined;
  const previousScore = this.get('previousScore') as number | undefined;

  if (overallScore !== undefined && previousScore !== undefined && this.get('delta') === undefined) {
    this.set('delta', Number((overallScore - previousScore).toFixed(2)));
  }

  if (overallScore !== undefined && this.get('grade') === undefined) {
    this.set('grade', gradeForScore(overallScore));
  }

  const delta = this.get('delta') as number | undefined;
  if (delta !== undefined && this.get('trend') === undefined) {
    if (delta > STABLE_TREND_THRESHOLD) this.set('trend', 'improving');
    else if (delta < -STABLE_TREND_THRESHOLD) this.set('trend', 'worsening');
    else this.set('trend', 'stable');
  }
});

// One current score per repository. Upsert target.
securityDebtSchema.index({ repository: 1 }, { unique: true, name: 'uniq_repository' });
// "Worst repositories first" leaderboard.
securityDebtSchema.index({ overallScore: 1, updatedAt: -1 }, { name: 'score_ascending' });
securityDebtSchema.index({ grade: 1, updatedAt: -1 }, { name: 'grade_recent' });
securityDebtSchema.index({ trend: 1, delta: 1 }, { name: 'trend' });
securityDebtSchema.index({ 'calculation.scan': 1 }, { sparse: true, name: 'calculation_scan' });
securityDebtSchema.index({ 'calculation.calculatedAt': -1 }, { name: 'calculated_at' });

export type SecurityDebt = InferSchemaType<typeof securityDebtSchema>;
export type SecurityDebtDocument = HydratedDocument<SecurityDebt>;

export const SecurityDebtModel = defineModel('SecurityDebt', securityDebtSchema);
