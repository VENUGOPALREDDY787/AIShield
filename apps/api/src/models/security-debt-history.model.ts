/**
 * SecurityDebtHistory — the append-only ledger behind the debt trend chart.
 *
 * One row per *change event*, never per scan that changed nothing, and never
 * updated. Two properties make the trend trustworthy:
 *
 *  1. Every row carries the methodology version and the full breakdown, so a
 *     graph spanning a scoring change can still explain itself.
 *  2. Rows are immutable. An update or delete is rejected by hooks below, so a
 *     correction has to be a new compensating row rather than a silent edit.
 *
 * There is deliberately **no TTL index**: this is the audit trail, and it is the
 * data that makes "we reduced debt by 40% this quarter" a checkable claim.
 */
import { Schema, type HydratedDocument, type InferSchemaType } from 'mongoose';
import { DEBT_GRADES, SCORING_METHODOLOGY_VERSION } from '@aishield/shared';
import { DEBT_HISTORY_EVENTS, DEBT_TRENDS } from './enums.js';
import { toJsonPlugin } from './plugins/to-json.plugin.js';
import { defineModel } from './registry.js';
import {
  categoryBreakdownSchema,
  scoreFactorSchema,
  severityBreakdownSchema,
} from './schemas/breakdowns.js';

/** Compact explanation: enough to re-render a historical tooltip. */
const historyExplanationSchema = new Schema(
  {
    methodology: { type: String, trim: true, default: SCORING_METHODOLOGY_VERSION },
    formula: { type: String, trim: true, maxlength: 500 },
    summary: { type: String, trim: true, maxlength: 2000 },
    factors: { type: [scoreFactorSchema], default: [] },
  },
  { _id: false },
);

/** Movement in the underlying counts, which is what actually changed. */
const findingCountsSchema = new Schema(
  {
    total: { type: Number, min: 0, default: 0 },
    open: { type: Number, min: 0, default: 0 },
    new: { type: Number, min: 0, default: 0 },
    resolved: { type: Number, min: 0, default: 0 },
  },
  { _id: false },
);

export const securityDebtHistorySchema = new Schema(
  {
    repository: {
      type: Schema.Types.ObjectId,
      ref: 'Repository',
      required: [true, 'repository is required'],
    },
    /** Scan that triggered this recorded change. Absent for baselines. */
    scan: { type: Schema.Types.ObjectId, ref: 'Scan' },
    pullRequest: { type: Schema.Types.ObjectId, ref: 'PullRequest' },

    /** What caused the entry. */
    event: {
      type: String,
      enum: [...DEBT_HISTORY_EVENTS],
      required: [true, 'event is required'],
    },

    overallScore: {
      type: Number,
      required: [true, 'overallScore is required'],
      min: 0,
      max: 100,
    },
    previousScore: { type: Number, min: 0, max: 100 },
    /** `overallScore - previousScore`. Positive means the score improved. */
    delta: { type: Number, min: -100, max: 100 },
    grade: { type: String, enum: [...DEBT_GRADES] },
    trend: { type: String, enum: [...DEBT_TRENDS] },

    severityBreakdown: { type: severityBreakdownSchema, default: () => ({}) },
    categoryBreakdown: { type: categoryBreakdownSchema, default: () => ({}) },
    findingCounts: { type: findingCountsSchema, default: () => ({}) },

    scoreExplanation: { type: historyExplanationSchema, default: () => ({}) },
    methodology: { type: String, trim: true, default: SCORING_METHODOLOGY_VERSION },

    recordedAt: { type: Date, required: true, default: () => new Date() },
    recordedBy: { type: Schema.Types.ObjectId, ref: 'User' },
  },
  { collection: 'security_debt_history', timestamps: true },
);

toJsonPlugin(securityDebtHistorySchema);

/**
 * Immutability guard.
 *
 * Mongoose has no first-class "append-only" flag, so both the document API and
 * the query API are locked down. Throwing here is intentional: a silent no-op
 * would let a caller believe a historical figure had been corrected when it had
 * not.
 */
/** Canonical refusal raised by every mutation path. */
export const HISTORY_APPEND_ONLY_MESSAGE =
  'SecurityDebtHistory is append-only: insert a compensating entry instead of mutating history';

/**
 * The append-only guard, exported so callers can reuse the exact wording (and
 * so the contract is testable without a live connection).
 */
export function rejectHistoryMutation(): never {
  throw new Error(HISTORY_APPEND_ONLY_MESSAGE);
}

securityDebtHistorySchema.pre('save', function rejectHistoryUpdates() {
  if (!this.isNew) rejectHistoryMutation();
});

// Registered one operation at a time: `Schema.pre` is overloaded per operation
// name, so a union loop would not type-check. Deletes are blocked too — purging
// the ledger for a compliance erasure must be an explicit, audited migration,
// not something a stray `deleteMany({})` can do.
securityDebtHistorySchema.pre('updateOne', rejectHistoryMutation);
securityDebtHistorySchema.pre('updateMany', rejectHistoryMutation);
securityDebtHistorySchema.pre('findOneAndUpdate', rejectHistoryMutation);
securityDebtHistorySchema.pre('replaceOne', rejectHistoryMutation);
securityDebtHistorySchema.pre('deleteOne', rejectHistoryMutation);
securityDebtHistorySchema.pre('deleteMany', rejectHistoryMutation);

// The trend chart's only query: one repository, newest first.
securityDebtHistorySchema.index({ repository: 1, recordedAt: -1 }, { name: 'repository_recent' });
/**
 * One entry per scan. Partial, so many rows may share a null `scan`
 * (baselines and manual recalculations) without colliding.
 */
securityDebtHistorySchema.index(
  { repository: 1, scan: 1 },
  { unique: true, sparse: true, name: 'uniq_repository_scan' },
);
// Cross-repository activity feed ("what changed overnight?").
securityDebtHistorySchema.index({ recordedAt: -1 }, { name: 'recorded_at' });
securityDebtHistorySchema.index({ event: 1, recordedAt: -1 }, { name: 'event_recent' });
securityDebtHistorySchema.index({ repository: 1, delta: 1 }, { name: 'repository_delta' });

export type SecurityDebtHistory = InferSchemaType<typeof securityDebtHistorySchema>;
export type SecurityDebtHistoryDocument = HydratedDocument<SecurityDebtHistory>;

export const SecurityDebtHistoryModel = defineModel(
  'SecurityDebtHistory',
  securityDebtHistorySchema,
);
