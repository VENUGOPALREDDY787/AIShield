/**
 * Reusable breakdown subschemas.
 *
 * `severityBreakdown` and `categoryBreakdown` appear on `Scan`, `SecurityDebt`
 * and `SecurityDebtHistory`. Defining them once guarantees the three can be
 * compared numerically — a score explanation that cannot be lined up against
 * the scan that produced it is worse than no explanation.
 */
import { Schema } from 'mongoose';

/**
 * Count of open findings per severity. Always all five keys present (defaulted
 * to 0) so consumers never have to distinguish "missing" from "zero", and so
 * MongoDB can index them individually.
 */
export const severityBreakdownSchema = new Schema(
  {
    critical: { type: Number, min: 0, default: 0 },
    high: { type: Number, min: 0, default: 0 },
    medium: { type: Number, min: 0, default: 0 },
    low: { type: Number, min: 0, default: 0 },
    info: { type: Number, min: 0, default: 0 },
  },
  { _id: false },
);

/**
 * Count of open findings per finding category.
 *
 * Keys mirror the `FindingCategory` union in `@aishield/shared`; `aiReasoning`
 * is camel-cased rather than hyphenated so it is safe to use as a MongoDB field
 * path without quoting.
 */
export const categoryBreakdownSchema = new Schema(
  {
    security: { type: Number, min: 0, default: 0 },
    secret: { type: Number, min: 0, default: 0 },
    dependency: { type: Number, min: 0, default: 0 },
    debt: { type: Number, min: 0, default: 0 },
    aiReasoning: { type: Number, min: 0, default: 0 },
  },
  { _id: false },
);

/** Weighted penalty contribution per severity, used by the score explanation. */
export const severityPenaltySchema = new Schema(
  {
    critical: { type: Number, min: 0, default: 0 },
    high: { type: Number, min: 0, default: 0 },
    medium: { type: Number, min: 0, default: 0 },
    low: { type: Number, min: 0, default: 0 },
    info: { type: Number, min: 0, default: 0 },
  },
  { _id: false },
);

/** A single human-readable reason contributing to a score. */
export const scoreFactorSchema = new Schema(
  {
    label: { type: String, required: true, trim: true, maxlength: 200 },
    impact: { type: Number, required: true },
    detail: { type: String, trim: true, maxlength: 500 },
  },
  { _id: false },
);
