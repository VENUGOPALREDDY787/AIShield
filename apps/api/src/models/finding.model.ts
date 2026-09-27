/**
 * Finding — a durable, deduplicated issue.
 *
 * ## Why a finding is not a per-scan row
 *
 * `fingerprint` is a stable hash of "what this issue is" (rule + file + symbol,
 * computed by the producing scanner). The unique index on
 * `(repository, fingerprint)` makes a finding a *single entity that persists
 * across scans*, which is what the product needs:
 *
 *  - `firstDetectedAt` / `lastDetectedAt` / `timesDetected` give an issue a
 *    real lifetime, so "new" and "resolved" are computable.
 *  - Triage survives re-scanning. A finding marked `risk_accepted` stays
 *    accepted; a per-scan row would resurrect it every night.
 *  - Debt scores are comparable over time, because the same issue is the same
 *    document rather than a new one with a new id.
 *
 * The cost is that a scan cannot "own" findings. `Scan.findings` keeps the
 * observation list and `Scan.summary` the immutable snapshot, so the per-scan
 * view is still a single read.
 *
 * ## What is deliberately not stored
 *
 * No raw scanner output, no full source file, no credential. `location.snippet`
 * is optional and capped, and every snippet written passes through the
 * redaction hook below. Gitleaks (and friends) must be told to *mask* the
 * secret it matched — this model is the backstop, not the primary control.
 */
import { Schema, type HydratedDocument, type InferSchemaType } from 'mongoose';
import { FINDING_CATEGORIES, SCANNER_IDS, SEVERITIES } from '@aishield/shared';
import {
  CLOSED_FINDING_STATUSES,
  DEPENDENCY_ECOSYSTEMS,
  FINDING_STATUSES,
  REACHABILITY,
  REMEDIATION_EFFORTS,
  RISK_LEVELS,
} from './enums.js';
import { toJsonPlugin } from './plugins/to-json.plugin.js';
import { defineModel } from './registry.js';
import { CWE_REGEX, SHA256_REGEX, maxItems } from './validators.js';
import { referenceSchema } from './schemas/references.js';
import { redactSensitiveText } from '../utils/redact-sensitive.js';

/** Hard cap on a stored code snippet. Beyond this it is context, not evidence. */
export const FINDING_SNIPPET_MAX_LENGTH = 2_000;

/** Where the issue was found. `filePath` is required, the rest is best-effort. */
const locationSchema = new Schema(
  {
    filePath: {
      type: String,
      required: [true, 'location.filePath is required'],
      trim: true,
      maxlength: 1024,
    },
    startLine: { type: Number, min: 1 },
    endLine: { type: Number, min: 1 },
    startColumn: { type: Number, min: 0 },
    endColumn: { type: Number, min: 0 },
    /** Optional, capped, and redacted by the pre-validate hook. */
    snippet: { type: String, maxlength: FINDING_SNIPPET_MAX_LENGTH },
    snippetRedacted: { type: Boolean, default: false },
    /** SHA-256 of the *original* snippet — lets us detect the same code without storing it. */
    snippetHash: { type: String, match: SHA256_REGEX },
  },
  { _id: false },
);

/** Provenance from the producing engine. Raw engine output is intentionally absent. */
const scannerMetadataSchema = new Schema(
  {
    engine: { type: String, trim: true, maxlength: 100 },
    toolVersion: { type: String, trim: true, maxlength: 100 },
    ruleSet: { type: String, trim: true, maxlength: 200 },
    /** Severity as the engine reported it, before normalisation. */
    rawSeverity: { type: String, trim: true, maxlength: 50 },
    /** Small, curated extras (CWE list, OWASP category, licence). Not a dump. */
    properties: { type: Schema.Types.Mixed },
  },
  { _id: false },
);

/** LLM reasoning attached to this specific finding. */
const findingAiAnalysisSchema = new Schema(
  {
    status: {
      type: String,
      enum: ['not_requested', 'queued', 'running', 'completed', 'failed', 'skipped'],
      default: 'not_requested',
    },
    provider: { type: String, trim: true, maxlength: 100 },
    model: { type: String, trim: true, maxlength: 200 },
    promptVersion: { type: String, trim: true, maxlength: 50 },
    summary: { type: String, maxlength: 2000 },
    exploitability: { type: String, enum: [...RISK_LEVELS] },
    reachability: { type: String, enum: [...REACHABILITY] },
    businessImpact: { type: String, maxlength: 1000 },
    /** 0–1: how likely this is a false positive, per the model. */
    falsePositiveLikelihood: { type: Number, min: 0, max: 1 },
    /** 0–1: the model's own confidence in its assessment. */
    confidence: { type: Number, min: 0, max: 1 },
    analyzedAt: { type: Date },
    tokensUsed: { type: Number, min: 0 },
    error: { type: String, maxlength: 2000 },
  },
  { _id: false },
);

/** Triage guidance embedded on the finding (the full suggestion lives in its own collection). */
const findingRemediationSchema = new Schema(
  {
    summary: { type: String, maxlength: 2000 },
    steps: { type: [String], default: [], validate: maxItems(20) },
    effort: { type: String, enum: [...REMEDIATION_EFFORTS] },
    autoFixAvailable: { type: Boolean, default: false },
    /** Pointer to the generated, reviewable suggestion. */
    suggestedFix: { type: Schema.Types.ObjectId, ref: 'RemediationSuggestion' },
    references: { type: [referenceSchema], default: [], validate: maxItems(10) },
  },
  { _id: false },
);

/** Extra context for dependency findings, so the UI can render an upgrade path. */
const dependencySchema = new Schema(
  {
    packageName: { type: String, trim: true, maxlength: 214 },
    installedVersion: { type: String, trim: true, maxlength: 100 },
    fixedVersion: { type: String, trim: true, maxlength: 100 },
    ecosystem: { type: String, enum: [...DEPENDENCY_ECOSYSTEMS] },
    /** Manifest that pulled the package in, e.g. `package-lock.json`. */
    manifestPath: { type: String, trim: true, maxlength: 1024 },
    isDirect: { type: Boolean },
    /** Advisory / CVE identifiers. */
    vulnerabilityIds: { type: [String], default: [], validate: maxItems(50) },
    cvssScore: { type: Number, min: 0, max: 10 },
    cvssVector: { type: String, trim: true, maxlength: 200 },
  },
  { _id: false },
);

export const findingSchema = new Schema(
  {
    // --- Identity --------------------------------------------------------------
    repository: {
      type: Schema.Types.ObjectId,
      ref: 'Repository',
      required: [true, 'repository is required'],
    },
    /**
     * Stable identity of the issue within a repository. Together with
     * `repository` this is the unique key that makes a finding durable.
     */
    fingerprint: {
      type: String,
      required: [true, 'fingerprint is required'],
      trim: true,
      maxlength: 128,
    },
    /** Bumped when the fingerprint algorithm changes, to force re-evaluation. */
    fingerprintVersion: { type: Number, min: 1, default: 1 },

    // --- Detection -------------------------------------------------------------
    /** Scan in which the issue was first seen. */
    firstSeenScan: {
      type: Schema.Types.ObjectId,
      ref: 'Scan',
      required: [true, 'firstSeenScan is required'],
    },
    /** Most recent scan that observed it. */
    lastSeenScan: {
      type: Schema.Types.ObjectId,
      ref: 'Scan',
      required: [true, 'lastSeenScan is required'],
    },
    firstDetectedAt: {
      type: Date,
      required: true,
      default: () => new Date(),
    },
    lastDetectedAt: {
      type: Date,
      required: true,
      default: () => new Date(),
    },
    /** How many scans have observed this issue. */
    timesDetected: { type: Number, min: 1, default: 1 },

    // --- Classification --------------------------------------------------------
    source: {
      type: String,
      required: [true, 'source is required'],
      enum: [...SCANNER_IDS],
    },
    ruleId: { type: String, required: [true, 'ruleId is required'], trim: true, maxlength: 300 },
    category: {
      type: String,
      required: [true, 'category is required'],
      enum: [...FINDING_CATEGORIES],
    },
    severity: {
      type: String,
      required: [true, 'severity is required'],
      enum: [...SEVERITIES],
    },
    /** 0–1. Deterministic engines match a rule exactly, hence the default of 1. */
    confidence: { type: Number, min: 0, max: 1, default: 1 },

    title: { type: String, required: [true, 'title is required'], trim: true, maxlength: 300 },
    description: { type: String, maxlength: 5000 },

    /** MITRE weakness id, when the rule maps to one. */
    cwe: { type: String, match: [CWE_REGEX, 'cwe must look like "CWE-79"'] },
    owasp: { type: String, trim: true, maxlength: 100 },
    tags: { type: [String], default: [], validate: maxItems(30) },

    location: { type: locationSchema },
    dependency: { type: dependencySchema },
    scannerMetadata: { type: scannerMetadataSchema, default: () => ({}) },
    aiAnalysis: { type: findingAiAnalysisSchema, default: () => ({}) },
    remediation: { type: findingRemediationSchema, default: () => ({}) },

    // --- Triage ----------------------------------------------------------------
    status: { type: String, enum: [...FINDING_STATUSES], default: 'open' },
    statusChangedAt: { type: Date },
    statusChangedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    /** Reason recorded when a finding is ignored, accepted or marked false positive. */
    statusNote: { type: String, maxlength: 2000 },
    resolvedAt: { type: Date },
    /** Scan that no longer observed the finding — i.e. what fixed it. */
    resolvedByScan: { type: Schema.Types.ObjectId, ref: 'Scan' },
    deadlineAt: { type: Date },
  },
  { collection: 'findings', timestamps: true },
);

toJsonPlugin(findingSchema);

/**
 * Redaction + invariants.
 *
 * Redaction runs here rather than in the scanner adapters because this is the
 * last point every write must pass through — including backfills, migrations
 * and manual edits.
 */
findingSchema.pre('validate', function redactAndValidateFinding() {
  const location = this.get('location') as
    | { snippet?: string; snippetRedacted?: boolean }
    | undefined;

  if (location?.snippet) {
    const result = redactSensitiveText(location.snippet);
    if (result.redacted) {
      this.set('location.snippet', result.text);
      this.set('location.snippetRedacted', true);
    }
  }

  const firstDetectedAt = this.get('firstDetectedAt') as Date | undefined;
  const lastDetectedAt = this.get('lastDetectedAt') as Date | undefined;
  if (firstDetectedAt && lastDetectedAt && lastDetectedAt.getTime() < firstDetectedAt.getTime()) {
    this.invalidate('lastDetectedAt', 'lastDetectedAt cannot precede firstDetectedAt');
  }

  const status = this.get('status') as (typeof FINDING_STATUSES)[number];
  if (CLOSED_FINDING_STATUSES.includes(status) && !this.get('resolvedAt')) {
    this.invalidate('resolvedAt', `resolvedAt is required when status is "${status}"`);
  }

  const startLine = this.get('location.startLine') as number | undefined;
  const endLine = this.get('location.endLine') as number | undefined;
  if (startLine !== undefined && endLine !== undefined && endLine < startLine) {
    this.invalidate('location.endLine', 'location.endLine cannot precede location.startLine');
  }
});

/**
 * The dedupe key. Unique, because two documents describing the same issue in the
 * same repository would break every "how many open criticals" count.
 */
findingSchema.index(
  { repository: 1, fingerprint: 1 },
  { unique: true, name: 'uniq_repository_fingerprint' },
);

// Primary list view: open findings of a repository, worst and most recent first.
findingSchema.index(
  { repository: 1, status: 1, severity: 1, lastDetectedAt: -1 },
  { name: 'repository_status_severity' },
);
// Category filters and the debt-score breakdown.
findingSchema.index({ repository: 1, category: 1, status: 1 }, { name: 'repository_category_status' });
// The per-scan views: "what did this scan find first?" and "what did it see last?".
findingSchema.index({ firstSeenScan: 1 }, { name: 'first_seen_scan' });
findingSchema.index({ lastSeenScan: 1 }, { name: 'last_seen_scan' });
// File-level views ("show me everything in src/auth") and inline PR comments.
findingSchema.index(
  { repository: 1, 'location.filePath': 1, status: 1 },
  { name: 'repository_file_status' },
);
// Rule hygiene: "how noisy is this rule across the org?"
findingSchema.index({ source: 1, ruleId: 1 }, { name: 'source_rule' });
// Compliance reporting by weakness class.
findingSchema.index({ cwe: 1, status: 1 }, { sparse: true, name: 'cwe_status' });
// The "new since" feed and stale-finding sweeps.
findingSchema.index({ repository: 1, firstDetectedAt: -1 }, { name: 'repository_first_detected' });
// Dependency findings: "who else is affected by CVE-x?"
findingSchema.index(
  { 'dependency.packageName': 1, status: 1 },
  { sparse: true, name: 'dependency_package_status' },
);

export type Finding = InferSchemaType<typeof findingSchema>;
export type FindingDocument = HydratedDocument<Finding>;

export const FindingModel = defineModel('Finding', findingSchema);
