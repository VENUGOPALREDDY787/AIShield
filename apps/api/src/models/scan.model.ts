/**
 * Scan — one execution of the scanner pipeline against one commit.
 *
 * A scan is an immutable *event*: once it reaches a terminal status its counts
 * and score snapshot must never be recomputed, because they are the historical
 * record that `SecurityDebtHistory` is built from. Anything mutable about a
 * finding's current state lives on `Finding`, not here.
 *
 * Relationship to findings: `Finding` is deduplicated across scans by
 * fingerprint, so a scan cannot own its findings. Instead `findings` carries the
 * ids of every finding *observed* during this run (a bounded pointer list) and
 * `summary` carries the immutable snapshot of the counts. That keeps the
 * per-scan view to a single document read while avoiding an unbounded
 * "scanIds" array on the finding side.
 */
import { Schema, type HydratedDocument, type InferSchemaType } from 'mongoose';
import {
  DEBT_GRADES,
  SCANNER_IDS,
  SCANNER_STATUSES,
  SCAN_STATUSES,
  SCORING_METHODOLOGY_VERSION,
} from '@aishield/shared';
import { AI_ANALYSIS_STATUSES, SCAN_TRIGGERS } from './enums.js';
import { toJsonPlugin } from './plugins/to-json.plugin.js';
import { defineModel } from './registry.js';
import { SHA_REGEX, maxItems } from './validators.js';
import { categoryBreakdownSchema, severityBreakdownSchema } from './schemas/breakdowns.js';

/** Upper bound on the observation list, so a mega-scan cannot approach the 16 MB doc limit. */
const MAX_FINDING_REFS = 50_000;

/** Outcome of one scanner engine inside this run. */
const scannerResultSchema = new Schema(
  {
    source: { type: String, required: true, enum: [...SCANNER_IDS] },
    status: { type: String, required: true, enum: [...SCANNER_STATUSES], default: 'pending' },
    /** Engine version actually executed, so results stay reproducible. */
    toolVersion: { type: String, trim: true, maxlength: 100 },
    startedAt: { type: Date },
    finishedAt: { type: Date },
    durationMs: { type: Number, min: 0 },
    findingCount: { type: Number, min: 0, default: 0 },
    newFindingCount: { type: Number, min: 0, default: 0 },
    severityCounts: { type: severityBreakdownSchema, default: () => ({}) },
    error: { type: String, maxlength: 2000 },
  },
  { _id: false },
);

/** Bookkeeping for the LLM stage — separate from per-finding AI metadata. */
const aiAnalysisReportSchema = new Schema(
  {
    provider: { type: String, trim: true, maxlength: 100 },
    model: { type: String, trim: true, maxlength: 200 },
    promptVersion: { type: String, trim: true, maxlength: 50 },
    startedAt: { type: Date },
    finishedAt: { type: Date },
    durationMs: { type: Number, min: 0 },
    findingsAnalyzed: { type: Number, min: 0, default: 0 },
    suggestionsGenerated: { type: Number, min: 0, default: 0 },
    tokensUsed: { type: Number, min: 0 },
    error: { type: String, maxlength: 2000 },
  },
  { _id: false },
);

/** Immutable snapshot of the debt score as it stood at the end of this run. */
const finalScoreSchema = new Schema(
  {
    overall: { type: Number, min: 0, max: 100 },
    previous: { type: Number, min: 0, max: 100 },
    /** `overall - previous`. Positive means the score improved. */
    delta: { type: Number, min: -100, max: 100 },
    grade: { type: String, enum: [...DEBT_GRADES] },
    methodology: { type: String, trim: true, default: SCORING_METHODOLOGY_VERSION },
    calculatedAt: { type: Date },
  },
  { _id: false },
);

const scanSummarySchema = new Schema(
  {
    totalFindings: { type: Number, min: 0, default: 0 },
    newFindings: { type: Number, min: 0, default: 0 },
    resolvedFindings: { type: Number, min: 0, default: 0 },
    bySeverity: { type: severityBreakdownSchema, default: () => ({}) },
    byCategory: { type: categoryBreakdownSchema, default: () => ({}) },
  },
  { _id: false },
);

const scanErrorSchema = new Schema(
  {
    code: { type: String, trim: true, maxlength: 100 },
    message: { type: String, trim: true, maxlength: 2000 },
  },
  { _id: false },
);

export const scanSchema = new Schema(
  {
    // --- Scope -----------------------------------------------------------------
    repository: {
      type: Schema.Types.ObjectId,
      ref: 'Repository',
      required: [true, 'repository is required'],
    },
    /** Set when the scan was triggered by (and scoped to) a pull request. */
    pullRequest: { type: Schema.Types.ObjectId, ref: 'PullRequest' },

    commitSha: {
      type: String,
      required: [true, 'commitSha is required'],
      match: [SHA_REGEX, 'commitSha must be a git object name'],
    },
    branch: { type: String, required: [true, 'branch is required'], trim: true, maxlength: 255 },
    baseSha: { type: String, match: [SHA_REGEX, 'baseSha must be a git object name'] },
    baseBranch: { type: String, trim: true, maxlength: 255 },

    // --- Lifecycle -------------------------------------------------------------
    trigger: { type: String, enum: [...SCAN_TRIGGERS], default: 'manual' },
    status: { type: String, enum: [...SCAN_STATUSES], required: true, default: 'queued' },
    enqueuedAt: { type: Date, default: () => new Date() },
    startedAt: { type: Date },
    finishedAt: { type: Date },
    durationMs: { type: Number, min: 0 },
    /** Written by the worker while running; lets a reaper detect stuck scans. */
    heartbeatAt: { type: Date },
    attempt: { type: Number, min: 1, default: 1 },
    error: { type: scanErrorSchema },

    // --- Results ---------------------------------------------------------------
    scannerResults: { type: [scannerResultSchema], default: [] },

    aiAnalysisStatus: {
      type: String,
      enum: [...AI_ANALYSIS_STATUSES],
      default: 'not_requested',
    },
    aiAnalysis: { type: aiAnalysisReportSchema },

    finalScore: { type: finalScoreSchema },
    summary: { type: scanSummarySchema, default: () => ({}) },

    /** Ids of every finding observed in this run. See the model doc comment. */
    findings: {
      type: [{ type: Schema.Types.ObjectId, ref: 'Finding' }],
      default: [],
      validate: maxItems(MAX_FINDING_REFS),
    },

    createdBy: { type: Schema.Types.ObjectId, ref: 'User' },
  },
  { collection: 'scans', timestamps: true },
);

toJsonPlugin(scanSchema);

/**
 * Lifecycle invariants. A terminal scan must be fully timestamped, and the
 * derived duration is computed rather than trusted from a client.
 */
scanSchema.pre('validate', function validateScanLifecycle() {
  const status = this.get('status') as (typeof SCAN_STATUSES)[number];
  const startedAt = this.get('startedAt') as Date | undefined;
  const finishedAt = this.get('finishedAt') as Date | undefined;

  const terminal = status === 'succeeded' || status === 'failed' || status === 'cancelled';

  if (terminal && !finishedAt) {
    this.invalidate('finishedAt', 'finishedAt is required once a scan reaches a terminal status');
  }
  if (!terminal && finishedAt) {
    this.invalidate('finishedAt', 'finishedAt must not be set while a scan is still in progress');
  }
  if (status !== 'queued' && !startedAt) {
    this.invalidate('startedAt', 'startedAt is required once a scan leaves the queued state');
  }
  if (startedAt && finishedAt && finishedAt.getTime() < startedAt.getTime()) {
    this.invalidate('finishedAt', 'finishedAt cannot precede startedAt');
  }
  if (startedAt && finishedAt && this.get('durationMs') === undefined) {
    this.set('durationMs', finishedAt.getTime() - startedAt.getTime());
  }

  // One result per engine: duplicates would double-count in the summary.
  const results = (this.get('scannerResults') ?? []) as Array<{ source: string }>;
  const seen = new Set<string>();
  for (const result of results) {
    if (seen.has(result.source)) {
      this.invalidate('scannerResults', `Duplicate scanner result for "${result.source}"`);
      break;
    }
    seen.add(result.source);
  }
});

// Primary access path: "the recent scans of this repository".
scanSchema.index({ repository: 1, createdAt: -1 }, { name: 'repository_recent' });
// "Has this exact commit been scanned?" — dedupe before enqueuing.
scanSchema.index({ repository: 1, commitSha: 1 }, { name: 'repository_commit' });
scanSchema.index({ commitSha: 1 }, { name: 'commit' });
scanSchema.index({ repository: 1, status: 1, createdAt: -1 }, { name: 'repository_status' });
// Global queue dashboard and stuck-scan reaping (with heartbeatAt).
scanSchema.index({ status: 1, heartbeatAt: 1 }, { name: 'status_heartbeat' });
scanSchema.index({ aiAnalysisStatus: 1, createdAt: -1 }, { name: 'ai_status_recent' });
scanSchema.index({ pullRequest: 1, createdAt: -1 }, { sparse: true, name: 'pull_request_recent' });
scanSchema.index({ createdBy: 1, createdAt: -1 }, { sparse: true, name: 'created_by_recent' });

/**
 * At most one in-flight scan per repository.
 *
 * This is the integrity guarantee that stops a double-clicked button or a
 * duplicated webhook from running (and paying for) the same scan twice. It is
 * only safe because `heartbeatAt` lets a reaper fail a scan whose worker died —
 * without that, a stuck `running` row would block the repository forever.
 */
scanSchema.index(
  { repository: 1 },
  {
    unique: true,
    name: 'one_active_scan_per_repository',
    partialFilterExpression: { status: { $in: ['queued', 'running'] } },
  },
);

export type Scan = InferSchemaType<typeof scanSchema>;
export type ScanDocument = HydratedDocument<Scan>;

export const ScanModel = defineModel('Scan', scanSchema);
