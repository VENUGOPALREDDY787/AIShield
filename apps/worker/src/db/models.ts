/**
 * Worker-side Mongoose models.
 *
 * Mapped to existing MongoDB collections (`scans`, `findings`, `security_debts`).
 * Reuses existing registered models if already compiled on the connection.
 */
import mongoose, { Schema } from 'mongoose';

// --- Scanner Result Sub-Schema ---
const scannerResultSchema = new Schema(
  {
    source: { type: String, required: true },
    status: { type: String, required: true, default: 'pending' },
    toolVersion: { type: String },
    startedAt: { type: Date },
    finishedAt: { type: Date },
    durationMs: { type: Number, min: 0 },
    findingCount: { type: Number, min: 0, default: 0 },
    newFindingCount: { type: Number, min: 0, default: 0 },
    severityCounts: { type: Schema.Types.Mixed, default: () => ({}) },
    error: { type: String, maxlength: 2000 },
  },
  { _id: false },
);

// --- AI Analysis Sub-Schema ---
const aiAnalysisReportSchema = new Schema(
  {
    provider: { type: String },
    model: { type: String },
    promptVersion: { type: String },
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

// --- Final Debt Score Sub-Schema ---
const finalScoreSchema = new Schema(
  {
    overall: { type: Number, min: 0, max: 100 },
    previous: { type: Number, min: 0, max: 100 },
    delta: { type: Number },
    grade: { type: String },
    methodology: { type: String, default: 'v1.0' },
    calculatedAt: { type: Date },
  },
  { _id: false },
);

// --- Scan Summary Sub-Schema ---
const scanSummarySchema = new Schema(
  {
    totalFindings: { type: Number, min: 0, default: 0 },
    newFindings: { type: Number, min: 0, default: 0 },
    resolvedFindings: { type: Number, min: 0, default: 0 },
    bySeverity: { type: Schema.Types.Mixed, default: () => ({}) },
    byCategory: { type: Schema.Types.Mixed, default: () => ({}) },
  },
  { _id: false },
);

// --- Scan Schema ---
const workerScanSchema = new Schema(
  {
    repository: { type: Schema.Types.Mixed },
    pullRequest: { type: Schema.Types.Mixed },
    commitSha: { type: String, required: true },
    branch: { type: String, required: true },
    baseSha: { type: String },
    baseBranch: { type: String },
    jobId: { type: String },
    trigger: { type: String, default: 'background_job' },
    status: {
      type: String,
      enum: ['queued', 'running', 'succeeded', 'failed', 'cancelled'],
      required: true,
      default: 'queued',
    },
    enqueuedAt: { type: Date, default: () => new Date() },
    startedAt: { type: Date },
    finishedAt: { type: Date },
    durationMs: { type: Number, min: 0 },
    heartbeatAt: { type: Date },
    attempt: { type: Number, min: 1, default: 1 },
    error: {
      code: { type: String },
      message: { type: String },
    },
    scannerResults: { type: [scannerResultSchema], default: [] },
    aiAnalysisStatus: {
      type: String,
      enum: ['not_requested', 'queued', 'running', 'completed', 'failed', 'skipped'],
      default: 'not_requested',
    },
    aiAnalysis: { type: aiAnalysisReportSchema },
    finalScore: { type: finalScoreSchema },
    summary: { type: scanSummarySchema, default: () => ({}) },
    findings: { type: [{ type: Schema.Types.ObjectId, ref: 'Finding' }], default: [] },
  },
  { collection: 'scans', timestamps: true },
);

// --- Finding Schema ---
const workerFindingSchema = new Schema(
  {
    repository: { type: Schema.Types.Mixed },
    fingerprint: { type: String, required: true },
    scanner: { type: String, required: true },
    category: { type: String, required: true },
    severity: { type: String, required: true },
    title: { type: String, required: true },
    description: { type: String, required: true },
    location: {
      filePath: { type: String, required: true },
      startLine: { type: Number },
      endLine: { type: Number },
      snippet: { type: String },
    },
    cwe: { type: String },
    remediation: { type: String },
    confidence: { type: Number, min: 0, max: 1, default: 1.0 },
    distinction: { type: String, default: 'confirmed_scanner_finding' },
    metadata: { type: Schema.Types.Mixed, default: () => ({}) },
    firstSeenScan: { type: Schema.Types.Mixed },
    lastSeenScan: { type: Schema.Types.Mixed },
    firstDetectedAt: { type: Date, default: () => new Date() },
    lastDetectedAt: { type: Date, default: () => new Date() },
    timesDetected: { type: Number, min: 1, default: 1 },
  },
  { collection: 'findings', timestamps: true },
);

// --- Security Debt Schema ---
const workerSecurityDebtSchema = new Schema(
  {
    repository: { type: Schema.Types.Mixed, required: true },
    score: { type: Number, min: 0, max: 100, required: true },
    riskLevel: { type: String, required: true },
    formulaSummary: { type: String },
    severityBreakdown: { type: Schema.Types.Mixed, default: () => ({}) },
    categoryBreakdown: { type: Schema.Types.Mixed, default: () => ({}) },
    topContributors: { type: [Schema.Types.Mixed], default: [] },
  },
  { collection: 'security_debts', timestamps: true },
);

export interface IWorkerModel {
  findByIdAndUpdate(id: unknown, update: unknown, options?: unknown): Promise<unknown>;
  findOneAndUpdate(filter: unknown, update: unknown, options?: unknown): Promise<unknown>;
  find(filter?: unknown): Promise<unknown[]>;
  findById(id: unknown): Promise<unknown>;
  create(doc: unknown): Promise<unknown>;
}

export const ScanModel: IWorkerModel = (mongoose.models.Scan ||
  mongoose.model('Scan', workerScanSchema)) as unknown as IWorkerModel;

export const FindingModel: IWorkerModel = (mongoose.models.Finding ||
  mongoose.model('Finding', workerFindingSchema)) as unknown as IWorkerModel;

export const SecurityDebtModel: IWorkerModel = (mongoose.models.SecurityDebt ||
  mongoose.model('SecurityDebt', workerSecurityDebtSchema)) as unknown as IWorkerModel;
