/**
 * RemediationSuggestion — a concrete, reviewable fix for one finding.
 *
 * Split out of `Finding` on purpose. A suggestion is large (a rationale, steps,
 * an optional diff), it is *versioned* (regenerating with a newer model should
 * not destroy the previous proposal), and its lifecycle — proposed, accepted,
 * applied, rejected — is independent of the finding's severity or status. An
 * array on the finding would make every list query drag along megabytes of
 * patches.
 *
 * Security posture: `patch.content` is the largest free-text field in the system
 * and the most likely place for a model to echo a credential it saw in the
 * source. Unlike a finding snippet — where a redacted excerpt still carries
 * useful context — a *fix* has no legitimate reason to contain a credential
 * literal, so such a suggestion is refused outright rather than stored in
 * redacted form. See `redact-sensititive.ts` for the complementary policy.
 */
import { Schema, type HydratedDocument, type InferSchemaType } from 'mongoose';
import { SEVERITIES } from '@aishield/shared';
import {
  PATCH_FORMATS,
  REMEDIATION_EFFORTS,
  REMEDIATION_KINDS,
  REMEDIATION_STATUSES,
  RISK_LEVELS,
} from './enums.js';
import { toJsonPlugin } from './plugins/to-json.plugin.js';
import { defineModel } from './registry.js';
import { HTTP_URL_REGEX, SHA_REGEX, maxItems } from './validators.js';
import { referenceSchema } from './schemas/references.js';
import { containsSecretLikeContent } from '../utils/redact-sensitive.js';

/** Hard cap on a generated patch. Larger than this should be a PR, not a record. */
export const PATCH_CONTENT_MAX_LENGTH = 40_000;

/** The proposed change itself. */
const patchSchema = new Schema(
  {
    format: { type: String, enum: [...PATCH_FORMATS], default: 'unified_diff' },
    /** Redacted and capped by the pre-validate hook. */
    content: { type: String, maxlength: PATCH_CONTENT_MAX_LENGTH },
    filesChanged: { type: [String], default: [], validate: maxItems(50) },
    /** Commit the patch was generated against, so it can be checked for staleness. */
    baseCommitSha: { type: String, match: [SHA_REGEX, 'baseCommitSha must be a git object name'] },
  },
  { _id: false },
);

/** Expected payoff, used to rank the remediation backlog. */
const estimatedImpactSchema = new Schema(
  {
    /** Debt-score points this fix is expected to recover. */
    scorePoints: { type: Number, min: 0, max: 100 },
    severitiesResolved: { type: [String], enum: [...SEVERITIES], default: [], validate: maxItems(5) },
  },
  { _id: false },
);

/** Which model produced the suggestion, and how. */
const generatorSchema = new Schema(
  {
    provider: { type: String, trim: true, maxlength: 100 },
    model: { type: String, trim: true, maxlength: 200 },
    promptVersion: { type: String, trim: true, maxlength: 50 },
    temperature: { type: Number, min: 0, max: 2 },
    tokensUsed: { type: Number, min: 0 },
    latencyMs: { type: Number, min: 0 },
    generatedAt: { type: Date, default: () => new Date() },
  },
  { _id: false },
);

/** Human review of the suggestion — the feedback loop for prompt quality. */
const suggestionFeedbackSchema = new Schema(
  {
    rating: { type: String, enum: ['helpful', 'not_helpful', 'partially_helpful'] },
    comment: { type: String, maxlength: 2000 },
    reviewedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    reviewedAt: { type: Date },
  },
  { _id: false },
);

export const remediationSuggestionSchema = new Schema(
  {
    finding: {
      type: Schema.Types.ObjectId,
      ref: 'Finding',
      required: [true, 'finding is required'],
    },
    /** Denormalised so repository-level backlog queries need no join. */
    repository: {
      type: Schema.Types.ObjectId,
      ref: 'Repository',
      required: [true, 'repository is required'],
    },
    /** Scan whose AI analysis produced it. */
    scan: { type: Schema.Types.ObjectId, ref: 'Scan' },

    kind: {
      type: String,
      enum: [...REMEDIATION_KINDS],
      required: [true, 'kind is required'],
    },
    status: {
      type: String,
      enum: [...REMEDIATION_STATUSES],
      required: true,
      default: 'proposed',
    },
    priority: { type: String, enum: [...RISK_LEVELS], default: 'medium' },

    title: { type: String, required: [true, 'title is required'], trim: true, maxlength: 300 },
    summary: { type: String, maxlength: 3000 },
    /** Why this fix is correct — the reasoning a reviewer audits. */
    rationale: { type: String, maxlength: 5000 },
    steps: { type: [String], default: [], validate: maxItems(20) },

    patch: { type: patchSchema, default: () => ({}) },
    estimatedEffort: { type: String, enum: [...REMEDIATION_EFFORTS] },
    estimatedImpact: { type: estimatedImpactSchema, default: () => ({}) },
    /** Risk of applying the fix (regressions, behaviour change). */
    risk: { type: String, enum: [...RISK_LEVELS] },
    references: { type: [referenceSchema], default: [], validate: maxItems(10) },
    docUrl: { type: String, match: [HTTP_URL_REGEX, 'docUrl must be an http(s) URL'] },

    generator: { type: generatorSchema, default: () => ({}) },
    /**
     * Set by the service to `sha256(finding.fingerprint + provider + model +
     * promptVersion)`. Unique and sparse, so regenerating the same suggestion
     * for the same finding is idempotent instead of a second paid LLM call.
     */
    dedupeHash: { type: String, trim: true, maxlength: 128 },

    appliedAt: { type: Date },
    appliedBy: { type: Schema.Types.ObjectId, ref: 'User' },
    appliedCommitSha: { type: String, match: [SHA_REGEX, 'appliedCommitSha must be a git object name'] },
    feedback: { type: suggestionFeedbackSchema, default: () => ({}) },
  },
  { collection: 'remediation_suggestions', timestamps: true },
);

toJsonPlugin(remediationSuggestionSchema);

/**
 * Refuses a patch that contains a credential literal, then enforces the
 * applied-state invariant.
 *
 * Refusing rather than redacting is deliberate: a patch that removes a
 * hardcoded secret must reference `process.env.X`, never the value it is
 * removing. Storing a redacted patch would silently produce a fix that cannot
 * be applied, and losing one suggestion is much cheaper than writing a live
 * credential into the database.
 */
remediationSuggestionSchema.pre('validate', function validateSuggestion() {
  const patch = this.get('patch') as { content?: string } | undefined;

  if (patch?.content && containsSecretLikeContent(patch.content)) {
    this.invalidate(
      'patch.content',
      'patch content appears to contain a credential literal; a remediation patch must reference the secret indirectly',
    );
  }

  const status = this.get('status') as (typeof REMEDIATION_STATUSES)[number];
  if (status === 'applied' && !this.get('appliedAt')) {
    this.invalidate('appliedAt', 'appliedAt is required when status is "applied"');
  }
  if (this.get('appliedAt') && status !== 'applied') {
    this.invalidate('status', 'status must be "applied" once appliedAt is set');
  }
});

// Primary view: the suggestions attached to one finding, newest first.
remediationSuggestionSchema.index(
  { finding: 1, status: 1, createdAt: -1 },
  { name: 'finding_status_recent' },
);
// The remediation backlog, ranked.
remediationSuggestionSchema.index(
  { repository: 1, status: 1, priority: 1, createdAt: -1 },
  { name: 'repository_backlog' },
);
remediationSuggestionSchema.index({ scan: 1 }, { sparse: true, name: 'scan' });
// Idempotency guard for generation (see `dedupeHash`).
remediationSuggestionSchema.index({ dedupeHash: 1 }, { unique: true, sparse: true, name: 'uniq_dedupe' });
// Prompt-quality analysis across the fleet.
remediationSuggestionSchema.index(
  { 'generator.provider': 1, 'generator.model': 1, status: 1 },
  { name: 'generator_model' },
);
remediationSuggestionSchema.index({ appliedAt: -1 }, { sparse: true, name: 'applied_recent' });

export type RemediationSuggestion = InferSchemaType<typeof remediationSuggestionSchema>;
export type RemediationSuggestionDocument = HydratedDocument<RemediationSuggestion>;

export const RemediationSuggestionModel = defineModel(
  'RemediationSuggestion',
  remediationSuggestionSchema,
);
