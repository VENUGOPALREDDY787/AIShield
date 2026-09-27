/**
 * PullRequest — the change-request context for a scan.
 *
 * The point of modelling PRs separately from scans is the *delta*: "did this
 * pull request introduce or remove risk?". `Scan.pullRequest` records the
 * relationship, while this document caches the aggregate outcome
 * (`findingsIntroduced`, `findingsResolved`, `scoreDelta`) so a PR list page is
 * one indexed query instead of an aggregation over every scan of the branch.
 */
import { Schema, type HydratedDocument, type InferSchemaType } from 'mongoose';
import { SCAN_STATUSES } from '@aishield/shared';
import { PULL_REQUEST_STATES } from './enums.js';
import { toJsonPlugin } from './plugins/to-json.plugin.js';
import { defineModel } from './registry.js';
import { HTTP_URL_REGEX, PROVIDER_ID_REGEX, SHA_REGEX } from './validators.js';

/** PR author, as reported by the provider (may not be a registered user). */
const pullRequestAuthorSchema = new Schema(
  {
    providerAccountId: { type: String, match: PROVIDER_ID_REGEX },
    login: { type: String, required: true, trim: true, maxlength: 200 },
    avatarUrl: { type: String, match: HTTP_URL_REGEX },
  },
  { _id: false },
);

export const pullRequestSchema = new Schema(
  {
    repository: {
      type: Schema.Types.ObjectId,
      ref: 'Repository',
      required: [true, 'repository is required'],
    },

    /** Provider-side PR number; unique within a repository. */
    number: {
      type: Number,
      required: [true, 'number is required'],
      min: [1, 'number must be a positive PR number'],
    },
    providerPrId: { type: String, match: PROVIDER_ID_REGEX },
    title: { type: String, required: true, trim: true, maxlength: 500 },
    author: { type: pullRequestAuthorSchema, required: true },

    state: { type: String, enum: [...PULL_REQUEST_STATES], default: 'open' },
    isDraft: { type: Boolean, default: false },

    baseBranch: { type: String, required: true, trim: true, maxlength: 255 },
    headBranch: { type: String, required: true, trim: true, maxlength: 255 },
    baseSha: { type: String, match: [SHA_REGEX, 'baseSha must be a git object name'] },
    headSha: { type: String, match: [SHA_REGEX, 'headSha must be a git object name'] },

    additions: { type: Number, min: 0 },
    deletions: { type: Number, min: 0 },
    changedFiles: { type: Number, min: 0 },
    htmlUrl: { type: String, match: [HTTP_URL_REGEX, 'htmlUrl must be an http(s) URL'] },

    openedAt: { type: Date, required: true, default: () => new Date() },
    closedAt: { type: Date },
    mergedAt: { type: Date },
    mergedByLogin: { type: String, trim: true, maxlength: 200 },

    /** Most recent scan performed against this PR's head commit. */
    latestScan: { type: Schema.Types.ObjectId, ref: 'Scan' },
    scanStatus: { type: String, enum: [...SCAN_STATUSES], default: 'queued' },

    /** Cached risk delta for the PR list view. */
    findingsIntroduced: { type: Number, min: 0, default: 0 },
    findingsResolved: { type: Number, min: 0, default: 0 },
    /** Change in debt score contributed by this PR. Positive = improvement. */
    scoreDelta: { type: Number, default: 0 },
  },
  { collection: 'pull_requests', timestamps: true },
);

toJsonPlugin(pullRequestSchema);

/**
 * Cross-field invariants. Kept in a hook rather than per-path validators
 * because they relate several fields at once.
 */
pullRequestSchema.pre('validate', function validatePullRequestLifecycle() {
  const state = this.get('state') as (typeof PULL_REQUEST_STATES)[number];
  const openedAt = this.get('openedAt') as Date | undefined;
  const closedAt = this.get('closedAt') as Date | undefined;
  const mergedAt = this.get('mergedAt') as Date | undefined;

  if (mergedAt && !closedAt) {
    this.invalidate('closedAt', 'closedAt is required once a pull request is merged');
  }
  if (mergedAt && state !== 'merged') {
    this.invalidate('state', 'state must be "merged" when mergedAt is set');
  }
  if (openedAt && closedAt && closedAt.getTime() < openedAt.getTime()) {
    this.invalidate('closedAt', 'closedAt cannot precede openedAt');
  }
  if (closedAt && mergedAt && mergedAt.getTime() < closedAt.getTime()) {
    this.invalidate('mergedAt', 'mergedAt cannot precede closedAt');
  }
});

// A PR number is unique per repository — the natural key for URL routing.
pullRequestSchema.index(
  { repository: 1, number: 1 },
  { unique: true, name: 'uniq_repository_number' },
);

pullRequestSchema.index({ repository: 1, state: 1, updatedAt: -1 }, { name: 'repository_state_recent' });
// "Which PR first introduced this commit?" — also used to attach scans.
pullRequestSchema.index({ repository: 1, headSha: 1 }, { name: 'repository_head_sha' });
pullRequestSchema.index({ headSha: 1 }, { name: 'head_sha' });
pullRequestSchema.index({ 'author.login': 1, updatedAt: -1 }, { name: 'author_recent' });
pullRequestSchema.index({ latestScan: 1 }, { sparse: true, name: 'latest_scan' });
// Risk-delta leaderboard: "which PRs made things worse?"
pullRequestSchema.index({ repository: 1, scoreDelta: 1, updatedAt: -1 }, { name: 'risk_delta' });

export type PullRequest = InferSchemaType<typeof pullRequestSchema>;
export type PullRequestDocument = HydratedDocument<PullRequest>;

export const PullRequestModel = defineModel('PullRequest', pullRequestSchema);
