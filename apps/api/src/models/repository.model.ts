/**
 * Repository — a tracked source repository.
 *
 * This is the pivot of the whole data model: scans, pull requests, findings and
 * debt scores are all scoped to exactly one repository. Its `_id` is therefore
 * the first key of almost every compound index in the system, which keeps all
 * per-repository queries single-shard friendly.
 *
 * Security posture: no access token, no deploy key, no webhook secret is stored
 * here. `installationId` is a *reference* to a credential held by the GitHub App
 * installation (or a secret manager), never the credential itself.
 */
import { Schema, type HydratedDocument, type InferSchemaType } from 'mongoose';
import { SCAN_STATUSES } from '@aishield/shared';
import { REPOSITORY_PROVIDERS } from './enums.js';
import { toJsonPlugin } from './plugins/to-json.plugin.js';
import { defineModel } from './registry.js';
import {
  HTTP_URL_REGEX,
  PROVIDER_ID_REGEX,
  REPOSITORY_FULL_NAME_REGEX,
  maxItems,
} from './validators.js';

const SSH_URL_REGEX = /^(?:ssh:\/\/)?git@[^\s:]+:[^\s]+$/;

/** Denormalised counters so a dashboard never has to aggregate `findings`. */
const repositoryStatsSchema = new Schema(
  {
    openFindings: { type: Number, min: 0, default: 0 },
    criticalFindings: { type: Number, min: 0, default: 0 },
    lastCalculatedAt: { type: Date },
  },
  { _id: false },
);

export const repositorySchema = new Schema(
  {
    provider: {
      type: String,
      enum: [...REPOSITORY_PROVIDERS],
      required: true,
      default: 'github',
    },
    /** Provider-side id; string so it is stable across providers. */
    providerRepoId: {
      type: String,
      required: [true, 'providerRepoId is required'],
      match: [PROVIDER_ID_REGEX, 'providerRepoId contains unsupported characters'],
    },
    /** Canonical `owner/name`. */
    fullName: {
      type: String,
      required: [true, 'fullName is required'],
      trim: true,
      maxlength: 300,
      match: [REPOSITORY_FULL_NAME_REGEX, 'fullName must look like "owner/repo"'],
    },
    name: { type: String, required: true, trim: true, maxlength: 200 },
    ownerLogin: { type: String, required: true, trim: true, maxlength: 200 },

    /** Local user who registered the repository (authorisation boundary). */
    owner: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'owner is required'],
    },

    isPrivate: { type: Boolean, default: false },
    isArchived: { type: Boolean, default: false },
    isFork: { type: Boolean, default: false },
    visibility: { type: String, enum: ['public', 'private', 'internal'], default: 'private' },

    defaultBranch: { type: String, required: true, trim: true, maxlength: 255, default: 'main' },
    primaryLanguage: { type: String, trim: true, maxlength: 100 },
    topics: { type: [String], default: [], validate: maxItems(50) },
    description: { type: String, trim: true, maxlength: 2000 },
    sizeKb: { type: Number, min: 0 },

    htmlUrl: { type: String, match: [HTTP_URL_REGEX, 'htmlUrl must be an http(s) URL'] },
    cloneUrl: { type: String, match: [HTTP_URL_REGEX, 'cloneUrl must be an http(s) URL'] },
    sshUrl: { type: String, match: [SSH_URL_REGEX, 'sshUrl must be a git SSH URL'] },

    /**
     * Reference to the GitHub App installation that grants read access.
     * A reference — deliberately not the token.
     */
    installationId: { type: String, trim: true, maxlength: 100 },

    scanEnabled: { type: Boolean, default: true },
    autoScanOnPush: { type: Boolean, default: true },

    lastScanAt: { type: Date },
    lastScanStatus: { type: String, enum: [...SCAN_STATUSES] },
    /** Most recent scan; the authoritative source is still the `scans` collection. */
    latestScan: { type: Schema.Types.ObjectId, ref: 'Scan' },
    /** Current debt snapshot; mirrors the unique `SecurityDebt` document. */
    latestDebt: { type: Schema.Types.ObjectId, ref: 'SecurityDebt' },

    stats: { type: repositoryStatsSchema, default: () => ({}) },
  },
  { collection: 'repositories', timestamps: true },
);

toJsonPlugin(repositorySchema);

// A provider repository is registered at most once, globally.
repositorySchema.index(
  { provider: 1, providerRepoId: 1 },
  { unique: true, name: 'uniq_provider_repo' },
);
// Renames upstream must not create a duplicate row.
repositorySchema.index({ provider: 1, fullName: 1 }, { unique: true, name: 'uniq_provider_full_name' });

// "My repositories", excluding archived ones.
repositorySchema.index({ owner: 1, isArchived: 1, updatedAt: -1 }, { name: 'owner_active' });
// The scan scheduler's work queue: enabled repos, least recently scanned first.
repositorySchema.index({ scanEnabled: 1, lastScanAt: 1 }, { name: 'scan_schedule' });
repositorySchema.index({ topics: 1 }, { name: 'topics' });
repositorySchema.index({ primaryLanguage: 1, updatedAt: -1 }, { name: 'language_recent' });

export type Repository = InferSchemaType<typeof repositorySchema>;
export type RepositoryDocument = HydratedDocument<Repository>;

export const RepositoryModel = defineModel('Repository', repositorySchema);
