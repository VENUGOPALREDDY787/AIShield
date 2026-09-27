/**
 * User — an authenticated person who can own repositories and trigger scans.
 *
 * Identity is delegated to an OAuth provider, so `(provider,
 * providerAccountId)` is the real primary key; `email` and `username` are
 * denormalised attributes that may change upstream.
 *
 * Security posture:
 *  - `passwordHash` exists only for the optional local-credentials path, is
 *    excluded from queries by default and is stripped from JSON output.
 *  - No provider access token is ever stored here. Tokens belong in a secret
 *    manager; the repository model keeps only an installation id.
 */
import { Schema, type HydratedDocument, type InferSchemaType } from 'mongoose';
import { SEVERITIES } from '@aishield/shared';
import { REPOSITORY_PROVIDERS, USER_ROLES, USER_STATUSES } from './enums.js';
import { toJsonPlugin } from './plugins/to-json.plugin.js';
import { defineModel } from './registry.js';
import { HTTP_URL_REGEX, PASSWORD_HASH_REGEX, PROVIDER_ID_REGEX } from './validators.js';

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Membership of a provider organisation (GitHub org, GitLab group). */
const organizationMembershipSchema = new Schema(
  {
    orgId: { type: String, required: true, match: PROVIDER_ID_REGEX },
    login: { type: String, required: true, trim: true, maxlength: 200 },
    role: { type: String, enum: [...USER_ROLES], default: 'member' },
    joinedAt: { type: Date, default: () => new Date() },
  },
  { _id: false },
);

const notificationPreferencesSchema = new Schema(
  {
    email: { type: Boolean, default: true },
    slack: { type: Boolean, default: false },
    /** Only notify about findings at or above this severity. */
    minimumSeverity: { type: String, enum: [...SEVERITIES], default: 'high' },
  },
  { _id: false },
);

const userPreferencesSchema = new Schema(
  {
    notifications: { type: notificationPreferencesSchema, default: () => ({}) },
  },
  { _id: false },
);

export const userSchema = new Schema(
  {
    provider: {
      type: String,
      enum: [...REPOSITORY_PROVIDERS],
      required: true,
      default: 'github',
    },
    providerAccountId: {
      type: String,
      required: [true, 'providerAccountId is required'],
      match: [PROVIDER_ID_REGEX, 'providerAccountId contains unsupported characters'],
    },
    username: {
      type: String,
      required: [true, 'username is required'],
      trim: true,
      maxlength: 100,
    },
    displayName: { type: String, trim: true, maxlength: 200 },
    email: {
      type: String,
      lowercase: true,
      trim: true,
      maxlength: 320,
      match: [EMAIL_REGEX, 'email is not a valid address'],
    },
    emailVerified: { type: Boolean, default: false },
    avatarUrl: { type: String, match: [HTTP_URL_REGEX, 'avatarUrl must be an http(s) URL'] },

    role: { type: String, enum: [...USER_ROLES], default: 'member' },
    status: { type: String, enum: [...USER_STATUSES], default: 'active' },

    organizations: { type: [organizationMembershipSchema], default: [] },

    /**
     * Optional local-credentials hash. Never selected by default and never
     * serialised; the `match` makes a plaintext value a validation error.
     */
    passwordHash: {
      type: String,
      select: false,
      match: [PASSWORD_HASH_REGEX, 'passwordHash must be a bcrypt or argon2 hash'],
    },

    preferences: { type: userPreferencesSchema, default: () => ({}) },

    lastLoginAt: { type: Date },
    lastActiveAt: { type: Date },
  },
  { collection: 'users', timestamps: true },
);

toJsonPlugin(userSchema, { redact: ['passwordHash'] });

// One account per provider identity — the true natural key.
userSchema.index(
  { provider: 1, providerAccountId: 1 },
  { unique: true, name: 'uniq_provider_account' },
);

// Sparse: a user may have no verified email, but two users may never share one.
userSchema.index({ email: 1 }, { unique: true, sparse: true, name: 'uniq_email' });

userSchema.index({ provider: 1, username: 1 }, { name: 'provider_username' });
userSchema.index({ 'organizations.orgId': 1 }, { name: 'org_membership' });
// Powers "who is active" admin views and stale-account sweeps.
userSchema.index({ status: 1, lastLoginAt: -1 }, { name: 'status_last_login' });

export type User = InferSchemaType<typeof userSchema>;
export type UserDocument = HydratedDocument<User>;

export const UserModel = defineModel('User', userSchema);
