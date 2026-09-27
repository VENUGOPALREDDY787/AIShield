import { describe, expect, it } from 'vitest';
import { UserModel } from '../user.model.js';
import { indexNamed, invalidPaths } from './helpers.js';

const BCRYPT_HASH = '$2b$12$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345';
const ARGON2_HASH =
  '$argon2id$v=19$m=65536,t=3,p=4$abcdefghijklmnop$abcdefghijklmnopqrstuvwx';

const minimalUser = () => ({ providerAccountId: '12345678', username: 'octocat' });

describe('User model', () => {
  it('accepts a minimal user and applies defaults', () => {
    const user = new UserModel(minimalUser());

    expect(invalidPaths(user)).toEqual([]);
    expect(user.provider).toBe('github');
    expect(user.role).toBe('member');
    expect(user.status).toBe('active');
    expect(user.emailVerified).toBe(false);
    expect(user.organizations).toEqual([]);
  });

  it('requires a provider account id and a username', () => {
    expect(invalidPaths(new UserModel({}))).toEqual(['providerAccountId', 'username']);
  });

  it('rejects a provider account id containing unsupported characters', () => {
    const user = new UserModel({ providerAccountId: 'has space and / slash', username: 'x' });

    expect(invalidPaths(user)).toContain('providerAccountId');
  });

  it('lowercases the email and rejects a malformed one', () => {
    const valid = new UserModel({ ...minimalUser(), email: 'Octo@Example.COM' });
    expect(invalidPaths(valid)).toEqual([]);
    expect(valid.email).toBe('octo@example.com');

    const invalid = new UserModel({ ...minimalUser(), email: 'not-an-email' });
    expect(invalidPaths(invalid)).toContain('email');
  });

  it('rejects an avatar url that is not http(s)', () => {
    expect(invalidPaths(new UserModel({ ...minimalUser(), avatarUrl: 'ftp://x/y.png' }))).toContain(
      'avatarUrl',
    );
    expect(
      invalidPaths(new UserModel({ ...minimalUser(), avatarUrl: 'https://x/y.png' })),
    ).toEqual([]);
  });

  describe('passwordHash', () => {
    it('refuses a plaintext password', () => {
      const user = new UserModel({ ...minimalUser(), passwordHash: 'hunter2' });

      expect(invalidPaths(user)).toContain('passwordHash');
    });

    it('accepts bcrypt and argon2 encodings', () => {
      expect(invalidPaths(new UserModel({ ...minimalUser(), passwordHash: BCRYPT_HASH }))).toEqual([]);
      expect(invalidPaths(new UserModel({ ...minimalUser(), passwordHash: ARGON2_HASH }))).toEqual([]);
    });

    it('is excluded from queries by default', () => {
      const options = UserModel.schema.path('passwordHash')?.options as { select?: boolean };

      expect(options.select).toBe(false);
    });

    it('never appears in serialised output', () => {
      const user = new UserModel({ ...minimalUser(), passwordHash: BCRYPT_HASH });
      const json = user.toJSON() as Record<string, unknown>;

      expect(json).not.toHaveProperty('passwordHash');
      expect(JSON.stringify(json)).not.toContain('$2b$');
    });
  });

  it('serialises with a string id and no internal fields', () => {
    const json = new UserModel(minimalUser()).toJSON() as Record<string, unknown>;

    expect(typeof json.id).toBe('string');
    expect(json).not.toHaveProperty('_id');
    expect(json).not.toHaveProperty('__v');
  });

  it('validates organisation memberships', () => {
    const user = new UserModel({
      ...minimalUser(),
      organizations: [{ orgId: 'acme', login: 'acme' }],
    });

    expect(invalidPaths(user)).toEqual([]);
    expect(user.organizations[0]?.role).toBe('member');

    const bad = new UserModel({
      ...minimalUser(),
      organizations: [{ orgId: 'has space', login: 'acme' }],
    });
    expect(invalidPaths(bad)).toContain('organizations.0.orgId');
  });

  it('declares the unique identity indexes', () => {
    const account = indexNamed(UserModel, 'uniq_provider_account');
    expect(account?.key).toBe('provider:1,providerAccountId:1');
    expect(account?.options.unique).toBe(true);

    // Sparse, because a user may legitimately have no email address.
    const email = indexNamed(UserModel, 'uniq_email');
    expect(email?.key).toBe('email:1');
    expect(email?.options.unique).toBe(true);
    expect(email?.options.sparse).toBe(true);
  });
});
