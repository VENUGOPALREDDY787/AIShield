/**
 * Reusable validation primitives.
 *
 * Sharing these keeps the rules identical across the eight schemas: a commit
 * SHA is validated the same way on `Scan`, `PullRequest` and
 * `RemediationSuggestion`, and the error messages stay consistent.
 */

/** Git object name: abbreviated (7+) through full SHA-1/SHA-256 hex. */
export const SHA_REGEX = /^[0-9a-f]{7,64}$/i;

/** MITRE CWE identifier, e.g. `CWE-79`. */
export const CWE_REGEX = /^CWE-\d{1,5}$/;

/** `owner/name` — one slash, no whitespace either side. */
export const REPOSITORY_FULL_NAME_REGEX = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;

/** Provider-side numeric or opaque account/repository identifier. */
export const PROVIDER_ID_REGEX = /^[A-Za-z0-9._-]{1,200}$/;

export const HTTP_URL_REGEX = /^https?:\/\/[^\s]+$/;

/** Lowercase hex SHA-256, used for fingerprints and content hashes. */
export const SHA256_REGEX = /^[a-f0-9]{64}$/;

/**
 * Password hashes must be a recognised bcrypt or argon2 encoding. This is a
 * guard rail, not authentication: it makes "someone stored a plaintext
 * password here" a validation failure instead of a silent data breach.
 */
export const PASSWORD_HASH_REGEX = /^\$(?:argon2(?:id|i|d)|2[aby])\$[^\s]+$/;

/** Mongoose `validate` object that caps an array's length. */
export function maxItems(length: number): {
  validator: (value: unknown[] | undefined) => boolean;
  message: string;
} {
  return {
    // `undefined` is allowed: "absent" is different from "too long".
    validator: (value) => !value || value.length <= length,
    message: `Must contain at most ${length} items`,
  };
}

export function isSha(value: string): boolean {
  return SHA_REGEX.test(value);
}

export function isHttpUrl(value: string): boolean {
  return HTTP_URL_REGEX.test(value);
}
