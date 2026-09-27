import { createHash } from 'node:crypto';

export const REDACTION_PLACEHOLDER = '[REDACTED]';

/**
 * Masks a secret string to hide sensitive contents while optionally preserving
 * a short prefix and suffix to assist developers in identifying which credential was leaked.
 *
 * Examples:
 * - "short" -> "[REDACTED]"
 * - "AKIAIOSFODNN7EXAMPLE" -> "AKIA************MPLE"
 */
export function maskSecret(secret: string, visibleEdgeChars = 4): string {
  if (!secret) {
    return '';
  }

  const trimmed = secret.trim();
  if (trimmed.length <= 8) {
    return REDACTION_PLACEHOLDER;
  }

  const edge = Math.min(visibleEdgeChars, Math.floor(trimmed.length / 4));
  const prefix = trimmed.slice(0, edge);
  const suffix = trimmed.slice(-edge);
  const maskedLength = trimmed.length - edge * 2;
  const stars = '*'.repeat(Math.max(maskedLength, 8));

  return `${prefix}${stars}${suffix}`;
}

/**
 * Computes a non-reversible cryptographic hash tag for a secret.
 * Used for stable deduplication and audit logging without ever storing the plain secret.
 */
export function hashSecret(secret: string): string {
  if (!secret) {
    return '';
  }
  const hex = createHash('sha256').update(secret).digest('hex');
  return `[REDACTED_SHA256:${hex.slice(0, 16)}]`;
}

/**
 * Generates a stable fingerprint for a secret finding.
 * Uses the normalized file path, rule ID, and a SHA-256 hash of the secret value.
 * This makes the fingerprint invariant to line shifting or branch rebasing.
 */
export function generateSecretFingerprint(
  ruleId: string,
  filePath: string,
  secretOrHash?: string,
): string {
  const normalizedPath = filePath.replace(/\\/g, '/');
  let token = secretOrHash || '';
  if (token && !token.startsWith('[REDACTED_SHA256:')) {
    token = createHash('sha256').update(token).digest('hex');
  }
  return createHash('sha256')
    .update(`secret:${ruleId}:${normalizedPath}:${token}`)
    .digest('hex');
}

/**
 * Replaces every occurrence of a specific secret string inside a body of text.
 */
export function redactSecretFromText(text: string, secret: string): string {
  if (!text || !secret) {
    return text;
  }
  const masked = maskSecret(secret);
  return text.split(secret).join(masked);
}

interface SecretPattern {
  readonly name: string;
  readonly pattern: RegExp;
  readonly replace?: (match: string, ...groups: string[]) => string;
}

const COMMON_SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    name: 'private-key-block',
    pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
  },
  { name: 'aws-access-key-id', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g },
  { name: 'github-pat', pattern: /\bgithub_pat_[A-Za-z0-9_]{20,255}\b/g },
  { name: 'github-token', pattern: /\bgh[pousr]_[A-Za-z0-9]{20,255}\b/g },
  { name: 'slack-token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,255}\b/g },
  { name: 'google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'openai-api-key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: 'authorization-header', pattern: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/g },
  {
    name: 'credential-assignment',
    pattern:
      /([A-Za-z0-9_]*?(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|password|passwd|private[_-]?key))\b\s*[:=]\s*(["']?)(?!\[REDACTED\])([^\s"',;]{8,})\2/gi,
    replace: (_match: string, key: string) => `${key}=${REDACTION_PLACEHOLDER}`,
  },
];

export interface PatternRedactionResult {
  readonly text: string;
  readonly redacted: boolean;
  readonly matchedPatterns: readonly string[];
}

/**
 * Scans arbitrary text against high-confidence secret patterns and masks any matches.
 * Defence-in-depth for code snippets, PR comments, and log messages.
 */
export function redactSensitivePatterns(input: string): PatternRedactionResult {
  if (!input) {
    return { text: input, redacted: false, matchedPatterns: [] };
  }

  let text = input;
  const matchedPatterns: string[] = [];

  for (const { name, pattern, replace } of COMMON_SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    if (!pattern.test(text)) continue;
    pattern.lastIndex = 0;
    text = replace ? text.replace(pattern, replace) : text.replace(pattern, REDACTION_PLACEHOLDER);
    matchedPatterns.push(name);
  }

  return {
    text,
    redacted: text !== input,
    matchedPatterns,
  };
}

export interface PrSecretAlertOptions {
  readonly ruleId: string;
  readonly file: string;
  readonly line: number;
  readonly description?: string;
  readonly maskedSecret?: string;
  readonly secretHash?: string;
}

/**
 * Formats a clean, safe Markdown comment for GitHub Pull Requests.
 * Guarantees that raw secret values are never included in the comment body.
 */
export function formatPrSecretAlert(options: PrSecretAlertOptions): string {
  const masked = options.maskedSecret || REDACTION_PLACEHOLDER;
  const hashTag = options.secretHash ? ` (${options.secretHash})` : '';

  return [
    '### ⚠️ AIShield Security Alert: Hardcoded Secret Detected',
    '',
    `AIShield detected hardcoded credentials introduced in this pull request.`,
    '',
    `| Property | Value |`,
    `| --- | --- |`,
    `| **Rule ID** | \`${options.ruleId}\` |`,
    `| **File** | \`${options.file}:${options.line}\` |`,
    `| **Classification** | Critical Secret Exposure (CWE-798) |`,
    `| **Masked Value** | \`${masked}\`${hashTag} |`,
    '',
    '#### Required Remediation Steps:',
    '1. **Immediately Revoke & Rotate**: Treat this credential as compromised. Invalidate it in your cloud or service provider console.',
    '2. **Externalize Configuration**: Store the replacement secret in an environment variable, GitHub Secrets, or secret manager (e.g. AWS Secrets Manager, HashiCorp Vault).',
    '3. **Purge Git History**: If this commit was pushed to a public remote repository, rewriting git history (via `git filter-repo` or BFG) is strongly advised.',
  ].join('\n');
}
