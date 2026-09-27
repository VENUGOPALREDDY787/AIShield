/**
 * Defence-in-depth secret redaction.
 *
 * Findings legitimately want to carry a short code snippet so a reviewer can
 * judge the issue without opening the repository. That snippet is exactly where
 * a scanner is most likely to paste a live credential — so anything written to
 * a snippet or a remediation patch passes through here first.
 *
 * This is deliberately a *second* line of defence: detectors such as Gitleaks
 * remain the primary control. Keeping a small, curated, offline pattern set
 * means this can run inside a schema hook on every write, with no network call
 * and no meaningful cost.
 */

export interface RedactionResult {
  readonly text: string;
  /** True when at least one pattern matched and the text was altered. */
  readonly redacted: boolean;
  /** Names of the patterns that matched, for audit logging. Never the secrets. */
  readonly patterns: readonly string[];
}

export const REDACTION_PLACEHOLDER = '[REDACTED]';

interface SecretPattern {
  readonly name: string;
  readonly pattern: RegExp;
  /**
   * Optional custom replacement. Receives the match and capture groups so a
   * pattern can keep the surrounding context while masking only the value.
   */
  readonly replace?: (match: string, ...groups: string[]) => string;
}

/**
 * Order matters: specific, high-confidence vendors come before the generic
 * keyword assignment rule, so a GitHub token is labelled as such.
 */
const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    name: 'private-key-block',
    pattern: /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/g,
  },
  { name: 'aws-access-key-id', pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b/g },
  { name: 'github-pat', pattern: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g },
  { name: 'github-token', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  { name: 'slack-token', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,255}\b/g },
  { name: 'google-api-key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'openai-api-key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { name: 'jwt', pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: 'authorization-header', pattern: /\bBearer\s+[A-Za-z0-9._~+/-]{20,}=*/g },
  {
    // Keeps the key name (useful context) and masks only the value.
    //
    // The optional identifier prefix means camelCase and snake_case keys
    // (`dbPassword`, `myApiKey`) are caught too — they are the common shape in
    // real code, and requiring a word boundary would silently miss them.
    // Over-redacting a snippet costs context; under-redacting leaks a secret.
    //
    // The lookahead makes redaction idempotent: without it the replacement
    // itself (`password=[REDACTED]`) would satisfy the pattern again.
    name: 'credential-assignment',
    pattern:
      /([A-Za-z0-9_]*?(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret|password|passwd|private[_-]?key))\b\s*[:=]\s*(["']?)(?!\[REDACTED\])([^\s"',;]{8,})\2/gi,
    replace: (_match: string, key: string) => `${key}=${REDACTION_PLACEHOLDER}`,
  },
];

/**
 * Redacts secret-like substrings. Pure and total: it never throws, and returns
 * the input unchanged (with `redacted: false`) when nothing matches.
 */
export function redactSensitiveText(input: string): RedactionResult {
  let text = input;
  const patterns: string[] = [];

  for (const { name, pattern, replace } of SECRET_PATTERNS) {
    // Patterns are module-level and stateful (`g`); reset before each use.
    pattern.lastIndex = 0;

    if (!pattern.test(text)) continue;
    pattern.lastIndex = 0;
    text = replace ? text.replace(pattern, replace) : text.replace(pattern, REDACTION_PLACEHOLDER);
    patterns.push(name);
  }

  return { text, redacted: text !== input, patterns };
}

/** Convenience predicate for callers that only need a yes/no answer. */
export function containsSecretLikeContent(input: string): boolean {
  return redactSensitiveText(input).redacted;
}
