import { describe, expect, it } from 'vitest';
import {
  REDACTION_PLACEHOLDER,
  containsSecretLikeContent,
  redactSensitiveText,
} from '../redact-sensitive.js';

describe('redactSensitiveText', () => {
  it.each([
    ['AWS access key id', 'const key = "' + 'AKIA' + 'IOSFODNN7EXAMPLE";', 'aws-access-key-id'],
    [
      'GitHub fine-grained PAT',
      'token: ' + 'github_' + 'pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGH',
      'github-pat',
    ],
    ['GitHub classic token', 'GH_TOKEN=' + 'gh' + 'p_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij', 'github-token'],
    ['Slack token', 'slack: ' + 'xox' + 'b-123456789012-abcdefghijklmnop', 'slack-token'],
    ['Google API key', 'key=' + 'AI' + 'zaSyA1234567890abcdefghijklmnopqrstuv', 'google-api-key'],
    [
      'OpenAI key',
      'OPENAI_KEY=' + 'sk-' + 'proj-abcdefghijklmnopqrstuvwxyz0123456789',
      'openai-api-key',
    ],
    [
      'PEM private key block',
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----',
      'private-key-block',
    ],
    [
      'JSON web token',
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g',
      'jwt',
    ],
    [
      'bearer token',
      'Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345',
      'authorization-header',
    ],
    ['credential assignment', 'const password = "hunter2secret"', 'credential-assignment'],
  ])('redacts a %s', (_label, input, expectedPattern) => {
    const result = redactSensitiveText(input);

    expect(result.redacted).toBe(true);
    expect(result.patterns).toContain(expectedPattern);
    expect(result.text).toContain(REDACTION_PLACEHOLDER);
  });

  it('masks only the value of a credential assignment, keeping the key name', () => {
    const result = redactSensitiveText('const dbPassword = "supersecretvalue";');

    expect(result.text).toContain('dbPassword');
    expect(result.text).not.toContain('supersecretvalue');
  });

  it('removes the secret itself, not just the label', () => {
    const result = redactSensitiveText('AKIAIOSFODNN7EXAMPLE');

    expect(result.text).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(result.text).toBe(REDACTION_PLACEHOLDER);
  });

  it('leaves ordinary source code untouched', () => {
    const code = [
      'const total = items.reduce((sum, item) => sum + item.price, 0);',
      '// the password reset flow lives in auth/reset.ts',
      'export function computeScore(weights) { return Object.values(weights).length; }',
    ].join('\n');

    const result = redactSensitiveText(code);

    expect(result.redacted).toBe(false);
    expect(result.text).toBe(code);
    expect(result.patterns).toEqual([]);
  });

  it('is idempotent: redacting an already-redacted string changes nothing', () => {
    const once = redactSensitiveText('password = "supersecretvalue"');
    const twice = redactSensitiveText(once.text);

    expect(twice.redacted).toBe(false);
    expect(twice.text).toBe(once.text);
  });

  it('handles the empty string', () => {
    expect(redactSensitiveText('')).toEqual({ text: '', redacted: false, patterns: [] });
  });
});

describe('containsSecretLikeContent', () => {
  it('is a predicate over the same pattern set', () => {
    expect(containsSecretLikeContent('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij')).toBe(true);
    expect(containsSecretLikeContent('const port = 4000;')).toBe(false);
  });
});
