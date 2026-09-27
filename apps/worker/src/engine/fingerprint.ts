import { createHash } from 'node:crypto';
import type { NormalizedCategory } from '@aishield/shared';

export interface FingerprintData {
  source?: string;
  ruleId?: string;
  file?: string;
  line?: number;
  snippet?: string;
  category?: NormalizedCategory | string;
  cwe?: string;
  title?: string;
  packageName?: string;
  advisoryId?: string;
}

/**
 * Canonicalizes a file path for consistent cross-platform matching.
 */
export function canonicalizeFilePath(rawPath?: string): string {
  if (!rawPath) return '';
  return rawPath
    .replace(/\\/g, '/')
    .replace(/^\.\//, '')
    .replace(/^\//, '')
    .trim();
}

/**
 * Normalizes code snippet whitespace and comments so formatting differences do not break fingerprints.
 */
export function normalizeSnippet(snippet?: string): string {
  if (!snippet) return '';
  return snippet
    .replace(/\/\*[\s\S]*?\*\/|\/\/.*/g, '') // strip comments
    .replace(/\s+/g, ' ') // collapse multi-spaces and newlines
    .trim();
}

/**
 * Generates a stable SHA-256 fingerprint for a finding across commits and scanners.
 */
export function generateStableFingerprint(data: FingerprintData): string {
  const file = canonicalizeFilePath(data.file);
  const src = String(data.source || '').toLowerCase();

  // 1. Dependency Scanner archetype: package + advisory ID
  if (src === 'dependency' || src === 'osv' || data.packageName || data.advisoryId) {
    const pkg = (data.packageName || data.title || '').toLowerCase().trim();
    const adv = (data.advisoryId || data.ruleId || data.cwe || '').toUpperCase().trim();
    return createHash('sha256')
      .update(`dependency:${pkg}:${adv}`)
      .digest('hex');
  }

  // 2. Secret Scanner archetype: file + rule + line/context
  if (src === 'gitleaks' || data.category === 'secrets') {
    const rule = (data.ruleId || 'secret-leak').toLowerCase().trim();
    const line = data.line ?? 1;
    return createHash('sha256')
      .update(`secret:${file}:${rule}:${line}`)
      .digest('hex');
  }

  // 3. SAST / AI Code Finding archetype
  const rule = (data.ruleId || data.title || 'generic-rule').toLowerCase().trim();
  const normalizedCode = normalizeSnippet(data.snippet);

  if (normalizedCode.length > 5) {
    // Content-anchored fingerprint: resilient to line additions/removals above this code
    return createHash('sha256')
      .update(`code:${file}:${rule}:${normalizedCode}`)
      .digest('hex');
  }

  // Fallback: file + rule + line
  const line = data.line ?? 1;
  return createHash('sha256')
    .update(`loc:${file}:${rule}:${line}`)
    .digest('hex');
}

/**
 * Determines whether two findings are correlated (i.e. refer to the same vulnerability instance
 * in the codebase, even if emitted by different scanners or an AI analyzer).
 */
export function areFindingsCorrelated(
  f1: { file: string; line: number; category: NormalizedCategory; fingerprint?: string; ruleId?: string; cwe?: string; title?: string },
  f2: { file: string; line: number; category: NormalizedCategory; fingerprint?: string; ruleId?: string; cwe?: string; title?: string },
): boolean {
  // 1. Exact fingerprint match
  if (f1.fingerprint && f2.fingerprint && f1.fingerprint === f2.fingerprint) {
    return true;
  }

  const file1 = canonicalizeFilePath(f1.file);
  const file2 = canonicalizeFilePath(f2.file);

  if (!file1 || !file2 || file1 !== file2) {
    return false;
  }

  // 2. Same rule on the same file
  if (f1.ruleId && f2.ruleId && f1.ruleId === f2.ruleId) {
    return Math.abs(f1.line - f2.line) <= 5;
  }

  // 3. Same CWE on the same file and overlapping or adjacent lines
  if (f1.cwe && f2.cwe && f1.cwe === f2.cwe) {
    return Math.abs(f1.line - f2.line) <= 5;
  }

  // 4. Same category on the same file with overlapping or adjacent lines (window of 5 lines)
  if (f1.category === f2.category && Math.abs(f1.line - f2.line) <= 5) {
    return true;
  }

  return false;
}
