import { createHash } from 'node:crypto';
import type { NormalizedFinding } from '@aishield/shared';
import type { AIFinding } from './types.js';

function cleanFilePath(rawPath: string): string {
  let cleaned = rawPath.replace(/\\/g, '/').trim();
  if (cleaned.startsWith('/src/')) {
    cleaned = cleaned.slice(5);
  } else if (cleaned.startsWith('/src')) {
    cleaned = cleaned.slice(4);
  }
  if (cleaned.startsWith('./')) {
    cleaned = cleaned.slice(2);
  }
  return cleaned;
}

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60)
    .replace(/-+$/, '');
}

function generateAIFingerprint(file: string, title: string, line: number, evidence: string): string {
  const normPath = file.replace(/\\/g, '/');
  const normContext = `${title}:${line}:${evidence.trim().replace(/\s+/g, ' ')}`;
  return createHash('sha256').update(`ai-analyzer:${normPath}:${normContext}`).digest('hex');
}

/**
 * Normalizes an array of validated AI findings into standard AIShield NormalizedFinding objects.
 */
export function normalizeAIFindings(
  aiFindings: readonly AIFinding[],
  metadata: { model: string; provider: string; scanId?: string },
): NormalizedFinding[] {
  return aiFindings.map((f) => {
    const file = cleanFilePath(f.file);
    const ruleId = `ai-contextual-${slugify(f.title)}`;
    const fingerprint = generateAIFingerprint(file, f.title, f.line, f.evidence);

    return {
      source: 'ai-analyzer',
      ruleId,
      category: f.category,
      title: f.title,
      description: f.description,
      severity: f.severity,
      confidence: f.confidence,
      file,
      line: f.line,
      fingerprint,
      remediation: f.remediation,
      metadata: {
        evidence: f.evidence,
        reasoningSummary: f.reasoning_summary,
        model: metadata.model,
        provider: metadata.provider,
        scanId: metadata.scanId,
      },
    };
  });
}
