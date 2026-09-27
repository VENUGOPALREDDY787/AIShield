import { createHash } from 'node:crypto';
import type { ScanFinding } from '@aishield/shared';

export interface DeduplicatedFindingsResult {
  uniqueFindings: ScanFinding[];
  duplicatesRemoved: number;
}

/**
 * Computes a deterministic SHA-256 fingerprint for a finding across commits.
 */
export function computeFindingFingerprint(finding: Partial<ScanFinding>): string {
  const file = finding.location?.filePath || '';
  const rule = finding.ruleId || finding.title || '';
  const content = (finding.location?.snippet || '').trim().replace(/\s+/g, ' ');

  return createHash('sha256')
    .update(`${rule}:${file}:${content}`)
    .digest('hex');
}

/**
 * Deduplicates findings based on their deterministic fingerprint.
 */
export function deduplicateFindings(findings: ScanFinding[]): DeduplicatedFindingsResult {
  const seen = new Set<string>();
  const uniqueFindings: ScanFinding[] = [];
  let duplicatesRemoved = 0;

  for (const finding of findings) {
    const fp = finding.id || computeFindingFingerprint(finding);
    if (seen.has(fp)) {
      duplicatesRemoved++;
    } else {
      seen.add(fp);
      uniqueFindings.push(finding);
    }
  }

  return { uniqueFindings, duplicatesRemoved };
}
