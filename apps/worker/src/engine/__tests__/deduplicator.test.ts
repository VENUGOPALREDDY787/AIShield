import { describe, expect, it } from 'vitest';
import { deduplicateFindings, computeFindingFingerprint } from '../deduplicator.js';
import type { ScanFinding } from '@aishield/shared';

describe('Deduplicator', () => {
  it('generates consistent fingerprint for same file and rule', () => {
    const findingA: Partial<ScanFinding> = {
      ruleId: 'semgrep-sqli',
      location: { filePath: 'src/user.ts', startLine: 10, snippet: 'SELECT * FROM users' },
    };
    const findingB: Partial<ScanFinding> = {
      ruleId: 'semgrep-sqli',
      location: { filePath: 'src/user.ts', startLine: 12, snippet: 'SELECT * FROM users' },
    };

    expect(computeFindingFingerprint(findingA)).toBe(computeFindingFingerprint(findingB));
  });

  it('deduplicates identical findings', () => {
    const findings: ScanFinding[] = [
      {
        id: 'dup-1',
        scanId: 's1',
        scanner: 'semgrep',
        category: 'security',
        severity: 'critical',
        title: 'SQLi',
      },
      {
        id: 'dup-1',
        scanId: 's1',
        scanner: 'semgrep',
        category: 'security',
        severity: 'critical',
        title: 'SQLi',
      },
      {
        id: 'dup-2',
        scanId: 's1',
        scanner: 'gitleaks',
        category: 'secret',
        severity: 'high',
        title: 'Secret',
      },
    ];

    const result = deduplicateFindings(findings);
    expect(result.uniqueFindings.length).toBe(2);
    expect(result.duplicatesRemoved).toBe(1);
  });
});
