import { describe, expect, it } from 'vitest';
import { calculateSecurityDebt } from '../debt-calculator.js';
import type { ScanFinding } from '@aishield/shared';

describe('DebtCalculator', () => {
  it('returns clean score of 100 with grade A when findings are empty', () => {
    const summary = calculateSecurityDebt([]);
    expect(summary.overallScore).toBe(100);
    expect(summary.grade).toBe('A');
    expect(summary.totalDebtPoints).toBe(0);
    expect(summary.severityBreakdown.critical).toBe(0);
  });

  it('calculates weighted severity penalties and degrades score', () => {
    const findings: ScanFinding[] = [
      {
        id: 'f1',
        scanId: 's1',
        scanner: 'semgrep',
        category: 'security',
        severity: 'critical',
        title: 'SQL Injection',
      },
      {
        id: 'f2',
        scanId: 's1',
        scanner: 'gitleaks',
        category: 'secret',
        severity: 'high',
        title: 'Leaked API Key',
      },
    ];

    const summary = calculateSecurityDebt(findings, 100);
    // critical (10) + high (5) = 15 points
    expect(summary.totalDebtPoints).toBe(15);
    expect(summary.severityBreakdown.critical).toBe(1);
    expect(summary.severityBreakdown.high).toBe(1);
    expect(summary.overallScore).toBeLessThan(100);
    expect(summary.deltaScore).toBeLessThan(0);
  });
});
