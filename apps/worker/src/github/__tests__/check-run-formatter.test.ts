import { describe, expect, it } from 'vitest';
import type {
  CategorizedFindingDelta,
  PRDeltaAnalysisResult,
  SecurityDebtResult,
  UnifiedFinding,
} from '@aishield/shared';
import {
  determineCheckConclusion,
  formatCheckRun,
  mapSeverityToAnnotationLevel,
} from '../check-run-formatter.js';

function createMockFinding(overrides: Partial<UnifiedFinding> = {}): UnifiedFinding {
  return {
    id: 'f-1',
    fingerprint: 'fp-1',
    ruleId: 'rce-exec',
    title: 'Command Execution via child_process.exec',
    description: 'Direct shell execution without argument validation',
    severity: 'CRITICAL',
    category: 'command_execution',
    confidence: 1.0,
    file: 'src/utils/runner.ts',
    line: 15,
    cwe: 'CWE-78',
    remediation: 'Use child_process.execFile with argument array',
    distinction: 'confirmed_scanner_finding',
    contributingSources: ['semgrep'],
    sources: [],
    metadata: {},
    ...overrides,
  };
}

function createMockDelta(
  introduced: CategorizedFindingDelta[] = [],
  overrides: Partial<PRDeltaAnalysisResult> = {},
): PRDeltaAnalysisResult {
  return {
    baseCommit: 'baseSha',
    headCommit: 'headSha',
    baseScore: 10,
    headScore: 50,
    newDebt: 40,
    resolvedDebt: 0,
    netDebtChange: 40,
    findingsIntroduced: introduced,
    findingsResolved: overrides.findingsResolved ?? [],
    findingsModified: overrides.findingsModified ?? [],
    findingsUnchanged: overrides.findingsUnchanged ?? [],
    totalHeadFindings: introduced.length,
    totalBaseFindings: overrides.findingsResolved?.length ?? 0,
    changedFilesCount: 1,
    summary: 'PR Summary',
    ...overrides,
  };
}

function createMockDebt(overrides: Partial<SecurityDebtResult> = {}): SecurityDebtResult {
  return {
    score: 50,
    riskLevel: 'HIGH',
    previousScore: 10,
    delta: 40,
    newDebt: 40,
    resolvedDebt: 0,
    severityBreakdown: {
      CRITICAL: 1,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    },
    categoryBreakdown: {
      injection: 0,
      authentication: 0,
      authorization: 0,
      secrets: 0,
      cryptography: 0,
      data_exposure: 0,
      dependency: 0,
      input_validation: 0,
      command_execution: 1,
      configuration: 0,
      business_logic: 0,
      other: 0,
    },
    topContributors: [],
    totalDebtPoints: 35,
    formulaSummary: 'Deterministic debt score',
    ...overrides,
  };
}

describe('GitHub Check Run Formatter', () => {
  it('maps severity strings to valid GitHub Check annotation levels', () => {
    expect(mapSeverityToAnnotationLevel('CRITICAL')).toBe('failure');
    expect(mapSeverityToAnnotationLevel('HIGH')).toBe('failure');
    expect(mapSeverityToAnnotationLevel('MEDIUM')).toBe('warning');
    expect(mapSeverityToAnnotationLevel('LOW')).toBe('notice');
    expect(mapSeverityToAnnotationLevel('INFO')).toBe('notice');
  });

  describe('determineCheckConclusion', () => {
    it('returns failure when a new CRITICAL finding is introduced', () => {
      const delta = createMockDelta([
        {
          finding: createMockFinding({ severity: 'CRITICAL' }),
          status: 'new',
          isIntroducedByPR: true,
          reason: 'New critical',
        },
      ]);
      const debt = createMockDebt({ riskLevel: 'HIGH' });

      const conclusion = determineCheckConclusion(delta, debt);
      expect(conclusion).toBe('failure');
    });

    it('returns failure when debt risk level is CRITICAL', () => {
      const delta = createMockDelta([]);
      const debt = createMockDebt({ score: 85, riskLevel: 'CRITICAL' });

      const conclusion = determineCheckConclusion(delta, debt);
      expect(conclusion).toBe('failure');
    });

    it('returns neutral for HIGH risk when failOnHigh is false (default)', () => {
      const delta = createMockDelta([
        {
          finding: createMockFinding({ severity: 'HIGH' }),
          status: 'new',
          isIntroducedByPR: true,
          reason: 'New high',
        },
      ]);
      const debt = createMockDebt({ riskLevel: 'HIGH' });

      const conclusion = determineCheckConclusion(delta, debt, { failOnHigh: false });
      expect(conclusion).toBe('neutral');
    });

    it('returns failure for HIGH risk when failOnHigh is true', () => {
      const delta = createMockDelta([
        {
          finding: createMockFinding({ severity: 'HIGH' }),
          status: 'new',
          isIntroducedByPR: true,
          reason: 'New high',
        },
      ]);
      const debt = createMockDebt({ riskLevel: 'HIGH' });

      const conclusion = determineCheckConclusion(delta, debt, { failOnHigh: true });
      expect(conclusion).toBe('failure');
    });

    it('returns success when debt risk is LOW and no critical/high issues are introduced', () => {
      const delta = createMockDelta([
        {
          finding: createMockFinding({ severity: 'LOW' }),
          status: 'new',
          isIntroducedByPR: true,
          reason: 'New low',
        },
      ]);
      const debt = createMockDebt({ score: 10, riskLevel: 'LOW' });

      const conclusion = determineCheckConclusion(delta, debt);
      expect(conclusion).toBe('success');
    });
  });

  it('formats full GitHub Check Run payload including annotations and summary', () => {
    const finding = createMockFinding();
    const delta = createMockDelta([
      {
        finding,
        status: 'new',
        isIntroducedByPR: true,
        reason: 'New issue',
      },
    ]);
    const debt = createMockDebt();

    const payload = formatCheckRun(delta, debt, { headSha: 'commit12345' });

    expect(payload.name).toBe('AIShield Security Debt');
    expect(payload.head_sha).toBe('commit12345');
    expect(payload.status).toBe('completed');
    expect(payload.conclusion).toBe('failure');
    expect(payload.output.title).toContain('Security Debt: 50/100 (HIGH)');
    expect(payload.output.summary).toContain('50/100 (HIGH Risk)');
    expect(payload.output.annotations).toHaveLength(1);

    const annotation = payload.output.annotations?.[0];
    expect(annotation).toBeDefined();
    expect(annotation?.path).toBe('src/utils/runner.ts');
    expect(annotation?.start_line).toBe(15);
    expect(annotation?.end_line).toBe(15);
    expect(annotation?.annotation_level).toBe('failure');
    expect(annotation?.title).toContain('[CRITICAL]');
    expect(annotation?.message).toContain('Suggested Remediation:');
  });

  it('limits annotations to the GitHub Checks API maximum of 50', () => {
    const manyFindings: CategorizedFindingDelta[] = [];
    for (let i = 1; i <= 65; i++) {
      manyFindings.push({
        finding: createMockFinding({ id: `f-${i}`, line: i }),
        status: 'new',
        isIntroducedByPR: true,
        reason: 'Batch item',
      });
    }

    const delta = createMockDelta(manyFindings);
    const debt = createMockDebt();

    const payload = formatCheckRun(delta, debt, { headSha: 'sha999' });

    expect(payload.output.annotations).toHaveLength(50);
  });

  describe('Policy Check Reporting (PASS, WARN, FAIL)', () => {
    it('reports PASS when no critical issues exist and debt is within threshold', () => {
      const delta = createMockDelta([], { netDebtChange: 2, newDebt: 2 });
      const debt = createMockDebt({ score: 12, riskLevel: 'LOW' });

      const payload = formatCheckRun(delta, debt, { headSha: 'shaPass' });

      expect(payload.conclusion).toBe('success');
      expect(payload.output.title).toContain('[PASS]');
      expect(payload.output.summary).toContain('Verdict: 🟢 **PASS**');
      expect(payload.output.summary).toContain('PASS: No critical findings and debt change within acceptable threshold.');
    });

    it('reports WARN when medium findings require review', () => {
      const mediumFinding = createMockFinding({ severity: 'MEDIUM' });
      const delta = createMockDelta(
        [{ finding: mediumFinding, status: 'new', isIntroducedByPR: true, reason: 'New' }],
        { netDebtChange: 3, newDebt: 3 },
      );
      const debt = createMockDebt({ score: 18, riskLevel: 'LOW' });

      const payload = formatCheckRun(delta, debt, {
        headSha: 'shaWarn',
        failOnCritical: true,
        failOnHigh: false,
      });

      expect(payload.conclusion).toBe('neutral');
      expect(payload.output.title).toContain('[WARN]');
      expect(payload.output.summary).toContain('Verdict: 🟡 **WARN**');
      expect(payload.output.summary).toContain('MEDIUM severity finding(s) introduced requiring security review');
    });

    it('reports FAIL when critical findings are introduced', () => {
      const criticalFinding = createMockFinding({ severity: 'CRITICAL' });
      const delta = createMockDelta(
        [{ finding: criticalFinding, status: 'new', isIntroducedByPR: true, reason: 'New' }],
        { netDebtChange: 25, newDebt: 25 },
      );
      const debt = createMockDebt({ score: 55, riskLevel: 'HIGH' });

      const payload = formatCheckRun(delta, debt, { headSha: 'shaFail' });

      expect(payload.conclusion).toBe('failure');
      expect(payload.output.title).toContain('[FAIL]');
      expect(payload.output.summary).toContain('Verdict: 🔴 **FAIL**');
      expect(payload.output.summary).toContain('Introduced 1 new CRITICAL finding(s)');
    });
  });
});
