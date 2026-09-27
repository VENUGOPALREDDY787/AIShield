import { describe, expect, it } from 'vitest';
import {
  SecurityDebtScoringEngine,
  calculateSecurityDebtScore,
} from '../debt-scoring-engine.js';
import type { ScoringFindingInput } from '../debt-scoring-engine.js';

describe('Security Debt Scoring Engine', () => {
  const engine = new SecurityDebtScoringEngine();

  describe('1. No findings scenario', () => {
    it('returns score = 0, riskLevel = LOW, and 0 delta with no findings', () => {
      const result = engine.calculateDebt({
        findings: [],
        previousScore: 0,
      });

      expect(result.score).toBe(0);
      expect(result.riskLevel).toBe('LOW');
      expect(result.previousScore).toBe(0);
      expect(result.delta).toBe(0);
      expect(result.newDebt).toBe(0);
      expect(result.resolvedDebt).toBe(0);
      expect(result.totalDebtPoints).toBe(0);
      expect(result.topContributors).toHaveLength(0);
      expect(result.severityBreakdown.CRITICAL).toBe(0);
      expect(result.categoryBreakdown.injection).toBe(0);
    });

    it('documents that 0 debt does not mean absolute security', () => {
      const result = engine.calculateDebt({ findings: [] });
      expect(result.formulaSummary).toContain('not absolute security');
    });
  });

  describe('2. Low findings scenario', () => {
    it('produces a low debt score within the LOW risk band for minor/info issues', () => {
      const lowFindings: ScoringFindingInput[] = [
        {
          file: 'src/components/Header.tsx',
          line: 12,
          ruleId: 'react.deprecated-method',
          severity: 'LOW',
          category: 'configuration',
          confidence: 0.8,
        },
        {
          file: 'src/utils/format.ts',
          line: 45,
          ruleId: 'js.console-log',
          severity: 'INFO',
          category: 'other',
          confidence: 0.9,
        },
      ];

      const result = engine.calculateDebt({ findings: lowFindings });

      expect(result.score).toBeGreaterThan(0);
      expect(result.score).toBeLessThanOrEqual(15);
      expect(result.riskLevel).toBe('LOW');
      expect(result.severityBreakdown.LOW).toBe(1);
      expect(result.severityBreakdown.INFO).toBe(1);
    });
  });

  describe('3. High findings scenario', () => {
    it('calculates significant debt for high-severity findings', () => {
      const highFindings: ScoringFindingInput[] = [
        {
          file: 'src/controllers/user.ts',
          line: 50,
          title: 'Insecure Direct Object Reference (IDOR)',
          ruleId: 'sec.idor-user-profile',
          severity: 'HIGH',
          category: 'authorization',
          confidence: 0.9,
        },
        {
          file: 'src/controllers/payment.ts',
          line: 120,
          title: 'Missing CSRF check on state mutation',
          ruleId: 'sec.csrf-disabled',
          severity: 'HIGH',
          category: 'configuration',
          confidence: 0.95,
        },
      ];

      const result = engine.calculateDebt({ findings: highFindings });

      // Two HIGH findings on controllers (with boundary multiplier 1.3) contribute substantial points
      expect(result.score).toBeGreaterThan(30);
      expect(result.score).toBeLessThanOrEqual(70);
      expect(result.riskLevel).toBe('HIGH');
      expect(result.severityBreakdown.HIGH).toBe(2);
      expect(result.topContributors.length).toBe(2);
    });
  });

  describe('4. Critical findings scenario', () => {
    it('pushes score to high/critical risk for critical vulnerabilities or exposed secrets', () => {
      const criticalFindings: ScoringFindingInput[] = [
        {
          file: 'src/routes/auth.ts',
          line: 25,
          title: 'SQL Injection in Login Endpoint',
          ruleId: 'cwe-89.sql-injection',
          severity: 'CRITICAL',
          category: 'injection',
          confidence: 0.95,
          exploitability: 'HIGH',
        },
        {
          file: 'src/config/aws.ts',
          line: 8,
          title: 'Exposed AWS Production Secret Key',
          ruleId: 'aws-secret-access-key',
          severity: 'CRITICAL',
          category: 'secrets',
          confidence: 1.0,
        },
      ];

      const result = engine.calculateDebt({ findings: criticalFindings });

      expect(result.score).toBeGreaterThan(70);
      expect(result.riskLevel).toBe('CRITICAL');
      expect(result.severityBreakdown.CRITICAL).toBe(2);
      expect(result.topContributors[0]?.severity).toBe('CRITICAL');
    });
  });

  describe('5. Multiple findings and asymptotic saturation', () => {
    it('aggregates multiple findings without exceeding the 100 upper bound', () => {
      const findings: ScoringFindingInput[] = [];

      for (let i = 0; i < 20; i++) {
        findings.push({
          file: `src/services/service_${i}.ts`,
          line: 10 + i,
          title: `Vulnerability ${i}`,
          ruleId: `vuln.rule.${i}`,
          severity: 'HIGH',
          category: 'injection',
          confidence: 0.9,
        });
      }

      const result = engine.calculateDebt({ findings });

      expect(result.score).toBeGreaterThanOrEqual(95);
      expect(result.score).toBeLessThanOrEqual(100);
      expect(result.riskLevel).toBe('CRITICAL');
      expect(result.severityBreakdown.HIGH).toBe(20);
    });

    it('accounts for systemic blast radius across multiple files', () => {
      // 3 findings in 1 file
      const singleFileFindings: ScoringFindingInput[] = [
        { file: 'src/app.ts', line: 10, severity: 'MEDIUM', ruleId: 'r1' },
        { file: 'src/app.ts', line: 20, severity: 'MEDIUM', ruleId: 'r2' },
        { file: 'src/app.ts', line: 30, severity: 'MEDIUM', ruleId: 'r3' },
      ];

      // 3 findings across 3 different files
      const multiFileFindings: ScoringFindingInput[] = [
        { file: 'src/a.ts', line: 10, severity: 'MEDIUM', ruleId: 'r1' },
        { file: 'src/b.ts', line: 10, severity: 'MEDIUM', ruleId: 'r2' },
        { file: 'src/c.ts', line: 10, severity: 'MEDIUM', ruleId: 'r3' },
      ];

      const resSingle = engine.calculateDebt({ findings: singleFileFindings });
      const resMulti = engine.calculateDebt({ findings: multiFileFindings });

      expect(resMulti.totalDebtPoints).toBeGreaterThan(resSingle.totalDebtPoints);
    });
  });

  describe('6. Duplicate findings deduplication', () => {
    it('deduplicates duplicate findings so identical alerts do not inflate debt', () => {
      const findingsWithDuplicates: ScoringFindingInput[] = [
        {
          file: 'src/db.ts',
          line: 42,
          ruleId: 'sql-injection',
          severity: 'CRITICAL',
          category: 'injection',
          snippet: 'db.query(userSql)',
        },
        {
          file: 'src/db.ts',
          line: 42,
          ruleId: 'sql-injection',
          severity: 'CRITICAL',
          category: 'injection',
          snippet: 'db.query(userSql)',
        },
      ];

      const result = engine.calculateDebt({ findings: findingsWithDuplicates });

      // Duplicates deduplicated into 1 finding
      expect(result.severityBreakdown.CRITICAL).toBe(1);
      expect(result.topContributors.length).toBe(1);
    });
  });

  describe('7. Resolved findings scenario', () => {
    it('correctly tracks resolved debt and negative delta when findings are fixed', () => {
      const previousFindings: ScoringFindingInput[] = [
        {
          file: 'src/routes/auth.ts',
          line: 40,
          ruleId: 'cwe-89',
          severity: 'CRITICAL',
          category: 'injection',
          snippet: 'db.query(input)',
        },
        {
          file: 'src/routes/api.ts',
          line: 15,
          ruleId: 'xss',
          severity: 'LOW',
          category: 'injection',
        },
      ];

      // Current scan only has the low XSS issue (the critical SQLi was resolved!)
      const currentFindings: ScoringFindingInput[] = [
        {
          file: 'src/routes/api.ts',
          line: 15,
          ruleId: 'xss',
          severity: 'LOW',
          category: 'injection',
        },
      ];

      const result = engine.calculateDebt({
        findings: currentFindings,
        previousFindings,
      });

      expect(result.resolvedDebt).toBeGreaterThan(0);
      expect(result.delta).toBeLessThan(0); // Score decreased!
      expect(result.score).toBeLessThan(result.previousScore);
    });
  });

  describe('8. PR introducing new debt scenario', () => {
    it('measures newDebt and positive delta when PR introduces new vulnerabilities', () => {
      const baselineFindings: ScoringFindingInput[] = [
        {
          file: 'src/existing.ts',
          line: 10,
          ruleId: 'low-risk',
          severity: 'LOW',
        },
      ];

      // PR adds a new critical finding in PR changed files
      const prFindings: ScoringFindingInput[] = [
        {
          file: 'src/existing.ts',
          line: 10,
          ruleId: 'low-risk',
          severity: 'LOW',
        },
        {
          file: 'src/routes/orders.ts',
          line: 33,
          ruleId: 'idor-bypass',
          severity: 'HIGH',
          category: 'authorization',
          isNewInPR: true,
        },
      ];

      const result = engine.calculateDebt({
        findings: prFindings,
        previousFindings: baselineFindings,
        prChangedFiles: ['src/routes/orders.ts'],
      });

      expect(result.newDebt).toBeGreaterThan(0);
      expect(result.delta).toBeGreaterThan(0); // Debt increased
      expect(result.score).toBeGreaterThan(result.previousScore);
      expect(result.topContributors[0]?.file).toBe('src/routes/orders.ts');
    });
  });

  describe('9. PR reducing existing debt scenario', () => {
    it('reports negative delta and positive resolvedDebt when PR fixes more than it adds', () => {
      const baselineFindings: ScoringFindingInput[] = [
        {
          file: 'src/legacy/db.ts',
          line: 100,
          ruleId: 'raw-eval',
          severity: 'CRITICAL',
          category: 'injection',
          snippet: 'eval(userInput)',
        },
      ];

      // PR removes the critical eval and adds only a minor info finding
      const prFindings: ScoringFindingInput[] = [
        {
          file: 'src/legacy/db.ts',
          line: 100,
          ruleId: 'info-log',
          severity: 'INFO',
          category: 'other',
          isNewInPR: true,
        },
      ];

      const result = engine.calculateDebt({
        findings: prFindings,
        previousFindings: baselineFindings,
        prChangedFiles: ['src/legacy/db.ts'],
      });

      expect(result.resolvedDebt).toBeGreaterThan(0);
      expect(result.delta).toBeLessThan(0); // Debt reduced
      expect(result.score).toBeLessThan(result.previousScore);
    });
  });

  describe('10. AI findings scoring with confidence and evidence', () => {
    it('scores AI findings objectively using confidence and evidence', () => {
      const aiFinding: ScoringFindingInput = {
        file: 'src/routes/billing.ts',
        line: 60,
        title: 'Missing Authorization on Subscription Downgrade',
        ruleId: 'ai-contextual-authz-downgrade',
        category: 'authorization',
        severity: 'HIGH',
        confidence: 0.9,
        remediation: 'Verify user is billing admin',
        metadata: {
          reasoningSummary: 'No session role check before downgrade mutation',
        },
      };

      const result = engine.calculateDebt({ findings: [aiFinding] });

      expect(result.score).toBeGreaterThan(0);
      expect(result.severityBreakdown.HIGH).toBe(1);
      expect(result.categoryBreakdown.authorization).toBe(1);
      expect(result.topContributors[0]?.reason).toContain('HIGH severity');
      expect(result.topContributors[0]?.reason).toContain('90% confidence');
    });

    it('corroborated AI + deterministic findings reflect higher confidence and points', () => {
      const singleFinder: ScoringFindingInput = {
        file: 'src/routes/billing.ts',
        line: 60,
        severity: 'HIGH',
        confidence: 0.8,
      };

      const corroboratedFinder: ScoringFindingInput = {
        file: 'src/routes/billing.ts',
        line: 60,
        severity: 'HIGH',
        confidence: 0.98, // Corroborated!
      };

      const resSingle = engine.calculateDebt({ findings: [singleFinder] });
      const resCorroborated = engine.calculateDebt({ findings: [corroboratedFinder] });

      expect(resCorroborated.totalDebtPoints).toBeGreaterThan(resSingle.totalDebtPoints);
    });
  });

  describe('11. Determinism and Reproducibility', () => {
    it('produces identical scores when executed multiple times with identical inputs', () => {
      const inputFindings: ScoringFindingInput[] = [
        { file: 'src/a.ts', line: 10, severity: 'HIGH', category: 'injection' },
        { file: 'src/b.ts', line: 20, severity: 'MEDIUM', category: 'secrets' },
        { file: 'src/c.ts', line: 30, severity: 'LOW', category: 'configuration' },
      ];

      const res1 = calculateSecurityDebtScore({ findings: inputFindings, previousScore: 10 });
      const res2 = calculateSecurityDebtScore({ findings: inputFindings, previousScore: 10 });

      expect(res1.score).toBe(res2.score);
      expect(res1.delta).toBe(res2.delta);
      expect(res1.totalDebtPoints).toBe(res2.totalDebtPoints);
      expect(res1.riskLevel).toBe(res2.riskLevel);
      expect(res1.topContributors).toEqual(res2.topContributors);
    });
  });
});
