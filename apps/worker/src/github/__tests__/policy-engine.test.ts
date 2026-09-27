import { describe, expect, it } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type {
  CategorizedFindingDelta,
  PRDeltaAnalysisResult,
  SecurityDebtResult,
  UnifiedFinding,
} from '@aishield/shared';
import {
  evaluateSecurityPolicy,
  loadPolicyConfig,
} from '../policy-engine.js';

function createMockFinding(overrides: Partial<UnifiedFinding> = {}): UnifiedFinding {
  return {
    id: 'f-1',
    fingerprint: 'fp-1',
    ruleId: 'test-rule',
    category: 'injection',
    severity: 'MEDIUM',
    title: 'Test finding',
    description: 'Test description',
    confidence: 0.9,
    distinction: 'confirmed_scanner_finding',
    file: 'src/app.ts',
    line: 10,
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
    baseCommit: 'base123',
    headCommit: 'head456',
    baseScore: 10,
    headScore: 15,
    newDebt: 5,
    resolvedDebt: 0,
    netDebtChange: 5,
    findingsIntroduced: introduced,
    findingsResolved: [],
    findingsModified: [],
    findingsUnchanged: [],
    totalHeadFindings: introduced.length,
    totalBaseFindings: 0,
    changedFilesCount: 1,
    summary: 'PR delta summary',
    ...overrides,
  };
}

function createMockDebt(overrides: Partial<SecurityDebtResult> = {}): SecurityDebtResult {
  return {
    score: 15,
    riskLevel: 'LOW',
    previousScore: 10,
    delta: 5,
    newDebt: 5,
    resolvedDebt: 0,
    severityBreakdown: {
      CRITICAL: 0,
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
      command_execution: 0,
      configuration: 0,
      business_logic: 0,
      other: 0,
    },
    topContributors: [],
    totalDebtPoints: 5,
    formulaSummary: 'Deterministic debt formula',
    ...overrides,
  };
}

describe('Security Policy Engine', () => {
  describe('PASS Evaluation', () => {
    it('returns PASS when no critical findings and debt delta is within acceptable threshold', () => {
      const delta = createMockDelta([], { netDebtChange: 2, newDebt: 2 });
      const debt = createMockDebt({ score: 12, riskLevel: 'LOW' });

      const result = evaluateSecurityPolicy(delta, debt);

      expect(result.overallStatus).toBe('PASS');
      expect(result.summary).toContain('PASS');
      expect(result.failReasons).toHaveLength(0);
      expect(result.warnReasons).toHaveLength(0);
    });

    it('returns PASS with custom relaxed thresholds even when a finding is present', () => {
      const criticalFinding = createMockFinding({ severity: 'CRITICAL' });
      const delta = createMockDelta(
        [{ finding: criticalFinding, status: 'new', isIntroducedByPR: true, reason: 'New' }],
        { netDebtChange: 5 },
      );
      const debt = createMockDebt({ score: 20 });

      // Custom policy allowing 1 critical
      const result = evaluateSecurityPolicy(delta, debt, {
        maxAllowedNewFindings: {
          maxCriticalAllowed: 1,
          maxHighAllowed: 1,
        },
        warnOnHigh: false,
        warnDebtDeltaThreshold: 10,
      });

      expect(result.overallStatus).toBe('PASS');
    });
  });

  describe('WARN Evaluation', () => {
    it('returns WARN when new medium findings require review', () => {
      const mediumFinding = createMockFinding({ severity: 'MEDIUM' });
      const delta = createMockDelta(
        [{ finding: mediumFinding, status: 'new', isIntroducedByPR: true, reason: 'New' }],
        { netDebtChange: 3 },
      );
      const debt = createMockDebt({ score: 13, riskLevel: 'LOW' });

      const result = evaluateSecurityPolicy(delta, debt, {
        warnOnMedium: true,
      });

      expect(result.overallStatus).toBe('WARN');
      expect(result.failReasons).toHaveLength(0);
      expect(result.warnReasons.length).toBeGreaterThan(0);
      expect(result.warnReasons[0]).toContain('MEDIUM severity finding(s) introduced requiring security review');
    });

    it('returns WARN when net debt increase exceeds advisory warning threshold', () => {
      const delta = createMockDelta([], { netDebtChange: 8 });
      const debt = createMockDebt({ score: 18, riskLevel: 'MEDIUM' });

      const result = evaluateSecurityPolicy(delta, debt, {
        maxNetDebtChange: 15,
        warnDebtDeltaThreshold: 5,
        warnOnMedium: false,
        warnOnHigh: false,
      });

      expect(result.overallStatus).toBe('WARN');
      expect(result.warnReasons[0]).toContain('exceeds advisory review threshold (+5)');
    });

    it('returns WARN when requireConfirmedScannerForFail is true and AI suggests a critical issue', () => {
      const aiCritical = createMockFinding({
        severity: 'CRITICAL',
        distinction: 'ai_suggested_finding',
      });
      const delta = createMockDelta(
        [{ finding: aiCritical, status: 'new', isIntroducedByPR: true, reason: 'AI suggested' }],
        { netDebtChange: 2 },
      );
      const debt = createMockDebt({ score: 12, riskLevel: 'LOW' });

      const result = evaluateSecurityPolicy(delta, debt, {
        requireConfirmedScannerForFail: true,
        maxAllowedNewFindings: { maxCriticalAllowed: 0, maxHighAllowed: 0 },
      });

      // Does not FAIL because scanner did not confirm; reports WARN for human verification
      expect(result.overallStatus).toBe('WARN');
      expect(result.warnReasons[0]).toContain('AI analyzer identified');
    });
  });

  describe('FAIL Evaluation', () => {
    it('returns FAIL when a critical vulnerability is introduced', () => {
      const criticalFinding = createMockFinding({ severity: 'CRITICAL' });
      const delta = createMockDelta(
        [{ finding: criticalFinding, status: 'new', isIntroducedByPR: true, reason: 'New' }],
        { netDebtChange: 25 },
      );
      const debt = createMockDebt({ score: 35, riskLevel: 'MEDIUM' });

      const result = evaluateSecurityPolicy(delta, debt);

      expect(result.overallStatus).toBe('FAIL');
      expect(result.failReasons.length).toBeGreaterThan(0);
      expect(result.failReasons[0]).toContain('Introduced 1 new CRITICAL finding(s)');
    });

    it('returns FAIL when hardcoded credentials or secrets are introduced', () => {
      const secretFinding = createMockFinding({
        severity: 'HIGH',
        category: 'secrets',
        title: 'Hardcoded Slack Token',
      });
      const delta = createMockDelta(
        [{ finding: secretFinding, status: 'new', isIntroducedByPR: true, reason: 'New' }],
        { netDebtChange: 5 },
      );
      const debt = createMockDebt({ score: 15, riskLevel: 'LOW' });

      const result = evaluateSecurityPolicy(delta, debt, {
        failOnSecrets: true,
      });

      expect(result.overallStatus).toBe('FAIL');
      expect(result.failReasons[0]).toContain('Exposed 1 secret(s) or credential(s)');
    });

    it('returns FAIL when configurable debt threshold is exceeded', () => {
      const delta = createMockDelta([], { netDebtChange: 18 });
      const debt = createMockDebt({ score: 28, riskLevel: 'MEDIUM' });

      const result = evaluateSecurityPolicy(delta, debt, {
        maxNetDebtChange: 10,
      });

      expect(result.overallStatus).toBe('FAIL');
      expect(result.failReasons[0]).toContain('Net debt change (+18) exceeded maximum allowed threshold (+10)');
    });

    it('returns FAIL when absolute head debt score exceeds maximum policy cap', () => {
      const delta = createMockDelta([], { netDebtChange: 2 });
      const debt = createMockDebt({ score: 85, riskLevel: 'CRITICAL' });

      const result = evaluateSecurityPolicy(delta, debt, {
        maxHeadScore: 75,
      });

      expect(result.overallStatus).toBe('FAIL');
      expect(result.failReasons[0]).toContain('Overall security debt score (85/100) exceeded maximum policy cap (75/100)');
    });
  });

  describe('loadPolicyConfig', () => {
    it('returns sensible defaults when no custom configuration is provided', () => {
      const config = loadPolicyConfig();
      expect(config.checkName).toBe('AIShield Security Debt');
      expect(config.maxNetDebtChange).toBeUndefined();
      expect(config.failOnSecrets).toBe(true);
    });

    it('loads policy configuration from a JSON config file', () => {
      const tempDir = mkdtempSync(join(tmpdir(), 'policy-test-'));
      const configPath = join(tempDir, '.aishieldrc.json');

      const customConfig = {
        policyName: 'Production Strict',
        maxAllowedNewFindings: {
          maxCriticalAllowed: 0,
          maxHighAllowed: 0,
        },
        maxNetDebtChange: 5,
        warnDebtDeltaThreshold: 2,
      };

      writeFileSync(configPath, JSON.stringify(customConfig), 'utf-8');

      const loaded = loadPolicyConfig({ configPath, workspaceRoot: tempDir });

      expect(loaded.policyName).toBe('Production Strict');
      expect(loaded.maxNetDebtChange).toBe(5);
      expect(loaded.warnDebtDeltaThreshold).toBe(2);

      rmSync(tempDir, { recursive: true, force: true });
    });
  });
});
