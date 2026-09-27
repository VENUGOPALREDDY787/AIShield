import { describe, expect, it } from 'vitest';
import type { NormalizedCategory, NormalizedSeverity, SecurityDebtResult } from '@aishield/shared';
import {
  SecurityDebtExplanationService,
  explainSecurityDebt,
} from '../debt-explanation-service.js';
import { SecurityDebtScoringEngine } from '../debt-scoring-engine.js';

describe('SecurityDebtExplanationService', () => {
  const service = new SecurityDebtExplanationService();

  const mockDebtResult: SecurityDebtResult = {
    score: 54,
    previousScore: 31,
    delta: 23,
    riskLevel: 'HIGH',
    newDebt: 23,
    resolvedDebt: 0,
    totalDebtPoints: 38.5,
    formulaSummary: 'Exponential saturation curve',
    severityBreakdown: {
      CRITICAL: 1,
      HIGH: 1,
      MEDIUM: 1,
      LOW: 0,
      INFO: 0,
    },
    categoryBreakdown: {
      authorization: 1,
      secrets: 1,
      dependency: 1,
      injection: 0,
      authentication: 0,
      cryptography: 0,
      data_exposure: 0,
      input_validation: 0,
      command_execution: 0,
      configuration: 0,
      business_logic: 0,
      other: 0,
    },
    topContributors: [
      {
        id: 'c-1',
        fingerprint: 'fp-auth-01',
        title: 'Missing Tenant Boundary Check in Export',
        file: 'src/controllers/export.ts',
        line: 112,
        severity: 'HIGH',
        category: 'authorization',
        confidence: 0.95,
        debtPoints: 18.2,
        reason: 'HIGH severity, 95% confidence, public/core boundary',
      },
      {
        id: 'c-2',
        fingerprint: 'fp-secret-02',
        title: 'Exposed GitHub Personal Access Token',
        file: 'tests/fixtures/ci-config.json',
        line: 18,
        severity: 'CRITICAL',
        category: 'secrets',
        confidence: 1.0,
        debtPoints: 14.5,
        reason: 'CRITICAL severity, 100% confidence, sensitive data exposed',
      },
      {
        id: 'c-3',
        fingerprint: 'fp-dep-03',
        title: 'Vulnerable express package < 4.21.2',
        file: 'package.json',
        line: 34,
        severity: 'MEDIUM',
        category: 'dependency',
        confidence: 1.0,
        debtPoints: 5.8,
        reason: 'MEDIUM severity, 100% confidence, high exploitability',
      },
    ],
  };

  it('generates concise deterministic explanation matching the user specification example', () => {
    const explanation = service.generateExplanation({
      debtResult: mockDebtResult,
    });

    expect(explanation.summary).toBe('Security Debt increased from 31 to 54.');
    expect(explanation.deltaStatement).toBe('Security Debt increased from 31 to 54 (+23 pts).');
    expect(explanation.riskStatement).toBe('Risk Level: HIGH');

    // Verify main contributors
    expect(explanation.mainContributors).toHaveLength(3);
    const [c1, c2, c3] = explanation.mainContributors;
    expect(c1).toBeDefined();
    expect(c2).toBeDefined();
    expect(c3).toBeDefined();

    expect(c1?.rank).toBe(1);
    expect(c1?.severity).toBe('HIGH');
    expect(c1?.category).toBe('authorization');
    expect(c1?.description).toContain('HIGH authorization finding');
    expect(c1?.description).toContain('Missing Tenant Boundary Check in Export');
    expect(c1?.description).toContain('src/controllers/export.ts:112');

    expect(c2?.rank).toBe(2);
    expect(c2?.severity).toBe('CRITICAL');
    expect(c2?.category).toBe('secrets');
    expect(c2?.description).toContain('CRITICAL secret exposure');
    expect(c2?.description).toContain('Exposed GitHub Personal Access Token');

    expect(c3?.rank).toBe(3);
    expect(c3?.severity).toBe('MEDIUM');
    expect(c3?.category).toBe('dependency');
    expect(c3?.description).toContain('MEDIUM dependency vulnerability');

    // Text explanation check
    expect(explanation.textExplanation).toContain('Security Debt increased from 31 to 54.');
    expect(explanation.textExplanation).toContain('Main contributors:');
    expect(explanation.textExplanation).toContain('1. HIGH authorization finding: Missing Tenant Boundary Check in Export (src/controllers/export.ts:112)');
    expect(explanation.textExplanation).toContain('2. CRITICAL secret exposure: Exposed GitHub Personal Access Token (tests/fixtures/ci-config.json:18)');
    expect(explanation.textExplanation).toContain('3. MEDIUM dependency vulnerability: Vulnerable express package < 4.21.2 (package.json:34)');
  });

  it('generates accurate explanation for decreased debt', () => {
    const decreasedDebtResult: SecurityDebtResult = {
      ...mockDebtResult,
      score: 30,
      previousScore: 45,
      delta: -15,
      riskLevel: 'MEDIUM',
      newDebt: 0,
      resolvedDebt: 15,
      topContributors: [
        {
          id: 'c-3',
          fingerprint: 'fp-dep-03',
          title: 'Vulnerable express package < 4.21.2',
          file: 'package.json',
          line: 34,
          severity: 'MEDIUM',
          category: 'dependency',
          confidence: 1.0,
          debtPoints: 5.8,
          reason: 'MEDIUM severity',
        },
      ],
    };

    const explanation = service.generateExplanation({
      debtResult: decreasedDebtResult,
    });

    expect(explanation.summary).toBe('Security Debt decreased from 45 to 30.');
    expect(explanation.deltaStatement).toBe('Security Debt decreased from 45 to 30 (-15 pts).');
    expect(explanation.resolvedDebtExplanation).toBe('Resolved 15 pts of existing security debt.');
  });

  it('generates accurate explanation for unchanged debt and zero baseline', () => {
    const zeroDebtResult: SecurityDebtResult = {
      ...mockDebtResult,
      score: 0,
      previousScore: 0,
      delta: 0,
      riskLevel: 'LOW',
      newDebt: 0,
      resolvedDebt: 0,
      topContributors: [],
    };

    const explanation = service.generateExplanation({
      debtResult: zeroDebtResult,
    });

    expect(explanation.summary).toContain('Security Debt score is 0/100 (Clean)');
    expect(explanation.mainContributors).toHaveLength(0);
  });

  it('strictly validates AI explanation against verified findings to prevent hallucinations', () => {
    const verifiedFindings = [
      {
        fingerprint: 'fp-auth-01',
        title: 'Missing Tenant Boundary Check in Export',
        file: 'src/controllers/export.ts',
        line: 112,
        severity: 'HIGH' as NormalizedSeverity,
        category: 'authorization' as NormalizedCategory,
      },
      {
        fingerprint: 'fp-secret-02',
        title: 'Exposed GitHub Personal Access Token',
        file: 'tests/fixtures/ci-config.json',
        line: 18,
        severity: 'CRITICAL' as NormalizedSeverity,
        category: 'secrets' as NormalizedCategory,
      },
    ];

    // Case 1: AI mentions only real verified findings
    const validAiMention = [
      'Missing Tenant Boundary Check in Export',
      'Exposed GitHub Personal Access Token',
    ];
    const validationResult1 = service.validateAiExplanationAgainstFindings(
      validAiMention,
      verifiedFindings,
    );
    expect(validationResult1.isValid).toBe(true);
    expect(validationResult1.unverifiedHallucinations).toHaveLength(0);
    expect(validationResult1.verifiedMatches).toHaveLength(2);

    // Case 2: AI invents a vulnerability that does not exist in scanner findings
    const hallucinatedAiMention = [
      'Missing Tenant Boundary Check in Export',
      'Invented Remote Code Execution in auth.ts (CVE-2099-99999)', // Hallucinated
      'Fake Memory Leak in logger.ts', // Hallucinated
    ];
    const validationResult2 = service.validateAiExplanationAgainstFindings(
      hallucinatedAiMention,
      verifiedFindings,
    );
    expect(validationResult2.isValid).toBe(false);
    expect(validationResult2.unverifiedHallucinations).toHaveLength(2);
    expect(validationResult2.unverifiedHallucinations).toContain(
      'Invented Remote Code Execution in auth.ts (CVE-2099-99999)',
    );
    expect(validationResult2.unverifiedHallucinations).toContain(
      'Fake Memory Leak in logger.ts',
    );
  });

  it('prepares safe, redacted prompt payloads for AI synthesizer', () => {
    const verifiedFindings = [
      {
        fingerprint: 'fp-secret-01',
        title: 'Secret leak: ghp_1234567890abcdefghijklmnopqrstuvwxyz',
        file: 'tests/keys.env',
        line: 5,
        severity: 'CRITICAL' as NormalizedSeverity,
        category: 'secrets' as NormalizedCategory,
      },
    ];

    const payload = service.prepareAiPromptPayload(mockDebtResult, verifiedFindings);
    expect(payload.score).toBe(54);
    expect(payload.verifiedFindings).toHaveLength(1);
    const firstFinding = payload.verifiedFindings[0];
    expect(firstFinding).toBeDefined();
    expect(firstFinding?.title).not.toContain('ghp_1234567890abcdefghijklmnopqrstuvwxyz');
    expect(firstFinding?.title).toContain('[REDACTED]');
  });

  it('integrates seamlessly with SecurityDebtScoringEngine.calculateDebt()', () => {
    const engine = new SecurityDebtScoringEngine();
    const result = engine.calculateDebt({
      previousScore: 31,
      findings: [
        {
          fingerprint: 'fp-1',
          title: 'Missing Authorization Check',
          file: 'src/api/admin.ts',
          line: 42,
          severity: 'HIGH',
          category: 'authorization',
          confidence: 0.9,
        },
        {
          fingerprint: 'fp-2',
          title: 'Hardcoded API Key',
          file: 'src/config/keys.ts',
          line: 12,
          severity: 'CRITICAL',
          category: 'secrets',
          confidence: 1.0,
        },
      ],
    });

    expect(result.explanation).toBeDefined();
    expect(result.explanation?.summary).toContain('Security Debt');
    expect(result.explanation?.mainContributors.length).toBeGreaterThan(0);
    const firstContrib = result.explanation?.mainContributors[0];
    expect(firstContrib).toBeDefined();
    expect(firstContrib?.severity).toBeDefined();
    expect(result.explanation?.textExplanation).toContain('Main contributors:');
  });

  it('functional helper explainSecurityDebt works as expected', () => {
    const explanation = explainSecurityDebt({ debtResult: mockDebtResult });
    expect(explanation.summary).toBe('Security Debt increased from 31 to 54.');
  });
});
