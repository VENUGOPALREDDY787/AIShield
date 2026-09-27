import { describe, expect, it } from 'vitest';
import type {
  CategorizedFindingDelta,
  PRDeltaAnalysisResult,
  SecurityDebtResult,
  UnifiedFinding,
} from '@aishield/shared';
import {
  AISHIELD_COMMENT_MARKER,
  formatPRComment,
} from '../comment-formatter.js';

function createMockFinding(overrides: Partial<UnifiedFinding> = {}): UnifiedFinding {
  return {
    id: 'f-1',
    fingerprint: 'fp-1',
    ruleId: 'sql-injection',
    title: 'SQL Injection in user search query',
    description: 'Dynamic user query passed directly to database without parameterization',
    severity: 'HIGH',
    category: 'injection',
    confidence: 0.95,
    file: 'src/controllers/user.controller.ts',
    line: 45,
    cwe: 'CWE-89',
    remediation: 'Use parameterized queries or ORM abstraction',
    distinction: 'confirmed_scanner_finding',
    contributingSources: ['semgrep'],
    sources: [],
    metadata: {},
    ...overrides,
  };
}

function createMockDeltaResult(
  overrides: Partial<PRDeltaAnalysisResult> = {},
): PRDeltaAnalysisResult {
  return {
    baseCommit: 'base1234567890',
    headCommit: 'head1234567890',
    baseScore: 20,
    headScore: 35,
    newDebt: 15,
    resolvedDebt: 0,
    netDebtChange: 15,
    findingsIntroduced: [],
    findingsResolved: [],
    findingsModified: [],
    findingsUnchanged: [],
    totalHeadFindings: 2,
    totalBaseFindings: 1,
    changedFilesCount: 2,
    summary: 'PR introduced 1 new finding (+15 debt).',
    ...overrides,
  };
}

function createMockDebtResult(
  overrides: Partial<SecurityDebtResult> = {},
): SecurityDebtResult {
  return {
    score: 35,
    riskLevel: 'MEDIUM',
    previousScore: 20,
    delta: 15,
    newDebt: 15,
    resolvedDebt: 0,
    severityBreakdown: {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 1,
      LOW: 0,
      INFO: 0,
    },
    categoryBreakdown: {
      injection: 1,
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
      other: 1,
    },
    topContributors: [
      {
        id: 'f-1',
        fingerprint: 'fp-1',
        title: 'SQL Injection in user search query',
        file: 'src/controllers/user.controller.ts',
        line: 45,
        severity: 'HIGH',
        category: 'injection',
        confidence: 0.95,
        debtPoints: 18.5,
        reason: 'Unsanitized user input concatenated to SQL statement',
      },
    ],
    totalDebtPoints: 24,
    formulaSummary: 'Deterministic saturated debt score',
    ...overrides,
  };
}

describe('GitHub PR Comment Formatter', () => {
  it('includes the hidden anchor marker for sticky comment updates', () => {
    const delta = createMockDeltaResult();
    const debt = createMockDebtResult();
    const comment = formatPRComment(delta, debt);

    expect(comment).toContain(AISHIELD_COMMENT_MARKER);
    expect(comment.startsWith(AISHIELD_COMMENT_MARKER)).toBe(true);
  });

  it('contains all required report fields exactly as specified', () => {
    const delta = createMockDeltaResult();
    const debt = createMockDebtResult();
    const comment = formatPRComment(delta, debt, {
      dashboardUrl: 'https://aishield.dev/scans/scan-99',
    });

    expect(comment).toContain('AIShield Security Report');
    expect(comment).toContain('Overall Security Debt:');
    expect(comment).toContain('35/100');
    expect(comment).toContain('Previous:');
    expect(comment).toContain('20/100');
    expect(comment).toContain('Change:');
    expect(comment).toContain('+15');
    expect(comment).toContain('Risk:');
    expect(comment).toContain('MEDIUM');
    expect(comment).toContain('New Findings:');
    expect(comment).toContain('Resolved Findings:');
    expect(comment).toContain('Top Security Risks:');
    expect(comment).toContain('Suggested Actions:');
    expect(comment).toContain('Link to full dashboard');
    expect(comment).toContain('https://aishield.dev/scans/scan-99');
  });

  it('renders a clear notice when no new findings are introduced', () => {
    const delta = createMockDeltaResult({
      newDebt: 0,
      netDebtChange: 0,
      findingsIntroduced: [],
    });
    const debt = createMockDebtResult({ score: 20, delta: 0, newDebt: 0 });
    const comment = formatPRComment(delta, debt);

    expect(comment).toContain('New Findings:');
    expect(comment).toContain('✅ No new security findings introduced in this pull request.');
  });

  it('renders introduced findings with location, rule ID, CWE, and category', () => {
    const introducedItem: CategorizedFindingDelta = {
      finding: createMockFinding(),
      status: 'new',
      isIntroducedByPR: true,
      reason: 'Introduced on line 45 within PR hunk',
    };

    const delta = createMockDeltaResult({
      findingsIntroduced: [introducedItem],
    });
    const debt = createMockDebtResult();
    const comment = formatPRComment(delta, debt);

    expect(comment).toContain('New Findings:');
    expect(comment).toContain('SQL Injection in user search query');
    expect(comment).toContain('src/controllers/user.controller.ts:45');
    expect(comment).toContain('`sql-injection`');
    expect(comment).toContain('CWE-89');
    expect(comment).toContain('`injection`');
  });

  it('renders resolved findings with strikethrough and resolved tag', () => {
    const resolvedItem: CategorizedFindingDelta = {
      finding: createMockFinding({
        id: 'f-old',
        title: 'Hardcoded API Key',
        file: 'config/keys.ts',
        line: 10,
        severity: 'CRITICAL',
      }),
      status: 'resolved',
      isIntroducedByPR: false,
      reason: 'Vulnerability was eliminated in this PR',
    };

    const delta = createMockDeltaResult({
      findingsResolved: [resolvedItem],
    });
    const debt = createMockDebtResult();
    const comment = formatPRComment(delta, debt);

    expect(comment).toContain('Resolved Findings:');
    expect(comment).toContain('~~[CRITICAL] **Hardcoded API Key**~~ in `config/keys.ts:10` *(Resolved)*');
  });

  it('redacts sensitive secrets from finding titles, descriptions, and files in comments', () => {
    const rawSecret = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456';
    const findingWithSecret = createMockFinding({
      title: `Secret exposed: ${rawSecret}`,
      description: `Found token ${rawSecret} in auth header`,
      file: `src/secrets/${rawSecret}.ts`,
      category: 'secrets',
      severity: 'CRITICAL',
    });

    const delta = createMockDeltaResult({
      findingsIntroduced: [
        {
          finding: findingWithSecret,
          status: 'new',
          isIntroducedByPR: true,
          reason: 'Hardcoded secret added',
        },
      ],
    });
    const debt = createMockDebtResult();
    const comment = formatPRComment(delta, debt);

    // Verify raw secret does NOT exist in comment
    expect(comment).not.toContain(rawSecret);
    expect(comment).toContain('[REDACTED]');
  });

  it('generates context-aware suggested actions for secrets, injection, and dependencies', () => {
    const secretFinding = createMockFinding({
      category: 'secrets',
      severity: 'CRITICAL',
      title: 'Exposed Private Key',
    });
    const injectionFinding = createMockFinding({
      category: 'injection',
      severity: 'HIGH',
      title: 'SQL Injection',
    });

    const delta = createMockDeltaResult({
      newDebt: 25,
      findingsIntroduced: [
        { finding: secretFinding, status: 'new', isIntroducedByPR: true, reason: 'New' },
        { finding: injectionFinding, status: 'new', isIntroducedByPR: true, reason: 'New' },
      ],
    });
    const debt = createMockDebtResult({ riskLevel: 'HIGH' });
    const comment = formatPRComment(delta, debt);

    expect(comment).toContain('Rotate Exposed Credentials');
    expect(comment).toContain('Parameterize Dynamic Inputs');
    expect(comment).toContain('Remediate New Debt');
    expect(comment).toContain('Security Review Required');
  });

  it('explicitly states that AIShield never automatically merges PRs', () => {
    const delta = createMockDeltaResult();
    const debt = createMockDebtResult();
    const comment = formatPRComment(delta, debt);

    expect(comment).toContain('AIShield never automatically merges or approves pull requests');
  });

  it('collapses findings into a details accordion when count exceeds display limit', () => {
    const findings: CategorizedFindingDelta[] = [];
    for (let i = 1; i <= 6; i++) {
      findings.push({
        finding: createMockFinding({ id: `f-${i}`, title: `Issue #${i}`, line: i * 10 }),
        status: 'new',
        isIntroducedByPR: true,
        reason: 'New issue',
      });
    }

    const delta = createMockDeltaResult({ findingsIntroduced: findings });
    const debt = createMockDebtResult();
    const comment = formatPRComment(delta, debt, { maxNewFindingsToDisplay: 3 });

    expect(comment).toContain('<details><summary>... and 3 more new finding(s)</summary>');
    expect(comment).toContain('Issue #1');
    expect(comment).toContain('Issue #6');
  });

  describe('Security Check Status (PASS / WARN / FAIL)', () => {
    it('displays 🟢 PASS when no critical issues exist and debt is within threshold', () => {
      const delta = createMockDeltaResult({ netDebtChange: 0, newDebt: 0 });
      const debt = createMockDebtResult({ score: 10, riskLevel: 'LOW' });
      const comment = formatPRComment(delta, debt);

      expect(comment).toContain('### Security Check:');
      expect(comment).toContain('🟢 **PASS**');
      expect(comment).toContain('PASS: No critical findings and debt change within acceptable threshold.');
    });

    it('displays 🟡 WARN when medium findings require review', () => {
      const mediumFinding = createMockFinding({ severity: 'MEDIUM' });
      const delta = createMockDeltaResult({
        findingsIntroduced: [
          { finding: mediumFinding, status: 'new', isIntroducedByPR: true, reason: 'New' },
        ],
        netDebtChange: 2,
        newDebt: 2,
      });
      const debt = createMockDebtResult({ score: 12, riskLevel: 'LOW' });
      const comment = formatPRComment(delta, debt);

      expect(comment).toContain('### Security Check:');
      expect(comment).toContain('🟡 **WARN**');
      expect(comment).toContain('MEDIUM severity finding(s) introduced requiring security review');
    });

    it('displays 🔴 FAIL when critical vulnerability is introduced', () => {
      const criticalFinding = createMockFinding({ severity: 'CRITICAL' });
      const delta = createMockDeltaResult({
        findingsIntroduced: [
          { finding: criticalFinding, status: 'new', isIntroducedByPR: true, reason: 'New' },
        ],
        netDebtChange: 20,
        newDebt: 20,
      });
      const debt = createMockDebtResult({ score: 45, riskLevel: 'HIGH' });
      const comment = formatPRComment(delta, debt);

      expect(comment).toContain('### Security Check:');
      expect(comment).toContain('🔴 **FAIL**');
      expect(comment).toContain('Policy Breaches:');
      expect(comment).toContain('Introduced 1 new CRITICAL finding(s)');
    });
  });
});
