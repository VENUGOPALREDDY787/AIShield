import { describe, expect, it } from 'vitest';
import type { FindingInput } from '../finding-normalizer-engine.js';
import {
  FindingNormalizerEngine,
  defaultFindingNormalizerEngine,
} from '../finding-normalizer-engine.js';
import {
  generateStableFingerprint,
  areFindingsCorrelated,
} from '../fingerprint.js';
import {
  combineConfidence,
  normalizeCategory,
  normalizeConfidence,
  normalizeSeverity,
} from '../normalizer.js';

describe('Finding Normalization and Deduplication Engine', () => {
  describe('1. Severity Normalization', () => {
    it('normalizes string severity levels to canonical uppercase values', () => {
      expect(normalizeSeverity('critical')).toBe('CRITICAL');
      expect(normalizeSeverity('CRITICAL')).toBe('CRITICAL');
      expect(normalizeSeverity('high')).toBe('HIGH');
      expect(normalizeSeverity('HIGH')).toBe('HIGH');
      expect(normalizeSeverity('medium')).toBe('MEDIUM');
      expect(normalizeSeverity('moderate')).toBe('MEDIUM');
      expect(normalizeSeverity('low')).toBe('LOW');
      expect(normalizeSeverity('info')).toBe('INFO');
      expect(normalizeSeverity('informational')).toBe('INFO');
    });

    it('normalizes severity aliases and common scanner equivalents', () => {
      expect(normalizeSeverity('blocker')).toBe('CRITICAL');
      expect(normalizeSeverity('fatal')).toBe('CRITICAL');
      expect(normalizeSeverity('p0')).toBe('CRITICAL');
      expect(normalizeSeverity('error')).toBe('HIGH');
      expect(normalizeSeverity('major')).toBe('HIGH');
      expect(normalizeSeverity('p1')).toBe('HIGH');
      expect(normalizeSeverity('warning')).toBe('MEDIUM');
      expect(normalizeSeverity('warn')).toBe('MEDIUM');
      expect(normalizeSeverity('p2')).toBe('MEDIUM');
      expect(normalizeSeverity('minor')).toBe('LOW');
      expect(normalizeSeverity('notice')).toBe('LOW');
      expect(normalizeSeverity('p3')).toBe('LOW');
      expect(normalizeSeverity('note')).toBe('INFO');
      expect(normalizeSeverity('experiment')).toBe('INFO');
    });

    it('normalizes numeric CVSS scores to corresponding severities', () => {
      expect(normalizeSeverity(9.8)).toBe('CRITICAL');
      expect(normalizeSeverity(9.0)).toBe('CRITICAL');
      expect(normalizeSeverity(8.5)).toBe('HIGH');
      expect(normalizeSeverity(7.0)).toBe('HIGH');
      expect(normalizeSeverity(6.1)).toBe('MEDIUM');
      expect(normalizeSeverity(4.0)).toBe('MEDIUM');
      expect(normalizeSeverity(3.2)).toBe('LOW');
      expect(normalizeSeverity(0.5)).toBe('LOW');
      expect(normalizeSeverity(0.0)).toBe('INFO');
    });

    it('uses fallback when severity is null, undefined, or unrecognized', () => {
      expect(normalizeSeverity(null)).toBe('MEDIUM');
      expect(normalizeSeverity(undefined, 'LOW')).toBe('LOW');
      expect(normalizeSeverity('unrecognized-token', 'INFO')).toBe('INFO');
    });
  });

  describe('2. Category Normalization (All 12 Categories)', () => {
    it('normalizes injection findings via category, CWE, or rule keywords', () => {
      expect(normalizeCategory({ category: 'injection' })).toBe('injection');
      expect(normalizeCategory({ cwe: 'CWE-89' })).toBe('injection'); // SQLi
      expect(normalizeCategory({ cwe: 'CWE-79' })).toBe('injection'); // XSS
      expect(normalizeCategory({ ruleId: 'rules.security.sql-injection' })).toBe('injection');
      expect(normalizeCategory({ title: 'Template Injection in Handlebars' })).toBe('injection');
    });

    it('normalizes command execution findings', () => {
      expect(normalizeCategory({ category: 'command_execution' })).toBe('command_execution');
      expect(normalizeCategory({ cwe: 'CWE-78' })).toBe('command_execution');
      expect(normalizeCategory({ ruleId: 'node.child_process.exec-injection' })).toBe('command_execution');
      expect(normalizeCategory({ title: 'Unsafe shell command execution via popen' })).toBe('command_execution');
    });

    it('normalizes authentication findings', () => {
      expect(normalizeCategory({ category: 'authentication' })).toBe('authentication');
      expect(normalizeCategory({ cwe: 'CWE-287' })).toBe('authentication');
      expect(normalizeCategory({ cwe: 'CWE-384' })).toBe('authentication');
      expect(normalizeCategory({ title: 'JWT token signature not verified' })).toBe('authentication');
    });

    it('normalizes authorization findings', () => {
      expect(normalizeCategory({ category: 'authorization' })).toBe('authorization');
      expect(normalizeCategory({ cwe: 'CWE-862' })).toBe('authorization');
      expect(normalizeCategory({ cwe: 'CWE-639' })).toBe('authorization'); // IDOR
      expect(normalizeCategory({ title: 'Missing Insecure Direct Object Reference check' })).toBe('authorization');
      expect(normalizeCategory({ description: 'Horizontal privilege escalation allowed' })).toBe('authorization');
    });

    it('normalizes secrets findings from Gitleaks and secret rules', () => {
      expect(normalizeCategory({ source: 'gitleaks' })).toBe('secrets');
      expect(normalizeCategory({ cwe: 'CWE-798' })).toBe('secrets');
      expect(normalizeCategory({ ruleId: 'aws-access-key-id' })).toBe('secrets');
      expect(normalizeCategory({ title: 'Hardcoded Stripe API Token' })).toBe('secrets');
    });

    it('normalizes cryptography findings', () => {
      expect(normalizeCategory({ category: 'cryptography' })).toBe('cryptography');
      expect(normalizeCategory({ cwe: 'CWE-327' })).toBe('cryptography');
      expect(normalizeCategory({ cwe: 'CWE-328' })).toBe('cryptography'); // MD5/SHA1
      expect(normalizeCategory({ title: 'Use of broken MD5 cryptographic hash' })).toBe('cryptography');
    });

    it('normalizes data exposure findings', () => {
      expect(normalizeCategory({ category: 'data_exposure' })).toBe('data_exposure');
      expect(normalizeCategory({ cwe: 'CWE-200' })).toBe('data_exposure');
      expect(normalizeCategory({ cwe: 'CWE-209' })).toBe('data_exposure');
      expect(normalizeCategory({ title: 'Information disclosure via debug stack trace' })).toBe('data_exposure');
    });

    it('normalizes dependency findings from package scanners and CVE/GHSA', () => {
      expect(normalizeCategory({ source: 'dependency' })).toBe('dependency');
      expect(normalizeCategory({ source: 'osv' })).toBe('dependency');
      expect(normalizeCategory({ cwe: 'CWE-1395' })).toBe('dependency');
      expect(normalizeCategory({ ruleId: 'CVE-2024-21538' })).toBe('dependency');
      expect(normalizeCategory({ title: 'Vulnerable package lodash < 4.17.21' })).toBe('dependency');
    });

    it('normalizes input validation findings', () => {
      expect(normalizeCategory({ category: 'input_validation' })).toBe('input_validation');
      expect(normalizeCategory({ cwe: 'CWE-22' })).toBe('input_validation'); // Path traversal
      expect(normalizeCategory({ cwe: 'CWE-20' })).toBe('input_validation');
      expect(normalizeCategory({ title: 'Path traversal via filename parameter' })).toBe('input_validation');
    });

    it('normalizes configuration findings', () => {
      expect(normalizeCategory({ category: 'configuration' })).toBe('configuration');
      expect(normalizeCategory({ cwe: 'CWE-16' })).toBe('configuration');
      expect(normalizeCategory({ cwe: 'CWE-942' })).toBe('configuration'); // CORS
      expect(normalizeCategory({ title: 'Permissive CORS policy wildcard' })).toBe('configuration');
    });

    it('normalizes business logic findings', () => {
      expect(normalizeCategory({ category: 'business_logic' })).toBe('business_logic');
      expect(normalizeCategory({ cwe: 'CWE-840' })).toBe('business_logic');
      expect(normalizeCategory({ cwe: 'CWE-362' })).toBe('business_logic'); // Race condition
      expect(normalizeCategory({ title: 'Price tampering in checkout payment flow' })).toBe('business_logic');
    });

    it('falls back to other when no category pattern matches', () => {
      expect(normalizeCategory({ title: 'Miscellaneous non-security code smell' })).toBe('other');
    });
  });

  describe('3. Stable Fingerprint Generation', () => {
    it('produces identical fingerprints for identical code findings across runs', () => {
      const fp1 = generateStableFingerprint({
        source: 'semgrep',
        file: 'src/routes/users.ts',
        ruleId: 'sql-injection',
        line: 42,
        snippet: 'db.query("SELECT * FROM users WHERE id = " + id);',
      });
      const fp2 = generateStableFingerprint({
        source: 'semgrep',
        file: 'src/routes/users.ts',
        ruleId: 'sql-injection',
        line: 42,
        snippet: 'db.query("SELECT * FROM users WHERE id = " + id);',
      });
      expect(fp1).toBe(fp2);
      expect(fp1.length).toBe(64);
    });

    it('is resilient to whitespace and comment differences in code snippets', () => {
      const fp1 = generateStableFingerprint({
        file: 'src/api.ts',
        ruleId: 'eval-injection',
        snippet: '  eval( userInput ); // dangerous ',
      });
      const fp2 = generateStableFingerprint({
        file: 'src/api.ts',
        ruleId: 'eval-injection',
        snippet: 'eval( userInput );',
      });
      expect(fp1).toBe(fp2);
    });

    it('produces distinct fingerprints for different rules or files', () => {
      const fp1 = generateStableFingerprint({
        file: 'src/a.ts',
        ruleId: 'rule-one',
        line: 10,
      });
      const fp2 = generateStableFingerprint({
        file: 'src/b.ts',
        ruleId: 'rule-one',
        line: 10,
      });
      expect(fp1).not.toBe(fp2);
    });

    it('generates stable location-independent fingerprints for dependencies', () => {
      const fp1 = generateStableFingerprint({
        source: 'dependency',
        packageName: 'express',
        advisoryId: 'GHSA-xxxx-yyyy',
      });
      const fp2 = generateStableFingerprint({
        source: 'dependency',
        packageName: 'express',
        advisoryId: 'GHSA-xxxx-yyyy',
      });
      expect(fp1).toBe(fp2);
    });

    it('correlates findings on the same file within a 5-line window of the same category', () => {
      const f1 = { file: 'src/api.ts', line: 10, category: 'authorization' as const };
      const f2 = { file: 'src/api.ts', line: 12, category: 'authorization' as const };
      const f3 = { file: 'src/api.ts', line: 40, category: 'authorization' as const };

      expect(areFindingsCorrelated(f1, f2)).toBe(true);
      expect(areFindingsCorrelated(f1, f3)).toBe(false);
    });
  });

  describe('4. Deduplication of Findings From Multiple Sources', () => {
    it('deduplicates identical findings from the same scanner', () => {
      const engine = new FindingNormalizerEngine();
      const findings: FindingInput[] = [
        {
          source: 'semgrep',
          ruleId: 'js.sql-injection',
          file: 'src/db.ts',
          line: 25,
          snippet: 'db.raw(query)',
          severity: 'HIGH',
        },
        {
          source: 'semgrep',
          ruleId: 'js.sql-injection',
          file: 'src/db.ts',
          line: 25,
          snippet: 'db.raw(query)',
          severity: 'HIGH',
        },
      ];

      const result = engine.processFindings({ allFindings: findings });
      expect(result.totalRawFindings).toBe(2);
      expect(result.uniqueFindingsCount).toBe(1);
      expect(result.duplicatesRemoved).toBe(1);
      expect(result.unifiedFindings[0]?.distinction).toBe('confirmed_scanner_finding');
    });

    it('deduplicates across multiple deterministic scanners and merges metadata', () => {
      const engine = new FindingNormalizerEngine();
      const semgrepFinding: FindingInput = {
        source: 'semgrep',
        ruleId: 'sec.hardcoded-key',
        category: 'secrets',
        file: 'src/config.ts',
        line: 10,
        severity: 'MEDIUM',
        snippet: 'const key = "AKIAIOSFODNN7EXAMPLE";',
      };
      const gitleaksFinding: FindingInput = {
        source: 'gitleaks',
        ruleId: 'aws-access-key-id',
        category: 'secrets',
        file: 'src/config.ts',
        line: 10,
        severity: 'CRITICAL',
        snippet: 'const key = "AKIAIOSFODNN7EXAMPLE";',
      };

      const result = engine.processFindings({
        semgrepFindings: [semgrepFinding],
        gitleaksFindings: [gitleaksFinding],
      });

      expect(result.uniqueFindingsCount).toBe(1);
      expect(result.duplicatesRemoved).toBe(1);

      const unified = result.unifiedFindings[0]!;
      expect(unified.severity).toBe('CRITICAL'); // highest severity preserved between deterministic scanners
      expect(unified.contributingSources).toContain('semgrep');
      expect(unified.contributingSources).toContain('gitleaks');
      expect(unified.sources.length).toBe(2);
      expect(unified.distinction).toBe('confirmed_scanner_finding');
    });
  });

  describe('5. Preserving All Contributing Sources', () => {
    it('preserves full audit records of each contributing source', () => {
      const engine = new FindingNormalizerEngine();
      const result = engine.processFindings({
        semgrepFindings: [
          {
            ruleId: 'sqli',
            file: 'src/user.ts',
            line: 30,
            severity: 'HIGH',
            snippet: 'SELECT * FROM users',
            cwe: 'CWE-89',
          },
        ],
        aiFindings: [
          {
            ruleId: 'ai-contextual-sqli',
            file: 'src/user.ts',
            line: 30,
            severity: 'HIGH',
            remediation: 'Use parameterized queries',
            metadata: { reasoningSummary: 'Concatenation detected in query' },
          },
        ],
      });

      const finding = result.unifiedFindings[0]!;
      expect(finding.contributingSources).toEqual(['semgrep', 'ai-analyzer']);
      expect(finding.sources.length).toBe(2);

      const semgrepSource = finding.sources.find((s) => s.source === 'semgrep');
      expect(semgrepSource?.severity).toBe('HIGH');
      expect(semgrepSource?.cwe).toBe('CWE-89');

      const aiSource = finding.sources.find((s) => s.source === 'ai-analyzer');
      expect(aiSource?.source).toBe('ai-analyzer');
      expect(aiSource?.metadata?.reasoningSummary).toBe('Concatenation detected in query');
    });
  });

  describe('6. Distinguishing Finding Kinds', () => {
    it('labels finding as confirmed_scanner_finding when only deterministic scanner flags it', () => {
      const engine = new FindingNormalizerEngine();
      const result = engine.processFindings({
        semgrepFindings: [
          {
            ruleId: 'xss',
            file: 'src/view.ts',
            line: 15,
            severity: 'HIGH',
          },
        ],
      });

      expect(result.confirmedScannerCount).toBe(1);
      expect(result.aiSuggestedCount).toBe(0);
      expect(result.correlatedFindingsCount).toBe(0);
      expect(result.unifiedFindings[0]?.distinction).toBe('confirmed_scanner_finding');
    });

    it('labels finding as ai_suggested_finding when only AI analyzer flags it', () => {
      const engine = new FindingNormalizerEngine();
      const result = engine.processFindings({
        aiFindings: [
          {
            ruleId: 'ai-idor',
            file: 'src/controllers/order.ts',
            line: 55,
            category: 'authorization',
            severity: 'HIGH',
            title: 'IDOR in Order Controller',
            description: 'Missing tenant check',
          },
        ],
      });

      expect(result.confirmedScannerCount).toBe(0);
      expect(result.aiSuggestedCount).toBe(1);
      expect(result.correlatedFindingsCount).toBe(0);
      expect(result.unifiedFindings[0]?.distinction).toBe('ai_suggested_finding');
    });

    it('labels finding as correlated_finding when both deterministic scanner and AI identify it', () => {
      const engine = new FindingNormalizerEngine();
      const result = engine.processFindings({
        semgrepFindings: [
          {
            ruleId: 'idor-rule',
            file: 'src/controllers/order.ts',
            line: 55,
            category: 'authorization',
            severity: 'HIGH',
          },
        ],
        aiFindings: [
          {
            ruleId: 'ai-idor',
            file: 'src/controllers/order.ts',
            line: 55,
            category: 'authorization',
            severity: 'HIGH',
            description: 'AI confirmed missing ownership check',
          },
        ],
      });

      expect(result.correlatedFindingsCount).toBe(1);
      expect(result.confirmedScannerCount).toBe(0);
      expect(result.aiSuggestedCount).toBe(0);
      expect(result.unifiedFindings[0]?.distinction).toBe('correlated_finding');
    });
  });

  describe('7. Invariant: AI Finding NEVER Overwrites Deterministic Scanner Finding', () => {
    it('preserves deterministic severity even if AI suggests a lower severity', () => {
      const engine = new FindingNormalizerEngine();
      const result = engine.processFindings({
        semgrepFindings: [
          {
            ruleId: 'sqli',
            file: 'src/db.ts',
            line: 40,
            category: 'injection',
            severity: 'CRITICAL',
          },
        ],
        aiFindings: [
          {
            ruleId: 'ai-sqli',
            file: 'src/db.ts',
            line: 40,
            category: 'injection',
            severity: 'LOW', // Attempted downgrade
            description: 'AI believes input is partially sanitized',
          },
        ],
      });

      const finding = result.unifiedFindings[0]!;
      expect(finding.severity).toBe('CRITICAL'); // Deterministic severity remains authoritative
      expect(finding.distinction).toBe('correlated_finding');
      expect(finding.aiInsights?.suggestedSeverity).toBe('LOW'); // Suggested severity recorded in AI insights
    });

    it('preserves deterministic ruleId, category and location when AI correlates', () => {
      const engine = new FindingNormalizerEngine();
      const result = engine.processFindings({
        semgrepFindings: [
          {
            ruleId: 'semgrep.cwe-89.sql-injection',
            file: 'src/db.ts',
            line: 40,
            category: 'injection',
            severity: 'HIGH',
          },
        ],
        aiFindings: [
          {
            ruleId: 'ai-hallucinated-rule-name',
            file: 'src/db.ts',
            line: 41,
            category: 'business_logic',
            severity: 'HIGH',
            title: 'Database Query Logic',
          },
        ],
      });

      const finding = result.unifiedFindings[0]!;
      expect(finding.ruleId).toBe('semgrep.cwe-89.sql-injection');
      expect(finding.category).toBe('injection');
      expect(finding.line).toBe(40);
    });
  });

  describe('8. Confidence Values and Corroboration', () => {
    it('assigns high default confidence to deterministic scanners', () => {
      expect(normalizeConfidence(undefined, 'dependency')).toBe(1.0);
      expect(normalizeConfidence(undefined, 'gitleaks')).toBe(0.95);
      expect(normalizeConfidence(undefined, 'semgrep')).toBe(0.9);
      expect(normalizeConfidence(undefined, 'ai-analyzer')).toBe(0.8);
    });

    it('boosts confidence when multiple independent sources corroborate an issue', () => {
      const c1 = 0.9; // Semgrep
      const c2 = 0.85; // AI Analyzer
      const combined = combineConfidence(c1, c2);

      // Probabilistic union: 1 - (1 - 0.90) * (1 - 0.85) = 1 - (0.10 * 0.15) = 0.985
      expect(combined).toBe(0.985);
      expect(combined).toBeGreaterThan(c1);
      expect(combined).toBeGreaterThan(c2);
    });

    it('correlates finding confidence in engine result', () => {
      const engine = new FindingNormalizerEngine();
      const result = engine.processFindings({
        semgrepFindings: [
          {
            file: 'src/auth.ts',
            line: 20,
            category: 'authentication',
            severity: 'HIGH',
            confidence: 0.9,
          },
        ],
        aiFindings: [
          {
            file: 'src/auth.ts',
            line: 20,
            category: 'authentication',
            severity: 'HIGH',
            confidence: 0.8,
          },
        ],
      });

      const finding = result.unifiedFindings[0]!;
      expect(finding.confidence).toBe(0.98); // 1 - (0.1 * 0.2) = 0.98
    });
  });

  describe('9. Comprehensive Multi-Source Processing', () => {
    it('processes findings across Semgrep, Gitleaks, Dependency, and AI simultaneously', () => {
      const engine = defaultFindingNormalizerEngine;

      const result = engine.processFindings({
        semgrepFindings: [
          {
            source: 'semgrep',
            ruleId: 'sqli',
            category: 'injection',
            file: 'src/api/users.ts',
            line: 50,
            severity: 'CRITICAL',
            snippet: 'SELECT * FROM users WHERE id = ' + 'input',
            cwe: 'CWE-89',
          },
          {
            source: 'semgrep',
            ruleId: 'xss',
            category: 'injection',
            file: 'src/views/profile.ts',
            line: 80,
            severity: 'HIGH',
            cwe: 'CWE-79',
          },
        ],
        gitleaksFindings: [
          {
            source: 'gitleaks',
            ruleId: 'github-token',
            category: 'secrets',
            file: '.env.example',
            line: 12,
            severity: 'CRITICAL',
          },
        ],
        dependencyFindings: [
          {
            source: 'dependency',
            packageName: 'axios',
            advisoryId: 'CVE-2023-45857',
            category: 'dependency',
            severity: 'HIGH',
            title: 'SSRF in axios',
          },
        ],
        aiFindings: [
          {
            source: 'ai-analyzer',
            ruleId: 'ai-sqli',
            file: 'src/api/users.ts',
            line: 51,
            category: 'injection',
            severity: 'HIGH',
            title: 'Corroborated SQL Injection in User Lookup',
            remediation: 'Use Prisma prepared statements',
            metadata: { reasoningSummary: 'User input concatenates into query directly' },
          },
          {
            source: 'ai-analyzer',
            ruleId: 'ai-idor',
            file: 'src/api/teams.ts',
            line: 95,
            category: 'authorization',
            severity: 'HIGH',
            title: 'Missing Authorization on Team Membership',
            description: 'Any user can add themselves to another team',
            remediation: 'Validate team admin rights',
          },
        ],
      });

      // Total raw findings: 2 Semgrep + 1 Gitleaks + 1 Dependency + 2 AI = 6 raw
      expect(result.totalRawFindings).toBe(6);

      // Unique:
      // 1. SQLi in users.ts (Semgrep + AI -> Correlated)
      // 2. XSS in profile.ts (Semgrep -> Confirmed)
      // 3. GitHub Token in .env.example (Gitleaks -> Confirmed)
      // 4. Axios SSRF (Dependency -> Confirmed)
      // 5. Team IDOR in teams.ts (AI -> AI-Suggested)
      expect(result.uniqueFindingsCount).toBe(5);
      expect(result.duplicatesRemoved).toBe(1);
      expect(result.correlatedFindingsCount).toBe(1);
      expect(result.confirmedScannerCount).toBe(3);
      expect(result.aiSuggestedCount).toBe(1);

      // Check category breakdown
      expect(result.byCategory.injection).toBe(2);
      expect(result.byCategory.secrets).toBe(1);
      expect(result.byCategory.dependency).toBe(1);
      expect(result.byCategory.authorization).toBe(1);

      // Check severity breakdown
      expect(result.bySeverity.CRITICAL).toBe(2); // SQLi and Gitleaks token
      expect(result.bySeverity.HIGH).toBe(3); // XSS, Axios, and Team IDOR

      // Verify the correlated SQLi finding has both sources and preserved severity
      const sqli = result.unifiedFindings.find((f) => f.file === 'src/api/users.ts')!;
      expect(sqli.severity).toBe('CRITICAL');
      expect(sqli.distinction).toBe('correlated_finding');
      expect(sqli.contributingSources).toEqual(['semgrep', 'ai-analyzer']);
      expect(sqli.remediation).toBe('Use Prisma prepared statements');
      expect(sqli.aiInsights?.reasoningSummary).toBe('User input concatenates into query directly');
    });
  });
});
