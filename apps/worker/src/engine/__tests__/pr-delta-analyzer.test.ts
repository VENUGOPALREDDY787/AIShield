import { describe, expect, it } from 'vitest';
import {
  PRDeltaAnalyzer,
  analyzePullRequestDelta,
} from '../pr-delta-analyzer.js';
import type { ScoringFindingInput } from '../debt-scoring-engine.js';

describe('Pull Request Security-Debt Delta Analysis', () => {
  const analyzer = new PRDeltaAnalyzer();

  const sampleDiff = `
diff --git a/src/routes/auth.ts b/src/routes/auth.ts
index 1111111..2222222 100644
--- a/src/routes/auth.ts
+++ b/src/routes/auth.ts
@@ -15,4 +15,6 @@ export function login(req, res) {
   const user = req.body.user;
+  const query = "SELECT * FROM users WHERE user = '" + user + "'";
+  db.query(query);
   res.send(user);
 }
diff --git a/src/utils/crypto.ts b/src/utils/crypto.ts
index 3333333..4444444 100644
--- a/src/utils/crypto.ts
+++ b/src/utils/crypto.ts
@@ -10,3 +10,3 @@ export function hashPassword(pass) {
-  return crypto.createHash('md5').update(pass).digest('hex');
+  return bcrypt.hashSync(pass, 12);
 }
`.trim();

  describe('1. New Vulnerability', () => {
    it('identifies vulnerability introduced specifically within added diff lines', () => {
      const baseFindings: ScoringFindingInput[] = [];

      const headFindings: ScoringFindingInput[] = [
        {
          file: 'src/routes/auth.ts',
          line: 17,
          ruleId: 'sql-injection',
          severity: 'CRITICAL',
          category: 'injection',
          snippet: 'db.query("SELECT * FROM users WHERE user = \'" + user + "\'")',
        },
      ];

      const result = analyzer.analyzePRDelta({
        baseCommit: 'commit-base-123',
        headCommit: 'commit-head-456',
        baseFindings,
        headFindings,
        diffContent: sampleDiff,
      });

      expect(result.findingsIntroduced).toHaveLength(1);
      const introduced = result.findingsIntroduced[0]!;
      expect(introduced.status).toBe('new');
      expect(introduced.isIntroducedByPR).toBe(true);
      expect(introduced.reason).toContain('added/modified PR diff hunk');

      expect(result.baseScore).toBe(0);
      expect(result.headScore).toBeGreaterThan(0);
      expect(result.newDebt).toBeGreaterThan(0);
      expect(result.netDebtChange).toBeGreaterThan(0);
      expect(result.resolvedDebt).toBe(0);
      expect(result.summary).toContain('PR introduced 1 new security finding(s)');
    });
  });

  describe('2. Fixed Vulnerability', () => {
    it('identifies vulnerability resolved by PR modifications', () => {
      // BASE had MD5 weak cryptographic hash
      const baseFindings: ScoringFindingInput[] = [
        {
          file: 'src/utils/crypto.ts',
          line: 11,
          ruleId: 'weak-crypto-md5',
          severity: 'HIGH',
          category: 'cryptography',
          snippet: "crypto.createHash('md5')",
        },
      ];

      // HEAD resolved it with bcrypt (crypto.ts modified in diff)
      const headFindings: ScoringFindingInput[] = [];

      const result = analyzer.analyzePRDelta({
        baseCommit: 'commit-base-123',
        headCommit: 'commit-head-456',
        baseFindings,
        headFindings,
        diffContent: sampleDiff,
      });

      expect(result.findingsResolved).toHaveLength(1);
      const resolved = result.findingsResolved[0]!;
      expect(resolved.status).toBe('resolved');
      expect(resolved.reason).toContain('resolved by PR code changes');

      expect(result.baseScore).toBeGreaterThan(0);
      expect(result.headScore).toBe(0);
      expect(result.resolvedDebt).toBeGreaterThan(0);
      expect(result.netDebtChange).toBeLessThan(0); // Score improved!
      expect(result.newDebt).toBe(0);
      expect(result.summary).toContain('PR successfully resolved 1 existing security finding(s)');
    });
  });

  describe('3. Unchanged Vulnerability', () => {
    it('recognizes pre-existing vulnerability untouched across BASE and HEAD', () => {
      const untouchedFinding: ScoringFindingInput = {
        file: 'src/legacy/data-export.ts',
        line: 50,
        ruleId: 'insecure-cookie-flags',
        severity: 'MEDIUM',
        category: 'configuration',
        snippet: 'res.cookie("session", id)',
      };

      const result = analyzer.analyzePRDelta({
        baseCommit: 'base-1',
        headCommit: 'head-2',
        baseFindings: [untouchedFinding],
        headFindings: [untouchedFinding],
        diffContent: sampleDiff, // Diff does not touch data-export.ts
      });

      expect(result.findingsUnchanged).toHaveLength(1);
      expect(result.findingsIntroduced).toHaveLength(0);
      expect(result.findingsResolved).toHaveLength(0);

      const unchanged = result.findingsUnchanged[0]!;
      expect(unchanged.status).toBe('unchanged');
      expect(unchanged.isIntroducedByPR).toBe(false);

      expect(result.baseScore).toBe(result.headScore);
      expect(result.netDebtChange).toBe(0);
      expect(result.newDebt).toBe(0);
      expect(result.resolvedDebt).toBe(0);
    });
  });

  describe('4. Modified Vulnerability (Line Drift & Context Shift)', () => {
    it('detects pre-existing vulnerability when lines shift due to surrounding edits', () => {
      // BASE finding on line 30
      const baseFinding: ScoringFindingInput = {
        file: 'src/routes/auth.ts',
        line: 30,
        ruleId: 'hardcoded-salt',
        category: 'cryptography',
        severity: 'MEDIUM',
        snippet: 'const salt = "static_salt_12345";',
      };

      // In HEAD, 2 lines were added earlier in auth.ts, so the salt line shifted to line 32
      const headFinding: ScoringFindingInput = {
        file: 'src/routes/auth.ts',
        line: 32,
        ruleId: 'hardcoded-salt',
        category: 'cryptography',
        severity: 'MEDIUM',
        snippet: 'const salt = "static_salt_12345";',
      };

      const result = analyzer.analyzePRDelta({
        baseCommit: 'base-1',
        headCommit: 'head-2',
        baseFindings: [baseFinding],
        headFindings: [headFinding],
        diffContent: sampleDiff,
      });

      expect(result.findingsModified).toHaveLength(1);
      expect(result.findingsIntroduced).toHaveLength(0); // NOT blamed as new debt!

      const modified = result.findingsModified[0]!;
      expect(modified.status).toBe('modified');
      expect(modified.isIntroducedByPR).toBe(false);
      expect(modified.reason).toContain('Pre-existing vulnerability from BASE commit; location drifted');
      expect(modified.matchedBaseFingerprint).toBeDefined();

      // Since the finding was existing and just shifted, newDebt should be 0
      expect(result.newDebt).toBe(0);
    });
  });

  describe('5. Duplicated Findings Handling', () => {
    it('deduplicates multiple identical findings in BASE and HEAD before computing delta', () => {
      // Duplicate findings in HEAD
      const dup1: ScoringFindingInput = {
        file: 'src/routes/auth.ts',
        line: 17,
        ruleId: 'sql-injection',
        severity: 'CRITICAL',
        category: 'injection',
        snippet: 'db.query(rawSql)',
      };
      const dup2: ScoringFindingInput = { ...dup1 };

      const result = analyzer.analyzePRDelta({
        baseCommit: 'base-1',
        headCommit: 'head-2',
        baseFindings: [],
        headFindings: [dup1, dup2],
        diffContent: sampleDiff,
      });

      // Deduplicated into 1 introduced finding
      expect(result.totalHeadFindings).toBe(1);
      expect(result.findingsIntroduced).toHaveLength(1);
    });
  });

  describe('6. Strict Evidence Invariant (No False Attribution)', () => {
    it('does NOT claim vulnerability is introduced by PR if file was not touched in PR', () => {
      const findingInUntouchedFile: ScoringFindingInput = {
        file: 'src/services/billing.ts',
        line: 45,
        ruleId: 'idor-check',
        severity: 'HIGH',
        category: 'authorization',
      };

      const result = analyzer.analyzePRDelta({
        baseCommit: 'base-1',
        headCommit: 'head-2',
        baseFindings: [], // Not in base (e.g. new scanner rule)
        headFindings: [findingInUntouchedFile],
        diffContent: sampleDiff, // Diff only touched auth.ts and crypto.ts!
      });

      // Crucial: The developer did NOT touch billing.ts in this PR!
      expect(result.findingsIntroduced).toHaveLength(0);
      expect(result.findingsUnchanged).toHaveLength(1);
      expect(result.findingsUnchanged[0]?.isIntroducedByPR).toBe(false);
      expect(result.findingsUnchanged[0]?.reason).toContain('not modified in this Pull Request');
      expect(result.newDebt).toBe(0);
    });

    it('does NOT claim vulnerability is introduced if line is outside PR diff hunks', () => {
      const findingOutsideHunk: ScoringFindingInput = {
        file: 'src/routes/auth.ts',
        line: 300, // auth.ts was modified, but only lines 15-20 were touched in diff!
        ruleId: 'console-log-sensitive',
        severity: 'LOW',
        category: 'data_exposure',
      };

      const result = analyzer.analyzePRDelta({
        baseCommit: 'base-1',
        headCommit: 'head-2',
        baseFindings: [],
        headFindings: [findingOutsideHunk],
        diffContent: sampleDiff,
      });

      expect(result.findingsIntroduced).toHaveLength(0);
      expect(result.findingsUnchanged).toHaveLength(1);
      expect(result.findingsUnchanged[0]?.isIntroducedByPR).toBe(false);
      expect(result.findingsUnchanged[0]?.reason).toContain('outside the PR diff hunks');
      expect(result.newDebt).toBe(0);
    });
  });

  describe('7. Simultaneous New and Resolved Debt (Net Change)', () => {
    it('correctly calculates netDebtChange when PR fixes one vulnerability while introducing another', () => {
      // BASE has MD5 in crypto.ts
      const baseFindings: ScoringFindingInput[] = [
        {
          file: 'src/utils/crypto.ts',
          line: 11,
          ruleId: 'weak-crypto-md5',
          severity: 'HIGH',
          category: 'cryptography',
          snippet: "crypto.createHash('md5')",
        },
      ];

      // HEAD fixes crypto.ts, but introduces SQLi in auth.ts
      const headFindings: ScoringFindingInput[] = [
        {
          file: 'src/routes/auth.ts',
          line: 17,
          ruleId: 'sql-injection',
          severity: 'CRITICAL',
          category: 'injection',
          snippet: 'db.query("SELECT * FROM users WHERE user = \'" + user + "\'")',
        },
      ];

      const result = analyzePullRequestDelta({
        baseCommit: 'base-commit',
        headCommit: 'head-commit',
        baseFindings,
        headFindings,
        diffContent: sampleDiff,
      });

      expect(result.findingsIntroduced).toHaveLength(1);
      expect(result.findingsResolved).toHaveLength(1);
      expect(result.newDebt).toBeGreaterThan(0);
      expect(result.resolvedDebt).toBeGreaterThan(0);
      expect(result.summary).toContain('PR introduced 1 new finding(s)');
      expect(result.summary).toContain('resolved 1 existing finding(s)');
    });
  });
});
