import type {
  CategorizedFindingDelta,
  PRDeltaAnalysisResult,
  UnifiedFinding,
} from '@aishield/shared';
import { areFindingsCorrelated, canonicalizeFilePath } from './fingerprint.js';
import { parseGitDiff, isLineInDiffHunk } from './diff-parser.js';
import {
  FindingNormalizerEngine,
  type FindingInput,
} from './finding-normalizer-engine.js';
import {
  SecurityDebtScoringEngine,
  type ScoringFindingInput,
} from './debt-scoring-engine.js';

export interface PRDeltaOptions {
  baseCommit: string;
  headCommit: string;
  baseFindings: readonly (UnifiedFinding | ScoringFindingInput)[];
  headFindings: readonly (UnifiedFinding | ScoringFindingInput)[];
  diffContent?: string;
  changedFiles?: readonly string[];
}

export class PRDeltaAnalyzer {
  private readonly normalizerEngine: FindingNormalizerEngine;
  private readonly debtEngine: SecurityDebtScoringEngine;

  constructor(
    normalizerEngine?: FindingNormalizerEngine,
    debtEngine?: SecurityDebtScoringEngine,
  ) {
    this.normalizerEngine = normalizerEngine || new FindingNormalizerEngine();
    this.debtEngine = debtEngine || new SecurityDebtScoringEngine(this.normalizerEngine);
  }

  /**
   * Performs rigorous PR security-debt delta analysis.
   * Enforces the invariant:
   * "Do not claim that a vulnerability was introduced by a PR unless the evidence supports that conclusion."
   */
  analyzePRDelta(options: PRDeltaOptions): PRDeltaAnalysisResult {
    const { baseCommit, headCommit, diffContent } = options;

    // 1. Deduplicate & normalize BASE and HEAD findings
    const baseDedup = this.normalizerEngine.processFindings({
      allFindings: options.baseFindings as unknown as readonly FindingInput[],
    });
    const headDedup = this.normalizerEngine.processFindings({
      allFindings: options.headFindings as unknown as readonly FindingInput[],
    });

    const deduplicatedBase = baseDedup.unifiedFindings;
    const deduplicatedHead = headDedup.unifiedFindings;

    // 2. Parse Git Diff evidence
    const parsedDiff = parseGitDiff(diffContent);
    const changedFilesSet = new Set<string>();

    for (const f of parsedDiff.changedFiles) {
      changedFilesSet.add(canonicalizeFilePath(f).toLowerCase());
    }
    if (options.changedFiles) {
      for (const f of options.changedFiles) {
        changedFilesSet.add(canonicalizeFilePath(f).toLowerCase());
      }
    }

    const hasDiffEvidence = Boolean(diffContent && diffContent.trim().length > 0);

    // 3. Classify HEAD findings (new vs modified vs unchanged)
    const categorizedHead: CategorizedFindingDelta[] = [];
    const matchedBaseFingerprints = new Set<string>();

    for (const headFinding of deduplicatedHead) {
      const headFile = canonicalizeFilePath(headFinding.file).toLowerCase();

      // Check 3.1: Exact fingerprint match in BASE
      const exactBaseMatch = deduplicatedBase.find(
        (bf) => bf.fingerprint === headFinding.fingerprint,
      );

      if (exactBaseMatch) {
        matchedBaseFingerprints.add(exactBaseMatch.fingerprint);
        const lineShifted = exactBaseMatch.line !== headFinding.line;
        categorizedHead.push({
          finding: headFinding,
          status: lineShifted ? 'modified' : 'unchanged',
          isIntroducedByPR: false,
          matchedBaseFingerprint: exactBaseMatch.fingerprint,
          reason: lineShifted
            ? `Pre-existing vulnerability from BASE commit; location drifted from line ${exactBaseMatch.line} to ${headFinding.line} due to PR edits`
            : `Identical finding already present in BASE commit (${exactBaseMatch.file}:${exactBaseMatch.line})`,
        });
        continue;
      }

      // Check 3.2: Shifted / Modified finding from BASE (same file & category/rule, line drifted)
      const modifiedBaseMatch = deduplicatedBase.find((bf) =>
        areFindingsCorrelated(bf, headFinding),
      );

      if (modifiedBaseMatch) {
        matchedBaseFingerprints.add(modifiedBaseMatch.fingerprint);
        categorizedHead.push({
          finding: headFinding,
          status: 'modified',
          isIntroducedByPR: false,
          matchedBaseFingerprint: modifiedBaseMatch.fingerprint,
          reason: `Pre-existing vulnerability from BASE commit; location drifted or surrounding code edited (${modifiedBaseMatch.file}:${modifiedBaseMatch.line} -> line ${headFinding.line})`,
        });
        continue;
      }

      // Check 3.3: Finding is absent from BASE. Does evidence prove it was introduced by this PR?
      // Rule A: Was the file even touched in this PR?
      if (changedFilesSet.size > 0 && !changedFilesSet.has(headFile)) {
        // File was NOT touched in this PR!
        categorizedHead.push({
          finding: headFinding,
          status: 'unchanged',
          isIntroducedByPR: false,
          reason: `File "${headFinding.file}" was not modified in this Pull Request; vulnerability pre-dates this PR`,
        });
        continue;
      }

      // Rule B: File was touched. If diffContent is available, verify the line is in a modified hunk
      if (hasDiffEvidence) {
        const lineCheck = isLineInDiffHunk(headFinding.file, headFinding.line, parsedDiff);

        if (lineCheck.isChanged) {
          // PROVEN: line is directly in PR's added/modified hunks
          categorizedHead.push({
            finding: headFinding,
            status: 'new',
            isIntroducedByPR: true,
            reason: `Vulnerability introduced on line ${headFinding.line} within added/modified PR diff hunk`,
          });
        } else {
          // Unrelated lines in a modified file were not touched
          categorizedHead.push({
            finding: headFinding,
            status: 'unchanged',
            isIntroducedByPR: false,
            reason: `File was modified, but line ${headFinding.line} is outside the PR diff hunks; vulnerability pre-dates this PR`,
          });
        }
        continue;
      }

      // If no line-by-line diff text was supplied but the file is in changedFiles
      categorizedHead.push({
        finding: headFinding,
        status: 'new',
        isIntroducedByPR: true,
        reason: `Vulnerability introduced in file "${headFinding.file}" modified by this Pull Request`,
      });
    }

    // 4. Classify BASE findings that were resolved (present in BASE, absent in HEAD)
    const categorizedResolved: CategorizedFindingDelta[] = [];

    for (const baseFinding of deduplicatedBase) {
      if (!matchedBaseFingerprints.has(baseFinding.fingerprint)) {
        const baseFile = canonicalizeFilePath(baseFinding.file).toLowerCase();
        const wasFileModified = changedFilesSet.has(baseFile);

        categorizedResolved.push({
          finding: baseFinding,
          status: 'resolved',
          isIntroducedByPR: false,
          matchedBaseFingerprint: baseFinding.fingerprint,
          reason: wasFileModified
            ? `Vulnerability in "${baseFinding.file}" was resolved by PR code changes`
            : `Vulnerability is no longer present in HEAD commit`,
        });
      }
    }

    // 5. Partition categorized findings
    const findingsIntroduced = categorizedHead.filter((f) => f.status === 'new' && f.isIntroducedByPR);
    const findingsModified = categorizedHead.filter((f) => f.status === 'modified');
    const findingsUnchanged = categorizedHead.filter((f) => f.status === 'unchanged');
    const findingsResolved = categorizedResolved;

    // 6. Calculate deterministic scores & debt deltas
    const baseScoreResult = this.debtEngine.calculateDebt({
      findings: deduplicatedBase,
    });
    const headScoreResult = this.debtEngine.calculateDebt({
      findings: deduplicatedHead,
    });

    const baseScore = baseScoreResult.score;
    const headScore = headScoreResult.score;
    const netDebtChange = Number((headScore - baseScore).toFixed(2));

    // Calculate newDebt: score generated strictly by the findings introduced in this PR
    const newDebtResult = this.debtEngine.calculateDebt({
      findings: findingsIntroduced.map((f) => f.finding),
      prChangedFiles: Array.from(changedFilesSet),
    });
    const newDebt = newDebtResult.score;

    // Calculate resolvedDebt: score that was eliminated by resolved findings
    const resolvedDebtResult = this.debtEngine.calculateDebt({
      findings: findingsResolved.map((f) => f.finding),
    });
    const resolvedDebt = resolvedDebtResult.score;

    // 7. Compose executive summary narrative
    let summary: string;
    if (findingsIntroduced.length > 0 && findingsResolved.length > 0) {
      summary = `PR introduced ${findingsIntroduced.length} new finding(s) (+${newDebt} debt), but resolved ${findingsResolved.length} existing finding(s) (-${resolvedDebt} debt). Net score change: ${netDebtChange > 0 ? `+${netDebtChange}` : netDebtChange}.`;
    } else if (findingsIntroduced.length > 0) {
      summary = `PR introduced ${findingsIntroduced.length} new security finding(s) (+${newDebt} debt). Net score change: +${netDebtChange}.`;
    } else if (findingsResolved.length > 0) {
      summary = `PR successfully resolved ${findingsResolved.length} existing security finding(s) (-${resolvedDebt} debt). Net score change: ${netDebtChange}.`;
    } else {
      summary = `PR did not introduce or resolve any security debt. Security debt remains stable at ${headScore}.`;
    }

    return {
      baseCommit,
      headCommit,
      baseScore,
      headScore,
      newDebt,
      resolvedDebt,
      netDebtChange,
      findingsIntroduced,
      findingsResolved,
      findingsModified,
      findingsUnchanged,
      totalHeadFindings: deduplicatedHead.length,
      totalBaseFindings: deduplicatedBase.length,
      changedFilesCount: changedFilesSet.size,
      summary,
    };
  }
}

export const defaultPRDeltaAnalyzer = new PRDeltaAnalyzer();

/**
 * Functional entry point for Pull Request delta analysis.
 */
export function analyzePullRequestDelta(options: PRDeltaOptions): PRDeltaAnalysisResult {
  return defaultPRDeltaAnalyzer.analyzePRDelta(options);
}
