/**
 * Security Debt Explanation Service.
 *
 * Generates concise, deterministic, human-readable and machine-auditable
 * explanations for Security Debt scores and score deltas directly from
 * structured findings.
 *
 * Architecture & Security Principles:
 *  1. Deterministic Grounding: Explanations are derived exclusively from
 *     verified structured findings.
 *  2. No Hallucination: The LLM is NEVER allowed to invent vulnerabilities or
 *     modify scores.
 *  3. Verification Guardrails: If an AI synthesizer is used to produce natural
 *     language commentary, its output is strictly validated against the actual
 *     findings list; any unverified finding is stripped.
 */

import type {
  DebtExplanation,
  DebtExplanationContributor,
  NormalizedCategory,
  NormalizedSeverity,
  SecurityDebtResult,
  TopDebtContributor,
  UnifiedFinding,
} from '@aishield/shared';
import { redactSensitivePatterns } from '@aishield/shared';
import type { ScoringFindingInput } from './debt-scoring-engine.js';

export interface DebtExplanationInput {
  /** The calculated security debt result */
  debtResult: SecurityDebtResult;
  /** Active findings contributing to this score */
  findings?: readonly (UnifiedFinding | ScoringFindingInput)[];
  /** Previous findings (for explaining resolved debt) */
  previousFindings?: readonly (UnifiedFinding | ScoringFindingInput)[];
  /** Max contributors to list (default: 3) */
  maxContributors?: number;
}

export interface AiExplanationPromptPayload {
  score: number;
  previousScore: number;
  delta: number;
  riskLevel: string;
  verifiedFindings: Array<{
    fingerprint: string;
    title: string;
    severity: string;
    category: string;
    file: string;
    line: number;
  }>;
}

export class SecurityDebtExplanationService {
  /**
   * Generates a deterministic explanation from structured findings.
   */
  generateExplanation(input: DebtExplanationInput): DebtExplanation {
    const { debtResult, maxContributors = 3 } = input;
    const score = debtResult.score;
    const prevScore = debtResult.previousScore;
    const delta = debtResult.delta;
    const risk = debtResult.riskLevel;

    // 1. Generate concise Delta Statement
    let summary: string;
    let deltaStatement: string;

    if (prevScore === 0 && score === 0) {
      summary = 'Security Debt score is 0/100 (Clean). No security debt detected.';
      deltaStatement = 'Security Debt is 0 (Clean baseline).';
    } else if (prevScore === score || delta === 0) {
      summary = `Security Debt remained unchanged at ${score}.`;
      deltaStatement = `Security Debt remained unchanged at ${score}/100.`;
    } else if (delta > 0) {
      summary = `Security Debt increased from ${prevScore} to ${score}.`;
      deltaStatement = `Security Debt increased from ${prevScore} to ${score} (+${delta} pts).`;
    } else {
      summary = `Security Debt decreased from ${prevScore} to ${score}.`;
      deltaStatement = `Security Debt decreased from ${prevScore} to ${score} (${delta} pts).`;
    }

    const riskStatement = `Risk Level: ${risk}`;

    // 2. Extract and format Main Contributors strictly from top contributors
    const contributors = this.formatContributors(debtResult.topContributors, maxContributors);

    // 3. Generate New Debt & Resolved Debt explanations
    let newDebtExplanation: string | undefined;
    if (debtResult.newDebt > 0) {
      newDebtExplanation = `New debt of +${debtResult.newDebt} pts introduced in this scan.`;
    }

    let resolvedDebtExplanation: string | undefined;
    if (debtResult.resolvedDebt > 0) {
      resolvedDebtExplanation = `Resolved ${debtResult.resolvedDebt} pts of existing security debt.`;
    }

    // 4. Construct plain-text multi-line explanation
    const textLines: string[] = [summary];

    if (contributors.length > 0) {
      textLines.push('', 'Main contributors:', '');
      for (const c of contributors) {
        textLines.push(`${c.rank}. ${c.description}`);
      }
    } else if (score === 0) {
      textLines.push('No open security vulnerabilities or weaknesses detected.');
    }

    const textExplanation = textLines.join('\n');

    // 5. Construct Markdown explanation (suitable for GitHub comments and PR reports)
    const mdLines: string[] = [`**${summary}**`];

    if (contributors.length > 0) {
      mdLines.push('', '### Main contributors:', '');
      for (const c of contributors) {
        const sevBadge = this.getSeverityEmoji(c.severity);
        const loc = c.file ? ` (\`${c.file}:${c.line || 1}\`)` : '';
        mdLines.push(
          `${c.rank}. ${sevBadge} **${c.severity}** ${this.formatCategoryName(c.category)}: ${c.title}${loc}`,
        );
      }
    }

    if (newDebtExplanation || resolvedDebtExplanation) {
      mdLines.push('');
      if (newDebtExplanation) mdLines.push(`- ⚠️ ${newDebtExplanation}`);
      if (resolvedDebtExplanation) mdLines.push(`- ✅ ${resolvedDebtExplanation}`);
    }

    const markdownExplanation = mdLines.join('\n');

    return {
      summary,
      deltaStatement,
      riskStatement,
      mainContributors: contributors,
      newDebtExplanation,
      resolvedDebtExplanation,
      textExplanation,
      markdownExplanation,
      isAiAssisted: false,
    };
  }

  /**
   * Formats top contributors into clean, structured explanation items.
   */
  private formatContributors(
    topContributors: readonly TopDebtContributor[],
    maxCount: number,
  ): DebtExplanationContributor[] {
    if (!topContributors || topContributors.length === 0) {
      return [];
    }

    return topContributors.slice(0, maxCount).map((tc, index) => {
      const rank = index + 1;
      const safeTitle = redactSensitivePatterns(tc.title).text;
      const safeFile = tc.file ? redactSensitivePatterns(tc.file).text : undefined;
      const catName = this.formatCategoryName(tc.category);

      // Concise natural description: "HIGH authorization finding - <Title>" or "CRITICAL secret exposure"
      let desc: string;
      if (tc.category === 'secrets') {
        desc = `${tc.severity} secret exposure`;
      } else if (tc.category === 'dependency') {
        desc = `${tc.severity} dependency vulnerability`;
      } else {
        desc = `${tc.severity} ${catName} finding`;
      }

      if (safeTitle) {
        desc += `: ${safeTitle}`;
      }
      if (safeFile) {
        desc += ` (${safeFile}${tc.line ? `:${tc.line}` : ''})`;
      }

      return {
        rank,
        severity: tc.severity,
        category: tc.category,
        title: safeTitle,
        file: safeFile,
        line: tc.line,
        debtPoints: tc.debtPoints,
        description: desc,
      };
    });
  }

  /**
   * Helper to format category identifier to human-friendly text.
   */
  private formatCategoryName(category: NormalizedCategory | string): string {
    const map: Record<string, string> = {
      injection: 'injection',
      authorization: 'authorization',
      authentication: 'authentication',
      secrets: 'secret exposure',
      cryptography: 'cryptography',
      data_exposure: 'data exposure',
      dependency: 'dependency vulnerability',
      input_validation: 'input validation',
      command_execution: 'command execution',
      configuration: 'security configuration',
      business_logic: 'business logic',
      other: 'security weakness',
    };
    return map[category] || category.replace(/_/g, ' ');
  }

  private getSeverityEmoji(sev: NormalizedSeverity): string {
    switch (sev) {
      case 'CRITICAL':
        return '🔴';
      case 'HIGH':
        return '🟠';
      case 'MEDIUM':
        return '🟡';
      case 'LOW':
        return '🟢';
      default:
        return '⚪';
    }
  }

  /**
   * Prepares a sanitized payload for optional LLM natural language explanation.
   * Ensures the LLM only receives verified structured findings and cannot invent findings.
   */
  prepareAiPromptPayload(
    debtResult: SecurityDebtResult,
    verifiedFindings: readonly (UnifiedFinding | ScoringFindingInput)[],
  ): AiExplanationPromptPayload {
    return {
      score: debtResult.score,
      previousScore: debtResult.previousScore,
      delta: debtResult.delta,
      riskLevel: debtResult.riskLevel,
      verifiedFindings: (verifiedFindings || []).map((f) => ({
        fingerprint: f.fingerprint || '',
        title: redactSensitivePatterns(f.title || '').text,
        severity: String(f.severity || 'MEDIUM'),
        category: String(f.category || 'other'),
        file: redactSensitivePatterns(f.file || '').text,
        line: f.line || 1,
      })),
    };
  }

  /**
   * Validates an AI-generated explanation against the list of actual verified findings.
   * If any mentioned finding does not exist in the verified findings set, it is flagged/removed.
   */
  validateAiExplanationAgainstFindings(
    aiMentionedTitlesOrFingerprints: readonly string[],
    verifiedFindings: readonly (UnifiedFinding | ScoringFindingInput)[],
  ): { isValid: boolean; verifiedMatches: string[]; unverifiedHallucinations: string[] } {
    const verifiedSet = new Set<string>();
    for (const vf of verifiedFindings) {
      if (vf.fingerprint) verifiedSet.add(vf.fingerprint.toLowerCase());
      if (vf.title) verifiedSet.add(vf.title.toLowerCase().trim());
      if (vf.file) verifiedSet.add(vf.file.toLowerCase().trim());
    }

    const verifiedMatches: string[] = [];
    const unverifiedHallucinations: string[] = [];

    for (const item of aiMentionedTitlesOrFingerprints) {
      const query = item.toLowerCase().trim();
      const matched = Array.from(verifiedSet).some(
        (v) => v.includes(query) || query.includes(v),
      );

      if (matched) {
        verifiedMatches.push(item);
      } else {
        unverifiedHallucinations.push(item);
      }
    }

    return {
      isValid: unverifiedHallucinations.length === 0,
      verifiedMatches,
      unverifiedHallucinations,
    };
  }
}

export const defaultDebtExplanationService = new SecurityDebtExplanationService();

/**
 * Functional entry point to generate a deterministic Security Debt explanation.
 */
export function explainSecurityDebt(input: DebtExplanationInput): DebtExplanation {
  return defaultDebtExplanationService.generateExplanation(input);
}
