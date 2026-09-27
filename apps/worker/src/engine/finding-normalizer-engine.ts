import type {
  ContributingSource,
  FindingDistinction,
  NormalizedCategory,
  NormalizedSeverity,
  UnifiedFinding,
} from '@aishield/shared';
import {
  NORMALIZED_CATEGORIES,
  NORMALIZED_SEVERITIES,
} from '@aishield/shared';
import {
  areFindingsCorrelated,
  canonicalizeFilePath,
  generateStableFingerprint,
} from './fingerprint.js';
import {
  combineConfidence,
  maxSeverity,
  normalizeCategory,
  normalizeConfidence,
  normalizeSeverity,
} from './normalizer.js';

export interface FindingInput {
  source?: string;
  ruleId?: string;
  category?: string;
  title?: string;
  description?: string;
  severity?: unknown;
  confidence?: unknown;
  file?: string;
  line?: number;
  endLine?: number;
  snippet?: string;
  cwe?: string;
  fingerprint?: string;
  remediation?: string;
  metadata?: Record<string, unknown>;
  location?: {
    filePath?: string;
    startLine?: number;
    endLine?: number;
    snippet?: string;
  };
  packageName?: string;
  advisoryId?: string;
  [key: string]: unknown;
}

export interface EngineProcessInputs {
  semgrepFindings?: readonly FindingInput[];
  gitleaksFindings?: readonly FindingInput[];
  dependencyFindings?: readonly FindingInput[];
  aiFindings?: readonly FindingInput[];
  allFindings?: readonly FindingInput[];
  scanId?: string;
}

export interface EngineDeduplicationResult {
  unifiedFindings: UnifiedFinding[];
  totalRawFindings: number;
  uniqueFindingsCount: number;
  duplicatesRemoved: number;
  correlatedFindingsCount: number;
  confirmedScannerCount: number;
  aiSuggestedCount: number;
  byCategory: Record<NormalizedCategory, number>;
  bySeverity: Record<NormalizedSeverity, number>;
}

export class FindingNormalizerEngine {
  /**
   * Normalizes an individual raw finding into an initial UnifiedFinding object.
   */
  normalizeSingleFinding(raw: FindingInput, defaultSource?: string, scanId?: string): UnifiedFinding {
    const source = String(raw.source || defaultSource || 'unknown').toLowerCase();
    const isAI = this.isAISource(source, raw);

    const file = canonicalizeFilePath(raw.file || raw.location?.filePath || '');
    const line = raw.line ?? raw.location?.startLine ?? 1;
    const endLine = raw.endLine ?? raw.location?.endLine;
    const snippet = raw.snippet ?? raw.location?.snippet;
    const ruleId = String(raw.ruleId || raw.title || 'unspecified-rule');
    const title = String(raw.title || raw.ruleId || 'Security Finding');
    const description = String(raw.description || raw.message || title);
    const cwe = raw.cwe ? String(raw.cwe).trim() : undefined;
    const remediation = raw.remediation ? String(raw.remediation).trim() : undefined;

    const severity = normalizeSeverity(raw.severity);
    const category = normalizeCategory({
      category: raw.category,
      ruleId,
      cwe,
      title,
      description,
      source,
    });
    const confidence = normalizeConfidence(raw.confidence, source, raw.metadata);

    const fingerprint =
      raw.fingerprint ||
      generateStableFingerprint({
        source,
        ruleId,
        file,
        line,
        snippet,
        category,
        cwe,
        title,
        packageName: raw.packageName,
        advisoryId: raw.advisoryId,
      });

    const distinction: FindingDistinction = isAI
      ? 'ai_suggested_finding'
      : 'confirmed_scanner_finding';

    const sourceRecord: ContributingSource = {
      source,
      ruleId,
      severity,
      confidence,
      detectedAt: new Date().toISOString(),
      snippet,
      cwe,
      metadata: raw.metadata,
    };

    const aiInsights = isAI
      ? {
          reasoningSummary:
            (raw.metadata?.reasoningSummary as string) ||
            (raw.metadata?.reasoning_summary as string) ||
            description,
          suggestedRemediation: remediation,
          confidence,
          suggestedSeverity: severity,
          model: raw.metadata?.model as string | undefined,
          provider: raw.metadata?.provider as string | undefined,
        }
      : undefined;

    return {
      id: fingerprint,
      fingerprint,
      scanId: scanId || (raw.scanId as string | undefined),
      ruleId,
      category,
      severity,
      title,
      description,
      confidence,
      distinction,
      file,
      line,
      endLine,
      snippet,
      cwe,
      remediation,
      contributingSources: [source],
      sources: [sourceRecord],
      aiInsights,
      metadata: raw.metadata || {},
    };
  }

  /**
   * Processes, normalizes, and deduplicates findings from multiple sources:
   * Semgrep, Gitleaks, Dependency, and AI Analyzer.
   *
   * Invariants guaranteed:
   * 1. Deterministic scanner findings are authoritative.
   * 2. AI findings NEVER overwrite deterministic scanner findings.
   * 3. All contributing sources and scanner metadata are preserved.
   * 4. Correlated findings (Scanner + AI or multi-scanner) are clearly distinguished.
   * 5. Confidences are combined probabilistically.
   */
  processFindings(inputs: EngineProcessInputs): EngineDeduplicationResult {
    const rawList: { finding: FindingInput; source: string }[] = [];

    if (inputs.semgrepFindings) {
      for (const f of inputs.semgrepFindings) rawList.push({ finding: f, source: 'semgrep' });
    }
    if (inputs.gitleaksFindings) {
      for (const f of inputs.gitleaksFindings) rawList.push({ finding: f, source: 'gitleaks' });
    }
    if (inputs.dependencyFindings) {
      for (const f of inputs.dependencyFindings) rawList.push({ finding: f, source: 'dependency' });
    }
    if (inputs.aiFindings) {
      for (const f of inputs.aiFindings) rawList.push({ finding: f, source: 'ai-analyzer' });
    }
    if (inputs.allFindings) {
      for (const f of inputs.allFindings) {
        rawList.push({ finding: f, source: (f.source as string) || 'unknown' });
      }
    }

    const totalRawFindings = rawList.length;

    // Normalize each finding into initial shape
    const normalizedList: UnifiedFinding[] = rawList.map((item) =>
      this.normalizeSingleFinding(item.finding, item.source, inputs.scanId),
    );

    // CRITICAL ARCHITECTURE RULE: Process deterministic scanner findings first!
    // This establishes the authoritative baseline before processing AI suggestions.
    const deterministicFindings = normalizedList.filter(
      (f) => f.distinction === 'confirmed_scanner_finding',
    );
    const aiFindings = normalizedList.filter(
      (f) => f.distinction === 'ai_suggested_finding',
    );

    const unifiedPool: UnifiedFinding[] = [];
    let duplicatesRemoved = 0;

    // Phase 1: Ingest Deterministic Scanner Findings
    for (const incoming of deterministicFindings) {
      const matchIndex = this.findMatchingIndex(unifiedPool, incoming);

      if (matchIndex === -1) {
        unifiedPool.push(incoming);
      } else {
        // Merge with existing deterministic finding
        duplicatesRemoved++;
        unifiedPool[matchIndex] = this.mergeDeterministicWithDeterministic(
          unifiedPool[matchIndex]!,
          incoming,
        );
      }
    }

    // Phase 2: Ingest AI Findings (Correlate or Add as AI-Suggested)
    for (const incoming of aiFindings) {
      const matchIndex = this.findMatchingIndex(unifiedPool, incoming);

      if (matchIndex === -1) {
        // Pure AI suggestion — no deterministic scanner caught this
        unifiedPool.push(incoming);
      } else {
        // Correlated! The AI has found/corroborated an existing deterministic finding
        duplicatesRemoved++;
        unifiedPool[matchIndex] = this.correlateAIFinding(
          unifiedPool[matchIndex]!,
          incoming,
        );
      }
    }

    // Build Category and Severity Breakdown Maps
    const byCategory = this.createEmptyCategoryBreakdown();
    const bySeverity = this.createEmptySeverityBreakdown();

    let correlatedCount = 0;
    let confirmedCount = 0;
    let aiSuggestedCount = 0;

    for (const f of unifiedPool) {
      byCategory[f.category] = (byCategory[f.category] || 0) + 1;
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;

      if (f.distinction === 'correlated_finding') correlatedCount++;
      else if (f.distinction === 'confirmed_scanner_finding') confirmedCount++;
      else if (f.distinction === 'ai_suggested_finding') aiSuggestedCount++;
    }

    return {
      unifiedFindings: unifiedPool,
      totalRawFindings,
      uniqueFindingsCount: unifiedPool.length,
      duplicatesRemoved,
      correlatedFindingsCount: correlatedCount,
      confirmedScannerCount: confirmedCount,
      aiSuggestedCount,
      byCategory,
      bySeverity,
    };
  }

  /**
   * Finds the index of a matching or correlated finding in the pool.
   */
  private findMatchingIndex(pool: readonly UnifiedFinding[], target: UnifiedFinding): number {
    for (let i = 0; i < pool.length; i++) {
      const existing = pool[i]!;

      // 1. Exact fingerprint match
      if (existing.fingerprint === target.fingerprint) {
        return i;
      }

      // 2. Cross-source correlation (same file, nearby line, same category or rule)
      if (areFindingsCorrelated(existing, target)) {
        return i;
      }
    }
    return -1;
  }

  /**
   * Merges two deterministic findings (e.g. Semgrep and ESLint, or duplicate runs).
   */
  private mergeDeterministicWithDeterministic(
    existing: UnifiedFinding,
    incoming: UnifiedFinding,
  ): UnifiedFinding {
    const combinedConfidence = combineConfidence(existing.confidence, incoming.confidence);
    const resolvedSeverity = maxSeverity(existing.severity, incoming.severity);

    // Merge contributing sources list
    const sourceSet = new Set([...existing.contributingSources, ...incoming.contributingSources]);

    // Append to detailed source audit list
    const sources = [...existing.sources, ...incoming.sources];

    return {
      ...existing,
      severity: resolvedSeverity,
      confidence: combinedConfidence,
      remediation: existing.remediation || incoming.remediation,
      cwe: existing.cwe || incoming.cwe,
      snippet: existing.snippet || incoming.snippet,
      contributingSources: Array.from(sourceSet),
      sources,
      metadata: { ...existing.metadata, ...incoming.metadata },
    };
  }

  /**
   * Correlates an AI finding with an existing deterministic finding.
   *
   * STRICT INVARIANT:
   * Never allow an AI finding to overwrite a deterministic scanner finding.
   * - Deterministic severity is PRESERVED.
   * - Deterministic ruleId, file, line, and category are PRESERVED.
   * - AI contributes: aiInsights, suggestedRemediation, and corroborating confidence.
   * - Finding distinction flips to 'correlated_finding'.
   */
  private correlateAIFinding(
    deterministic: UnifiedFinding,
    ai: UnifiedFinding,
  ): UnifiedFinding {
    // Corroboration increases total confidence
    const combinedConfidence = combineConfidence(deterministic.confidence, ai.confidence);

    const sourceSet = new Set([...deterministic.contributingSources, ...ai.contributingSources]);
    const sources = [...deterministic.sources, ...ai.sources];

    // Combine or enrich remediation
    const remediation = deterministic.remediation || ai.remediation;

    return {
      ...deterministic, // Keep deterministic authority as base!
      distinction: 'correlated_finding',
      confidence: combinedConfidence,
      remediation,
      contributingSources: Array.from(sourceSet),
      sources,
      aiInsights: {
        reasoningSummary:
          ai.aiInsights?.reasoningSummary || ai.description,
        suggestedRemediation: ai.remediation,
        confidence: ai.confidence,
        suggestedSeverity: ai.severity, // Record what AI suggested, without overwriting deterministic severity
        model: ai.aiInsights?.model,
        provider: ai.aiInsights?.provider,
      },
    };
  }

  private isAISource(source: string, raw: FindingInput): boolean {
    const s = source.toLowerCase();
    if (s === 'ai-analyzer' || s === 'ai' || s === 'llm' || s === 'ai-reasoning') {
      return true;
    }
    if (raw.category === 'ai-reasoning') {
      return true;
    }
    return false;
  }

  private createEmptyCategoryBreakdown(): Record<NormalizedCategory, number> {
    const acc = {} as Record<NormalizedCategory, number>;
    for (const cat of NORMALIZED_CATEGORIES) {
      acc[cat] = 0;
    }
    return acc;
  }

  private createEmptySeverityBreakdown(): Record<NormalizedSeverity, number> {
    const acc = {} as Record<NormalizedSeverity, number>;
    for (const sev of NORMALIZED_SEVERITIES) {
      acc[sev] = 0;
    }
    return acc;
  }
}

export const defaultFindingNormalizerEngine = new FindingNormalizerEngine();
