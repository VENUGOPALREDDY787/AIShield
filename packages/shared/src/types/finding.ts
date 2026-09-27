import type { ScannerId } from '../constants/scanners.js';

/**
 * Standard normalized severities (uppercase) for all AIShield Debt findings.
 */
export const NORMALIZED_SEVERITIES = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'INFO',
] as const;

export type NormalizedSeverity = (typeof NORMALIZED_SEVERITIES)[number];

/**
 * Standard 12 finding categories.
 */
export const NORMALIZED_CATEGORIES = [
  'injection',
  'authentication',
  'authorization',
  'secrets',
  'cryptography',
  'data_exposure',
  'dependency',
  'input_validation',
  'command_execution',
  'configuration',
  'business_logic',
  'other',
] as const;

export type NormalizedCategory = (typeof NORMALIZED_CATEGORIES)[number];

/**
 * Distinction between deterministic scanner detections, AI suggestions, and cross-source correlations.
 */
export const FINDING_DISTINCTIONS = [
  'confirmed_scanner_finding',
  'ai_suggested_finding',
  'correlated_finding',
] as const;

export type FindingDistinction = (typeof FINDING_DISTINCTIONS)[number];

/**
 * Audit record of a single scanner or AI analyzer contributing to a finding.
 */
export interface ContributingSource {
  readonly source: ScannerId | string;
  readonly ruleId?: string;
  readonly severity: NormalizedSeverity;
  readonly confidence: number;
  readonly detectedAt?: string;
  readonly snippet?: string;
  readonly cwe?: string;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/**
 * Contextual insights contributed by AI analysis.
 */
export interface AIInsights {
  readonly reasoningSummary?: string;
  readonly suggestedRemediation?: string;
  readonly confidence?: number;
  readonly suggestedSeverity?: NormalizedSeverity;
  readonly model?: string;
  readonly provider?: string;
}

/**
 * Unified finding produced by the Finding Normalization and Deduplication Engine.
 */
export interface UnifiedFinding {
  readonly id: string;
  readonly fingerprint: string;
  readonly scanId?: string;
  readonly ruleId?: string;
  readonly category: NormalizedCategory;
  readonly severity: NormalizedSeverity;
  readonly title: string;
  readonly description: string;
  readonly confidence: number;
  readonly distinction: FindingDistinction;
  readonly file: string;
  readonly line: number;
  readonly endLine?: number;
  readonly snippet?: string;
  readonly cwe?: string;
  readonly remediation?: string;
  readonly contributingSources: readonly (ScannerId | string)[];
  readonly sources: readonly ContributingSource[];
  readonly aiInsights?: AIInsights;
  readonly metadata: Readonly<Record<string, unknown>>;
}
