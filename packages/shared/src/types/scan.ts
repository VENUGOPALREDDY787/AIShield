import type { ScannerId } from '../constants/scanners.js';

/** Severity ladder, ordered most → least urgent. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Lifecycle of a single scan run. */
export const SCAN_STATUSES = ['queued', 'running', 'succeeded', 'failed', 'cancelled'] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

/** Outcome of one scanner inside a scan run. */
export const SCANNER_STATUSES = ['pending', 'running', 'succeeded', 'failed', 'skipped'] as const;
export type ScannerStatus = (typeof SCANNER_STATUSES)[number];

/**
 * What kind of problem a finding represents. Kept separate from severity so
 * the UI can group by origin ("secret leak" vs "outdated dependency").
 */
export const FINDING_CATEGORIES = [
  'security',
  'secret',
  'dependency',
  'debt',
  'ai-reasoning',
] as const;
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

export interface SourceLocation {
  readonly filePath: string;
  readonly startLine: number;
  readonly endLine?: number;
  /** Redacted by the producing scanner — never ship raw secrets in a report. */
  readonly snippet?: string;
}

/** One normalised issue. Every scanner maps its native output onto this shape. */
export interface ScanFinding {
  readonly id: string;
  readonly scanId: string;
  readonly scanner: ScannerId;
  readonly category: FindingCategory;
  readonly severity: Severity;
  readonly title: string;
  readonly description?: string;
  /** Native rule/vulnerability identifier, e.g. `javascript.lang.security.audit`. */
  readonly ruleId?: string;
  readonly location?: SourceLocation;
  readonly remediation?: string;
  /** 0–1. Populated by engines that emit confidence (notably the AI analyzer). */
  readonly confidence?: number;
  readonly metadata?: Readonly<Record<string, unknown>>;
}

/**
 * Standard normalized finding emitted by all scanner adapters.
 */
export interface NormalizedFinding {
  readonly source: ScannerId | string;
  readonly ruleId: string;
  readonly category: FindingCategory | string;
  readonly title: string;
  readonly description: string;
  readonly severity: Severity;
  readonly confidence: number;
  readonly file: string;
  readonly line: number;
  readonly endLine?: number;
  readonly cwe?: string;
  readonly fingerprint: string;
  readonly remediation?: string;
  readonly metadata: Readonly<Record<string, unknown>>;
}

export interface ScannerResult {
  readonly scanner: ScannerId;
  readonly status: ScannerStatus;
  readonly startedAt: string;
  readonly finishedAt?: string;
  readonly durationMs?: number;
  readonly findings: readonly ScanFinding[];
  /** Populated when `status` is `failed`. */
  readonly error?: string;
}

export interface ScanStats {
  readonly total: number;
  readonly bySeverity: Readonly<Record<Severity, number>>;
  readonly byScanner: Readonly<Record<string, number>>;
}

/** Aggregated result of a completed scan run. */
export interface ScanReport {
  readonly scanId: string;
  readonly repositoryUrl: string;
  readonly ref: string;
  readonly status: ScanStatus;
  readonly startedAt: string;
  readonly finishedAt?: string;
  readonly durationMs?: number;
  readonly scanners: readonly ScannerResult[];
  readonly findings: readonly ScanFinding[];
  readonly stats: ScanStats;
}

export function emptyScanStats(): ScanStats {
  return {
    total: 0,
    bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    byScanner: {},
  };
}
