import type { ScannerId } from '../constants/scanners.js';
import type { ScannerStatus } from './scan.js';

/** Payload placed on the scan queue by the API or GitHub Action. */
export interface ScanJobData {
  readonly scanId: string;
  /** Repository URL or local workspace key the worker should materialise. */
  readonly repositoryUrl: string;
  /** Branch, tag or commit SHA to scan. */
  readonly ref: string;
  readonly commitSha?: string;
  readonly baseSha?: string;
  readonly branch?: string;
  readonly pullNumber?: number;
  readonly repositoryId?: string;
  readonly repoPath?: string;
  /** Engines to run, in the order the orchestrator should execute them. */
  readonly scanners: readonly ScannerId[];
  readonly requestedBy?: string;
  /** ISO-8601 timestamp set by the producer. */
  readonly requestedAt: string;
  readonly diffContent?: string;
  readonly githubToken?: string;
  readonly reportToGitHub?: boolean;
  readonly dashboardUrl?: string;
  readonly options?: ScanJobOptions;
}

export interface ScanJobOptions {
  /** Wall-clock budget for a single scanner. Falls back to `SCANNER_TIMEOUT_MS`. */
  readonly timeoutMs?: number;
  /** Restrict analysis to changed files where the engine supports it. */
  readonly diffOnly?: boolean;
  /** Free-form labels passed through to the scanners. */
  readonly labels?: Readonly<Record<string, string>>;
  readonly failOnCritical?: boolean;
  readonly failOnHigh?: boolean;
}

/** Returned by the worker when the job completes. */
export interface ScanJobResult {
  readonly scanId: string;
  readonly jobId?: string;
  readonly status: 'succeeded' | 'failed';
  readonly findingCount: number;
  readonly durationMs: number;
  readonly debtScore?: number;
  readonly riskLevel?: string;
  readonly componentStatuses?: Readonly<Record<string, ScannerStatus>>;
  readonly error?: string;
}

/** Emitted through `job.updateProgress()` so the UI can stream progress. */
export interface ScanJobProgress {
  readonly scanId: string;
  readonly scanner?: ScannerId;
  readonly completed: number;
  readonly total: number;
  readonly stage?: string;
  readonly message?: string;
}
