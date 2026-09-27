import type { ScannerId, ScanFinding, NormalizedFinding } from '@aishield/shared';

export interface ScannerExecutionContext {
  scanId: string;
  repoPath: string;
  baseCommit?: string;
  targetCommit?: string;
  changedFiles?: string[];
  timeoutMs?: number;
  diffContent?: string;
  deterministicFindings?: NormalizedFinding[];
}

export interface ScannerExecutionResult {
  scanner: ScannerId;
  status: 'succeeded' | 'failed' | 'skipped';
  durationMs: number;
  findings: (ScanFinding | NormalizedFinding)[];
  error?: string;
}

export interface IScannerRunner {
  readonly id: ScannerId;
  readonly displayName: string;
  execute(ctx: ScannerExecutionContext): Promise<ScannerExecutionResult>;
}
