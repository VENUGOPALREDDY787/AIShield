import type { NormalizedFinding } from '@aishield/shared';
import type { ScanOptions, ScannerResultEnvelope } from './types.js';

/**
 * Common abstraction for all security scanner engines.
 *
 * The rest of the codebase interacts strictly through this contract and has
 * zero direct dependencies on scanner CLI flags or vendor-specific output schemas.
 */
export interface SecurityScanner {
  /** Machine identifier of the scanner (e.g. 'semgrep', 'gitleaks', 'dependency'). */
  getName(): string;

  /** Human-readable display title (e.g. 'Semgrep SAST Scanner'). */
  getDisplayName(): string;

  /** Queries or detects the current scanner binary/engine version. */
  getVersion(): Promise<string>;

  /** Executes scan against the target options, tolerating failures and returning a normalized envelope. */
  scan(options: ScanOptions): Promise<ScannerResultEnvelope>;

  /** Pure function converting raw scanner stdout/JSON into normalized findings. */
  normalizeResult(rawOutput: unknown, options?: ScanOptions): NormalizedFinding[];
}
