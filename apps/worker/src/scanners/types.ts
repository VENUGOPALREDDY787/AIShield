import type { NormalizedFinding } from '@aishield/shared';

export interface ScanOptions {
  /** Root directory of the repository or checked-out code to scan. */
  readonly targetPath: string;
  /** Starting git commit SHA (for diff / history scans). */
  readonly baseCommit?: string;
  /** Ending git commit SHA. */
  readonly targetCommit?: string;
  /** Timeout in milliseconds for this scanner run. */
  readonly timeoutMs?: number;
  /** Restricted set of changed files to scan. */
  readonly changedFiles?: readonly string[];
  /** Optional cancellation signal. */
  readonly signal?: AbortSignal;
  /** Whether to explicitly validate that targetPath exists on disk. */
  readonly validateTargetPath?: boolean;
  /** Scanner rule overrides for this specific scan run. */
  readonly rules?: readonly string[];
  /** Runner override ('docker' | 'local') for this scan. */
  readonly runner?: 'docker' | 'local';
}

export interface ScannerResultEnvelope {
  readonly scanner: string;
  readonly status: 'succeeded' | 'failed' | 'skipped';
  readonly durationMs: number;
  readonly findings: readonly NormalizedFinding[];
  readonly rawOutput?: unknown;
  readonly error?: string;
}

export interface CommandResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: number;
}

export interface CommandExecutionOptions {
  readonly cwd: string;
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
}

export type CommandExecutor = (
  command: string,
  args: string[],
  options: CommandExecutionOptions,
) => Promise<CommandResult>;
