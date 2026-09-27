import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import type { Logger } from 'pino';
import type { NormalizedFinding } from '@aishield/shared';
import { childLogger } from '../logging/logger.js';
import { defaultCommandExecutor } from './command-executor.js';
import type { SecurityScanner } from './security-scanner.interface.js';
import type { CommandExecutor, ScanOptions, ScannerResultEnvelope } from './types.js';

/**
 * Standard utility to generate stable, cross-platform finding fingerprints.
 */
export function generateFingerprint(ruleId: string, filePath: string, context?: string): string {
  const normalizedPath = filePath.replace(/\\/g, '/');
  const normalizedContext = (context || '').trim().replace(/\s+/g, ' ');
  return createHash('sha256')
    .update(`${ruleId}:${normalizedPath}:${normalizedContext}`)
    .digest('hex');
}

export abstract class BaseSecurityScanner implements SecurityScanner {
  protected readonly executor: CommandExecutor;
  protected readonly log: Logger;
  protected cachedVersion: string | null = null;

  constructor(executor: CommandExecutor = defaultCommandExecutor) {
    this.executor = executor;
    this.log = childLogger({ scanner: this.getName() });
  }

  abstract getName(): string;
  abstract getDisplayName(): string;

  /** Constructs the CLI command and arguments for this scanner engine. */
  protected abstract buildCommand(options: ScanOptions): { command: string; args: string[] };

  /** Concrete version probe command (e.g. ['--version']). */
  protected abstract getVersionArgs(): { command: string; args: string[] };

  abstract normalizeResult(rawOutput: unknown, options?: ScanOptions): NormalizedFinding[];

  async getVersion(): Promise<string> {
    if (this.cachedVersion) {
      return this.cachedVersion;
    }

    try {
      const { command, args } = this.getVersionArgs();
      const res = await this.executor(command, args, { cwd: process.cwd(), timeoutMs: 5000 });
      const versionOutput = (res.stdout || res.stderr).trim().split('\n')[0] || 'unknown';
      this.cachedVersion = versionOutput;
      return versionOutput;
    } catch {
      return 'unknown';
    }
  }

  async scan(options: ScanOptions): Promise<ScannerResultEnvelope> {
    const started = Date.now();
    const timeoutMs = options.timeoutMs ?? 120_000;

    // Validate target repository path existence if requested or using default executor
    const shouldValidatePath = options.validateTargetPath ?? (this.executor === defaultCommandExecutor);
    if (shouldValidatePath && (!options.targetPath || !existsSync(options.targetPath))) {
      const errorMsg = `Target repository path does not exist or is not accessible: ${options.targetPath}`;
      this.log.error({ targetPath: options.targetPath }, errorMsg);
      return {
        scanner: this.getName(),
        status: 'failed',
        durationMs: 0,
        findings: [],
        error: errorMsg,
      };
    }

    this.log.info({ targetPath: options.targetPath, timeoutMs }, 'Starting scanner execution');

    // Create an internal timeout abort controller if none was provided
    const abortController = new AbortController();
    const timer = setTimeout(() => {
      abortController.abort(new Error(`Scanner ${this.getName()} timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    // If caller provided an external signal, propagate it
    if (options.signal) {
      options.signal.addEventListener('abort', () => abortController.abort(options.signal?.reason));
    }

    try {
      const { command, args } = this.buildCommand(options);

      const commandResult = await this.executor(command, args, {
        cwd: options.targetPath,
        timeoutMs,
        signal: abortController.signal,
      });

      const durationMs = Date.now() - started;

      // Exit code >= 2 indicates an execution error / engine crash / invalid syntax
      if (commandResult.exitCode >= 2) {
        const errorDetail = (commandResult.stderr || commandResult.stdout || '').trim();
        this.log.error(
          { durationMs, exitCode: commandResult.exitCode, errorDetail },
          'Scanner process failed with error exit code >= 2',
        );
        return {
          scanner: this.getName(),
          status: 'failed',
          durationMs,
          findings: [],
          error: `Scanner process failed with exit code ${commandResult.exitCode}${errorDetail ? `: ${errorDetail}` : ''}`,
        };
      }

      let parsedJson: unknown;
      try {
        parsedJson = commandResult.stdout.trim() ? JSON.parse(commandResult.stdout) : null;
      } catch (parseError) {
        // If stdout is not JSON, check stderr or return error
        const errorDetail = (commandResult.stderr || '').trim();
        this.log.warn(
          { durationMs, exitCode: commandResult.exitCode, err: parseError, errorDetail },
          'Failed to parse scanner output as JSON',
        );
        return {
          scanner: this.getName(),
          status: 'failed',
          durationMs,
          findings: [],
          error: `Failed to parse scanner output as JSON: ${String(parseError)}${errorDetail ? ` (stderr: ${errorDetail})` : ''}`,
        };
      }

      const findings = this.normalizeResult(parsedJson, options);

      this.log.info(
        { durationMs, findingCount: findings.length, exitCode: commandResult.exitCode },
        'Scanner execution succeeded',
      );

      return {
        scanner: this.getName(),
        status: 'succeeded',
        durationMs,
        findings,
        rawOutput: parsedJson,
      };
    } catch (err: unknown) {
      const durationMs = Date.now() - started;
      const isNotFound =
        (err as { code?: string })?.code === 'ENOENT' ||
        String(err).includes('ENOENT');
      const errorMessage = isNotFound
        ? `Scanner executable '${this.getName()}' is not installed or not found in PATH`
        : err instanceof Error ? err.message : String(err);

      this.log.error({ durationMs, error: errorMessage }, 'Scanner execution failed');

      // Return a failed envelope instead of letting an unhandled error crash the application
      return {
        scanner: this.getName(),
        status: 'failed',
        durationMs,
        findings: [],
        error: errorMessage,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}
