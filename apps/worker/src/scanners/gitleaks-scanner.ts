import path from 'node:path';
import type { NormalizedFinding } from '@aishield/shared';
import {
  formatPrSecretAlert,
  generateSecretFingerprint,
  hashSecret,
  maskSecret,
} from '@aishield/shared';
import { workerEnv } from '../config/env.js';
import { BaseSecurityScanner } from './base-scanner.js';
import { defaultCommandExecutor } from './command-executor.js';
import type { CommandExecutor, ScanOptions } from './types.js';

export interface GitleaksScannerOptions {
  /** Execution runner mode: 'docker' or 'local'. Defaults to workerEnv.SCANNER_RUNNER or 'docker'. */
  readonly runner?: 'docker' | 'local';

  /** Docker image to run when in container mode. Defaults to workerEnv.SCANNER_IMAGE_GITLEAKS or 'zricethezav/gitleaks:v8.18.2'. */
  readonly dockerImage?: string;

  /** Optional custom Gitleaks configuration file path. Defaults to workerEnv.GITLEAKS_CONFIG_PATH. */
  readonly configPath?: string;

  /** Custom command executor for dependency injection and testing. */
  readonly executor?: CommandExecutor;
}

interface GitleaksResultItem {
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  StartColumn?: number;
  EndColumn?: number;
  Match?: string;
  Secret?: string;
  File?: string;
  SymlinkFile?: string;
  Commit?: string;
  Entropy?: number;
  Author?: string;
  Email?: string;
  Date?: string;
  Message?: string;
  RuleID?: string;
  Fingerprint?: string;
}

/**
 * Normalizes file path across platforms and removes Docker container volume prefixes (/src/).
 */
function cleanFilePath(rawPath: string): string {
  let cleaned = rawPath.replace(/\\/g, '/').trim();
  if (cleaned.startsWith('/src/')) {
    cleaned = cleaned.slice(5);
  } else if (cleaned.startsWith('/src')) {
    cleaned = cleaned.slice(4);
  }
  if (cleaned.startsWith('./')) {
    cleaned = cleaned.slice(2);
  }
  return cleaned;
}

export class GitleaksScanner extends BaseSecurityScanner {
  readonly runner: 'docker' | 'local';
  readonly dockerImage: string;
  readonly configPath?: string;

  constructor(optionsOrExecutor: GitleaksScannerOptions | CommandExecutor = {}) {
    let executor: CommandExecutor = defaultCommandExecutor;
    let options: GitleaksScannerOptions = {};

    if (typeof optionsOrExecutor === 'function') {
      executor = optionsOrExecutor;
    } else if (optionsOrExecutor) {
      options = optionsOrExecutor;
      if (options.executor) {
        executor = options.executor;
      }
    }

    super(executor);

    this.runner = options.runner ?? workerEnv.SCANNER_RUNNER ?? 'docker';
    this.dockerImage = options.dockerImage ?? workerEnv.SCANNER_IMAGE_GITLEAKS ?? 'zricethezav/gitleaks:v8.18.2';
    this.configPath = options.configPath ?? workerEnv.GITLEAKS_CONFIG_PATH;
  }

  getName(): string {
    return 'gitleaks';
  }

  getDisplayName(): string {
    return 'Gitleaks Secret Scanner';
  }

  protected getVersionArgs(): { command: string; args: string[] } {
    if (this.runner === 'docker') {
      return {
        command: 'docker',
        args: ['run', '--rm', this.dockerImage, 'version'],
      };
    }
    return {
      command: 'gitleaks',
      args: ['version'],
    };
  }

  protected buildCommand(options: ScanOptions): { command: string; args: string[] } {
    const activeRunner = options.runner ?? this.runner;

    if (activeRunner === 'docker') {
      const normalizedTargetPath = path.resolve(options.targetPath).replace(/\\/g, '/');
      const args: string[] = [
        'run',
        '--rm',
        '--network',
        'none',
        '--cap-drop=ALL',
        '--security-opt=no-new-privileges',
        '--pids-limit=200',
        '--memory=2g',
        '--cpus=2',
        '-v',
        `${normalizedTargetPath}:/src:ro`,
        '-w',
        '/src',
      ];

      // Mount custom config if provided
      if (this.configPath) {
        const normalizedConfig = path.resolve(this.configPath).replace(/\\/g, '/');
        args.push('-v', `${normalizedConfig}:/gitleaks.toml:ro`);
      }

      args.push(
        this.dockerImage,
        'detect',
        '--no-banner',
        '--report-format=json',
        '--report-path=/dev/stdout',
      );

      if (this.configPath) {
        args.push('--config=/gitleaks.toml');
      }

      // PR Scope: scan commits in the Pull Request delta (validated against flag injection)
      if (
        options.baseCommit &&
        options.targetCommit &&
        !options.baseCommit.startsWith('-') &&
        !options.targetCommit.startsWith('-')
      ) {
        args.push(`--log-opts=${options.baseCommit}..${options.targetCommit}`);
      }

      args.push('--source=/src');

      return { command: 'docker', args };
    }

    // Local runner
    const args: string[] = [
      'detect',
      '--no-banner',
      '--report-format=json',
      '--report-path=/dev/stdout',
    ];

    if (this.configPath) {
      args.push(`--config=${this.configPath}`);
    }

    // PR Scope: scan commits in the Pull Request delta
    if (options.baseCommit && options.targetCommit) {
      args.push(`--log-opts=${options.baseCommit}..${options.targetCommit}`);
    }

    args.push(`--source=${options.targetPath}`);

    return { command: 'gitleaks', args };
  }

  normalizeResult(rawOutput: unknown, options?: ScanOptions): NormalizedFinding[] {
    if (!rawOutput) {
      return [];
    }

    const items: GitleaksResultItem[] = Array.isArray(rawOutput) ? rawOutput : [];
    const normalized: NormalizedFinding[] = [];

    // Optional PR changed files filter
    const changedFilesSet =
      options?.changedFiles && options.changedFiles.length > 0
        ? new Set(options.changedFiles.map((f) => cleanFilePath(f)))
        : null;

    for (const item of items) {
      const ruleId = item.RuleID || 'generic-secret';
      const file = cleanFilePath(item.File || 'unknown');
      const line = item.StartLine ?? 1;
      const endLine = item.EndLine;
      const description = item.Description || 'Potential leaked secret or hardcoded credential detected';

      // If PR changed files are specified, only keep findings on those modified files
      if (changedFilesSet && !changedFilesSet.has(file)) {
        continue;
      }

      // CRITICAL SECURITY CONTROL:
      // Redact the raw secret immediately. Never store or expose plain secrets.
      const rawSecret = item.Secret || item.Match || '';
      const maskedSecret = maskSecret(rawSecret);
      const secretHash = hashSecret(rawSecret);

      // Invariant fingerprint that remains stable across line movements and branch rebases
      const fingerprint = generateSecretFingerprint(ruleId, file, secretHash);

      normalized.push({
        source: this.getName(),
        ruleId,
        category: 'secret',
        title: `Exposed Secret: ${description}`,
        description: `Hardcoded credential (${ruleId}) identified in ${file}:${line}`,
        severity: 'critical',
        confidence: 0.95,
        file,
        line,
        endLine,
        cwe: 'CWE-798',
        fingerprint,
        remediation:
          'Immediately revoke and rotate this secret. Remove it from git history and configure via environment variables or a secret manager.',
        metadata: {
          ruleId,
          description,
          commit: item.Commit,
          author: item.Author,
          date: item.Date,
          entropy: item.Entropy,
          maskedSecret,
          secretHash: secretHash || undefined,
        },
      });

      // Scrub the raw in-memory item so any downstream inspection of rawOutput never sees plain secrets
      if (item.Secret) item.Secret = maskedSecret;
      if (item.Match) item.Match = maskedSecret;
    }

    return normalized;
  }

  /**
   * Generates a safe Markdown PR comment for a secret finding with zero raw secrets.
   */
  formatPrComment(finding: NormalizedFinding): string {
    return formatPrSecretAlert({
      ruleId: finding.ruleId,
      file: finding.file,
      line: finding.line,
      description: finding.description,
      maskedSecret: (finding.metadata as { maskedSecret?: string })?.maskedSecret,
      secretHash: (finding.metadata as { secretHash?: string })?.secretHash,
    });
  }
}
