import path from 'node:path';
import type { NormalizedFinding, Severity } from '@aishield/shared';
import { workerEnv } from '../config/env.js';
import { BaseSecurityScanner, generateFingerprint } from './base-scanner.js';
import { defaultCommandExecutor } from './command-executor.js';
import type { CommandExecutor, ScanOptions } from './types.js';

export interface SemgrepScannerOptions {
  /**
   * Execution runner mode:
   * - 'docker': Run Semgrep container with dropped privileges and read-only volume mount.
   * - 'local': Run local semgrep CLI executable directly.
   * Defaults to workerEnv.SCANNER_RUNNER or 'docker'.
   */
  readonly runner?: 'docker' | 'local';

  /**
   * Docker image to use when runner is 'docker'.
   * Defaults to workerEnv.SCANNER_IMAGE_SEMGREP or 'returntocorp/semgrep:1.78.0'.
   */
  readonly dockerImage?: string;

  /**
   * Security rule packs to use (e.g. ['p/security-audit', 'p/owasp-top-ten']).
   * Defaults to workerEnv.SEMGREP_RULES split by comma or ['p/security-audit', 'p/owasp-top-ten'].
   */
  readonly rules?: readonly string[];

  /**
   * Optional custom local rule file paths or directories.
   */
  readonly customRulePaths?: readonly string[];

  /**
   * Network mode for Docker runner ('none' | 'bridge' | 'host').
   * Defaults to 'none' for maximum security and network isolation during static analysis.
   */
  readonly dockerNetwork?: string;

  /**
   * Custom command executor for dependency injection and testing.
   */
  readonly executor?: CommandExecutor;
}

interface SemgrepResultItem {
  check_id: string;
  path: string;
  start: { line: number; col?: number; offset?: number };
  end?: { line: number; col?: number; offset?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    fix?: string;
    metadata?: {
      cwe?: string | string[] | number;
      owasp?: string | string[];
      confidence?: string;
      category?: string;
      impact?: string;
      likelihood?: string;
      shortlink?: string;
      references?: string[];
      technology?: string[];
      fix?: string;
      [key: string]: unknown;
    };
  };
}

interface SemgrepOutput {
  results?: SemgrepResultItem[];
  errors?: unknown[];
  version?: string;
  paths?: {
    scanned?: string[];
    skipped?: unknown[];
  };
}

/** High-risk CWEs that escalate ERROR severity findings to 'critical' */
const CRITICAL_CWES = new Set([
  'CWE-89', // SQL Injection
  'CWE-78', // OS Command Injection
  'CWE-95', // Eval / Dynamic Code Injection
  'CWE-94', // General Code Injection
  'CWE-502', // Deserialization of Untrusted Data
  'CWE-22', // Path Traversal
  'CWE-23', // Relative Path Traversal
  'CWE-918', // Server-Side Request Forgery (SSRF)
  'CWE-798', // Use of Hard-coded Credentials
  'CWE-287', // Improper Authentication
  'CWE-306', // Missing Authentication
]);

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
  while (cleaned.startsWith('./') || cleaned.startsWith('../')) {
    cleaned = cleaned.replace(/^\.?\.\//, '');
  }
  return cleaned;
}

/**
 * Robust extractor for CWE identifier across various Semgrep metadata formats.
 * Handles strings, arrays of strings, and numeric IDs.
 */
function extractCwe(rawCwe: unknown): string | undefined {
  if (!rawCwe) return undefined;

  if (typeof rawCwe === 'string') {
    const match = rawCwe.match(/CWE-(\d+)/i);
    return match ? `CWE-${match[1]}` : undefined;
  }

  if (Array.isArray(rawCwe)) {
    for (const item of rawCwe) {
      const extracted = extractCwe(item);
      if (extracted) return extracted;
    }
  }

  if (typeof rawCwe === 'number') {
    return `CWE-${rawCwe}`;
  }

  return undefined;
}

export class SemgrepScanner extends BaseSecurityScanner {
  readonly runner: 'docker' | 'local';
  readonly dockerImage: string;
  readonly rules: readonly string[];
  readonly customRulePaths: readonly string[];
  readonly dockerNetwork: string;

  constructor(optionsOrExecutor: SemgrepScannerOptions | CommandExecutor = {}) {
    let executor: CommandExecutor = defaultCommandExecutor;
    let options: SemgrepScannerOptions = {};

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
    this.dockerImage = options.dockerImage ?? workerEnv.SCANNER_IMAGE_SEMGREP ?? 'returntocorp/semgrep:1.78.0';

    if (options.rules && options.rules.length > 0) {
      this.rules = options.rules;
    } else if (workerEnv.SEMGREP_RULES) {
      this.rules = workerEnv.SEMGREP_RULES.split(',')
        .map((r) => r.trim())
        .filter(Boolean);
    } else {
      this.rules = ['p/security-audit', 'p/owasp-top-ten'];
    }

    this.customRulePaths = options.customRulePaths ?? [];
    this.dockerNetwork = options.dockerNetwork ?? 'none';
  }

  getName(): string {
    return 'semgrep';
  }

  getDisplayName(): string {
    return 'Semgrep SAST Scanner';
  }

  protected getVersionArgs(): { command: string; args: string[] } {
    if (this.runner === 'docker') {
      return {
        command: 'docker',
        args: ['run', '--rm', this.dockerImage, 'semgrep', '--version'],
      };
    }
    return {
      command: 'semgrep',
      args: ['--version'],
    };
  }

  protected buildCommand(options: ScanOptions): { command: string; args: string[] } {
    const activeRunner = options.runner ?? this.runner;
    const activeRules = options.rules ?? this.rules;

    if (activeRunner === 'docker') {
      const normalizedPath = path.resolve(options.targetPath).replace(/\\/g, '/');
      const args: string[] = [
        'run',
        '--rm',
        '--network',
        this.dockerNetwork,
        '--cap-drop=ALL',
        '--security-opt=no-new-privileges',
        '--pids-limit=200',
        '--memory=2g',
        '--cpus=2',
        '-v',
        `${normalizedPath}:/src:ro`,
        '-w',
        '/src',
      ];

      // Mount any local custom rule files read-only
      for (let i = 0; i < this.customRulePaths.length; i++) {
        const localRule = path.resolve(this.customRulePaths[i]!).replace(/\\/g, '/');
        args.push('-v', `${localRule}:/rules/custom_${i}.yml:ro`);
      }

      args.push(
        this.dockerImage,
        'semgrep',
        'scan',
        '--json',
        '--quiet',
        '--metrics=off',
        '--disable-version-check',
      );

      // Append standard / registry rule packs
      for (const rule of activeRules) {
        args.push('--config', rule);
      }

      // Append mounted custom rule paths
      for (let i = 0; i < this.customRulePaths.length; i++) {
        args.push('--config', `/rules/custom_${i}.yml`);
      }

      // PR Changed Files: Only scan files modified by the Pull Request
      if (options.changedFiles && options.changedFiles.length > 0) {
        for (const file of options.changedFiles) {
          const cleaned = cleanFilePath(file);
          if (cleaned && !cleaned.startsWith('-')) {
            args.push('--include', cleaned);
          }
        }
      }

      // Container positional target directory
      args.push('/src');

      return { command: 'docker', args };
    }

    // Local CLI execution runner
    const args: string[] = [
      'scan',
      '--json',
      '--quiet',
      '--metrics=off',
      '--disable-version-check',
    ];

    for (const rule of activeRules) {
      args.push('--config', rule);
    }

    for (const customRule of this.customRulePaths) {
      args.push('--config', customRule);
    }

    // PR Changed Files: Only scan files modified by the Pull Request
    if (options.changedFiles && options.changedFiles.length > 0) {
      for (const file of options.changedFiles) {
        args.push('--include', file.replace(/\\/g, '/'));
      }
    }

    args.push(options.targetPath);

    return { command: 'semgrep', args };
  }

  normalizeResult(rawOutput: unknown, _options?: ScanOptions): NormalizedFinding[] {
    if (!rawOutput || typeof rawOutput !== 'object') {
      return [];
    }

    const data = rawOutput as SemgrepOutput;

    // Log diagnostic warning if Semgrep encountered syntax or analysis errors in scanned files
    if (Array.isArray(data.errors) && data.errors.length > 0) {
      this.log.warn(
        { errorCount: data.errors.length, sampleError: data.errors[0] },
        'Semgrep reported analysis errors in parsed files',
      );
    }

    const results = Array.isArray(data.results) ? data.results : [];
    const normalized: NormalizedFinding[] = [];

    for (const item of results) {
      if (!item.check_id || !item.path) {
        continue;
      }

      const ruleId = item.check_id;
      const file = cleanFilePath(item.path);
      const line = item.start?.line ?? 1;
      const endLine = item.end?.line;
      const message = item.extra?.message?.trim() || `Finding detected by rule ${ruleId}`;
      const codeSnippet = item.extra?.lines?.trim();

      // Extract standardized CWE ID (e.g. "CWE-89")
      const cwe = extractCwe(item.extra?.metadata?.cwe);

      // Determine category (security, secret, debt, dependency)
      let category: 'security' | 'secret' | 'dependency' | 'debt' = 'security';
      const rawCategory = typeof item.extra?.metadata?.category === 'string'
        ? item.extra.metadata.category.toLowerCase()
        : '';
      const checkIdLower = ruleId.toLowerCase();

      if (
        rawCategory === 'maintainability' ||
        rawCategory === 'best-practice' ||
        rawCategory === 'debt'
      ) {
        category = 'debt';
      } else if (
        rawCategory === 'secret' ||
        checkIdLower.includes('secret') ||
        checkIdLower.includes('token') ||
        checkIdLower.includes('credential') ||
        checkIdLower.includes('password')
      ) {
        category = 'secret';
      } else if (rawCategory === 'dependency' || checkIdLower.includes('dependency')) {
        category = 'dependency';
      }

      // Map severity according to impact and CWE criticality
      const rawSeverity = (item.extra?.severity || 'WARNING').toUpperCase();
      const impact = typeof item.extra?.metadata?.impact === 'string'
        ? item.extra.metadata.impact.toUpperCase()
        : '';
      const likelihood = typeof item.extra?.metadata?.likelihood === 'string'
        ? item.extra.metadata.likelihood.toUpperCase()
        : '';

      let severity: Severity;
      if (rawSeverity === 'ERROR') {
        const isCriticalCwe = cwe && CRITICAL_CWES.has(cwe);
        const isCriticalImpact = impact === 'HIGH' && likelihood === 'HIGH';
        severity = isCriticalCwe || isCriticalImpact ? 'critical' : 'high';
      } else if (rawSeverity === 'WARNING') {
        severity = impact === 'HIGH' ? 'high' : 'medium';
      } else if (rawSeverity === 'INFO') {
        severity = category === 'debt' ? 'low' : 'low';
      } else {
        severity = 'info';
      }

      // Map confidence score (0.0 to 1.0)
      let confidence = 0.85;
      const rawConf = typeof item.extra?.metadata?.confidence === 'string'
        ? item.extra.metadata.confidence.toUpperCase()
        : '';
      if (rawConf === 'HIGH') confidence = 0.95;
      else if (rawConf === 'MEDIUM') confidence = 0.75;
      else if (rawConf === 'LOW') confidence = 0.5;

      // Extract or construct remediation guidance
      let remediation: string;
      if (item.extra?.fix && typeof item.extra.fix === 'string' && item.extra.fix.trim().length > 0) {
        remediation = item.extra.fix.trim();
      } else if (
        item.extra?.metadata?.fix &&
        typeof item.extra.metadata.fix === 'string' &&
        item.extra.metadata.fix.trim().length > 0
      ) {
        remediation = item.extra.metadata.fix.trim();
      } else if (
        item.extra?.metadata?.shortlink &&
        typeof item.extra.metadata.shortlink === 'string'
      ) {
        remediation = `Review and remediate according to Semgrep rule documentation: ${item.extra.metadata.shortlink}`;
      } else if (
        Array.isArray(item.extra?.metadata?.references) &&
        item.extra.metadata.references.length > 0 &&
        typeof item.extra.metadata.references[0] === 'string'
      ) {
        remediation = `Review secure coding guidelines: ${item.extra.metadata.references[0]}`;
      } else {
        remediation = `Review code and adhere to secure coding guidelines for rule ${ruleId}.`;
      }

      const fingerprint = generateFingerprint(ruleId, file, codeSnippet || String(line));

      normalized.push({
        source: this.getName(),
        ruleId,
        category,
        title: message.split('\n')[0] || ruleId,
        description: message,
        severity,
        confidence,
        file,
        line,
        endLine,
        cwe,
        fingerprint,
        remediation,
        metadata: {
          owasp: item.extra?.metadata?.owasp,
          rawSeverity: item.extra?.severity,
          impact: item.extra?.metadata?.impact,
          likelihood: item.extra?.metadata?.likelihood,
          confidence: item.extra?.metadata?.confidence,
          shortlink: item.extra?.metadata?.shortlink,
          references: item.extra?.metadata?.references,
          technology: item.extra?.metadata?.technology,
          ruleMetadata: item.extra?.metadata,
          codeSnippet,
        },
      });
    }

    return normalized;
  }
}
