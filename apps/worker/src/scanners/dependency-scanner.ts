import path from 'node:path';
import type { NormalizedFinding, Severity } from '@aishield/shared';
import { workerEnv } from '../config/env.js';
import { BaseSecurityScanner, generateFingerprint } from './base-scanner.js';
import { defaultCommandExecutor } from './command-executor.js';
import type { CommandExecutor, ScanOptions } from './types.js';

export interface EcosystemMetadata {
  readonly id: string;
  readonly displayName: string;
  readonly lockfiles: readonly string[];
}

/**
 * Extensible registry of supported ecosystems and their canonical manifest/lockfile names.
 * Designed to easily support Node.js (npm/yarn/pnpm), Python (pip/poetry), Java (Maven/Gradle), etc.
 */
export const SUPPORTED_ECOSYSTEMS: Record<string, EcosystemMetadata> = {
  npm: {
    id: 'npm',
    displayName: 'Node.js (npm / yarn / pnpm)',
    lockfiles: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'package.json'],
  },
  pypi: {
    id: 'PyPI',
    displayName: 'Python (pip / poetry / pipenv)',
    lockfiles: ['requirements.txt', 'poetry.lock', 'Pipfile.lock', 'Pipfile', 'setup.py'],
  },
  maven: {
    id: 'Maven',
    displayName: 'Java (Maven / Gradle)',
    lockfiles: ['pom.xml', 'build.gradle', 'build.gradle.kts', 'gradle.lockfile'],
  },
  go: {
    id: 'Go',
    displayName: 'Go',
    lockfiles: ['go.sum', 'go.mod'],
  },
  crates: {
    id: 'crates.io',
    displayName: 'Rust (Cargo)',
    lockfiles: ['Cargo.lock'],
  },
  nuget: {
    id: 'NuGet',
    displayName: '.NET / NuGet',
    lockfiles: ['packages.lock.json'],
  },
};

export interface DependencyScannerOptions {
  /** Execution runner: 'docker' or 'local'. Defaults to workerEnv.SCANNER_RUNNER or 'docker'. */
  readonly runner?: 'docker' | 'local';

  /** Docker image when running in container mode. Defaults to workerEnv.SCANNER_IMAGE_OSV or 'ghcr.io/google/osv-scanner:v1.7.0'. */
  readonly dockerImage?: string;

  /** Network mode for Docker runner. Defaults to 'bridge' (OSV-Scanner queries api.osv.dev). */
  readonly dockerNetwork?: string;

  /** Specific lockfiles or manifests to target. */
  readonly targetLockfiles?: readonly string[];

  /** Custom command executor for dependency injection and testing. */
  readonly executor?: CommandExecutor;
}

interface OSVAffectedEvent {
  introduced?: string;
  fixed?: string;
}

interface OSVSeverityItem {
  type?: string;
  score?: string;
}

interface OSVVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: {
    severity?: string;
    cwe_ids?: string[];
    github_reviewed?: boolean;
    [key: string]: unknown;
  };
  references?: Array<{
    type?: string;
    url?: string;
  }>;
  affected?: Array<{
    package?: {
      name?: string;
      ecosystem?: string;
      purl?: string;
    };
    ranges?: Array<{
      type?: string;
      events?: OSVAffectedEvent[];
    }>;
  }>;
  severity?: OSVSeverityItem[];
}

interface OSVPackageItem {
  package?: {
    name?: string;
    version?: string;
    ecosystem?: string;
  };
  vulnerabilities?: OSVVulnerability[];
}

interface OSVResultItem {
  source?: {
    path?: string;
    type?: string;
  };
  packages?: OSVPackageItem[];
}

interface OSVOutput {
  results?: OSVResultItem[];
  errors?: unknown[];
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

/**
 * Infers the ecosystem from manifest file name when OSV metadata is absent.
 */
function inferEcosystemFromPath(filePath: string): string {
  const baseName = path.basename(filePath).toLowerCase();
  for (const eco of Object.values(SUPPORTED_ECOSYSTEMS)) {
    if (eco.lockfiles.some((l) => l.toLowerCase() === baseName)) {
      return eco.id;
    }
  }
  return 'npm';
}

/**
 * Extracts CVE identifier from primary ID or aliases list.
 */
function extractCveId(id: string, aliases: readonly string[] = []): string | undefined {
  if (/^CVE-\d{4}-\d+$/i.test(id)) {
    return id.toUpperCase();
  }
  for (const alias of aliases) {
    if (/^CVE-\d{4}-\d+$/i.test(alias)) {
      return alias.toUpperCase();
    }
  }
  return undefined;
}

/**
 * Extracts GHSA identifier from primary ID or aliases list.
 */
function extractGhsaId(id: string, aliases: readonly string[] = []): string | undefined {
  if (/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i.test(id)) {
    return id;
  }
  for (const alias of aliases) {
    if (/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/i.test(alias)) {
      return alias;
    }
  }
  return undefined;
}

/**
 * Extracts standardized CWE identifier from OSV database_specific fields.
 */
function extractCwe(cweIds?: readonly string[]): string | undefined {
  if (!Array.isArray(cweIds) || cweIds.length === 0) {
    return undefined;
  }
  for (const item of cweIds) {
    if (typeof item === 'string') {
      const match = item.match(/CWE-\d+/i);
      if (match) {
        return match[0].toUpperCase();
      }
    }
  }
  return undefined;
}

/**
 * Maps OSV database severity, CVSS scores, or CVSS vectors to normalized Severity.
 */
function parseSeverity(
  rawSeverity?: string,
  severities?: readonly OSVSeverityItem[],
  cwe?: string,
): Severity {
  if (rawSeverity) {
    const s = rawSeverity.toUpperCase();
    if (s === 'CRITICAL') return 'critical';
    if (s === 'HIGH') return 'high';
    if (s === 'MODERATE' || s === 'MEDIUM') return 'medium';
    if (s === 'LOW') return 'low';
    if (s === 'INFO') return 'info';
  }

  // Check CVSS vector or score in severity array
  if (Array.isArray(severities)) {
    for (const item of severities) {
      if (item.score) {
        const numScore = parseFloat(item.score);
        if (!isNaN(numScore)) {
          if (numScore >= 9.0) return 'critical';
          if (numScore >= 7.0) return 'high';
          if (numScore >= 4.0) return 'medium';
          if (numScore > 0.0) return 'low';
          return 'info';
        }
        // CVSS v3 vector check (e.g. S:C or AV:N + PR:N + C:H + I:H + A:H)
        if (item.score.includes('AV:N') && item.score.includes('PR:N') && item.score.includes('C:H')) {
          return 'critical';
        }
      }
    }
  }

  // Elevate critical injection or deserialization CWEs
  if (cwe === 'CWE-502' || cwe === 'CWE-78' || cwe === 'CWE-89' || cwe === 'CWE-95') {
    return 'critical';
  }

  return 'high';
}

export class DependencyScanner extends BaseSecurityScanner {
  readonly runner: 'docker' | 'local';
  readonly dockerImage: string;
  readonly dockerNetwork: string;
  readonly targetLockfiles: readonly string[];

  constructor(optionsOrExecutor: DependencyScannerOptions | CommandExecutor = {}) {
    let executor: CommandExecutor = defaultCommandExecutor;
    let options: DependencyScannerOptions = {};

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
    this.dockerImage = options.dockerImage ?? workerEnv.SCANNER_IMAGE_OSV ?? 'ghcr.io/google/osv-scanner:v1.7.0';
    this.dockerNetwork = options.dockerNetwork ?? 'bridge';
    this.targetLockfiles = options.targetLockfiles ?? [];
  }

  getName(): string {
    return 'dependency';
  }

  getDisplayName(): string {
    return 'OSV Dependency Vulnerability Scanner';
  }

  protected getVersionArgs(): { command: string; args: string[] } {
    if (this.runner === 'docker') {
      return {
        command: 'docker',
        args: ['run', '--rm', this.dockerImage, '--version'],
      };
    }
    return {
      command: 'osv-scanner',
      args: ['--version'],
    };
  }

  protected buildCommand(options: ScanOptions): { command: string; args: string[] } {
    const activeRunner = options.runner ?? this.runner;

    // Detect if any PR changed files are known manifest/lockfiles
    const lockfilesToScan: string[] = [];
    if (this.targetLockfiles.length > 0) {
      lockfilesToScan.push(...this.targetLockfiles);
    } else if (options.changedFiles && options.changedFiles.length > 0) {
      for (const file of options.changedFiles) {
        const baseName = path.basename(file).toLowerCase();
        for (const eco of Object.values(SUPPORTED_ECOSYSTEMS)) {
          if (eco.lockfiles.some((l) => l.toLowerCase() === baseName)) {
            lockfilesToScan.push(file);
            break;
          }
        }
      }
    }

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
        this.dockerImage,
        '--json',
      ];

      if (lockfilesToScan.length > 0) {
        for (const lf of lockfilesToScan) {
          args.push(`--lockfile=/src/${lf.replace(/\\/g, '/')}`);
        }
      } else {
        args.push('-r', '/src');
      }

      return { command: 'docker', args };
    }

    // Local runner
    const args: string[] = ['--json'];

    if (lockfilesToScan.length > 0) {
      for (const lf of lockfilesToScan) {
        args.push(`--lockfile=${lf}`);
      }
    } else {
      args.push('-r', options.targetPath);
    }

    return { command: 'osv-scanner', args };
  }

  normalizeResult(rawOutput: unknown, options?: ScanOptions): NormalizedFinding[] {
    if (!rawOutput || typeof rawOutput !== 'object') {
      return [];
    }

    const data = rawOutput as OSVOutput;
    const results = Array.isArray(data.results) ? data.results : [];
    const normalized: NormalizedFinding[] = [];

    // Filter set for PR changed files if provided
    const changedFilesSet =
      options?.changedFiles && options.changedFiles.length > 0
        ? new Set(options.changedFiles.map((f) => cleanFilePath(f)))
        : null;

    for (const res of results) {
      const file = cleanFilePath(res.source?.path || 'package-lock.json');

      // If PR changed files are specified and this lockfile wasn't modified, skip
      if (changedFilesSet && !changedFilesSet.has(file)) {
        continue;
      }

      const packages = Array.isArray(res.packages) ? res.packages : [];

      for (const pkgItem of packages) {
        const pkgName = pkgItem.package?.name || 'unknown-package';
        const pkgVersion = pkgItem.package?.version || 'unknown-version';
        const ecosystem = pkgItem.package?.ecosystem || inferEcosystemFromPath(file);
        const vulns = Array.isArray(pkgItem.vulnerabilities) ? pkgItem.vulnerabilities : [];

        for (const vuln of vulns) {
          if (!vuln || (!vuln.id && !vuln.summary && !vuln.details)) {
            continue;
          }

          const rawId = vuln.id || 'GENERIC-VULN';
          const aliases = Array.isArray(vuln.aliases) ? vuln.aliases : [];
          const cveId = extractCveId(rawId, aliases);
          const ghsaId = extractGhsaId(rawId, aliases);

          // Standardize primary rule identifier (prefer GHSA or CVE, fallback to raw ID)
          const ruleId = ghsaId || cveId || rawId;

          const summary = vuln.summary || vuln.details || `Security vulnerability in ${pkgName}`;
          const title = `${pkgName}@${pkgVersion}: ${vuln.summary || ruleId}`;

          // Extract CWE if present in database_specific
          const cwe = extractCwe(vuln.database_specific?.cwe_ids);

          // Map severity
          const severity = parseSeverity(
            vuln.database_specific?.severity,
            vuln.severity,
            cwe,
          );

          // Locate first fixed version from affected ranges
          let fixedVersion: string | undefined;
          if (Array.isArray(vuln.affected)) {
            for (const aff of vuln.affected) {
              if (Array.isArray(aff.ranges)) {
                for (const range of aff.ranges) {
                  if (Array.isArray(range.events)) {
                    for (const ev of range.events) {
                      if (ev.fixed) {
                        fixedVersion = ev.fixed;
                        break;
                      }
                    }
                  }
                  if (fixedVersion) break;
                }
              }
              if (fixedVersion) break;
            }
          }

          // Stable fingerprint for dependency finding
          const fingerprint = generateFingerprint(
            'dependency',
            file,
            `${ecosystem}:${pkgName}@${pkgVersion}:${ruleId}`,
          );

          // Find primary advisory URL if available
          let advisoryUrl: string | undefined;
          if (Array.isArray(vuln.references)) {
            const adv = vuln.references.find((r) => r.type === 'ADVISORY' && r.url);
            advisoryUrl = adv?.url || vuln.references[0]?.url;
          }

          const remediation = fixedVersion
            ? `Upgrade ${pkgName} to version ${fixedVersion} or higher.`
            : `Review advisory ${ruleId} and update ${pkgName} to a patched release.`;

          normalized.push({
            source: this.getName(),
            ruleId,
            category: 'dependency',
            title,
            description: summary,
            severity,
            confidence: 1.0,
            file,
            line: 1,
            cwe,
            fingerprint,
            remediation,
            metadata: {
              packageName: pkgName,
              installedVersion: pkgVersion,
              fixedVersion,
              ecosystem,
              vulnId: rawId,
              cve: cveId,
              ghsa: ghsaId,
              aliases,
              advisoryUrl,
              rawSeverity: vuln.database_specific?.severity,
            },
          });
        }
      }
    }

    return normalized;
  }
}
