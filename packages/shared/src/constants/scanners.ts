import type { FindingCategory } from '../types/scan.js';

/**
 * The scanner engines AIShield Debt knows how to orchestrate.
 *
 * Each id has a matching `services/<dir>` image and a matching
 * `SCANNER_IMAGE_*` environment variable consumed by the worker's Docker runner.
 */
export const SCANNER_IDS = ['semgrep', 'gitleaks', 'dependency', 'ai-analyzer'] as const;

export type ScannerId = (typeof SCANNER_IDS)[number];

export interface ScannerDescriptor {
  readonly id: ScannerId;
  readonly displayName: string;
  /** Default severity bucket this engine produces. */
  readonly category: FindingCategory;
  /** Environment variable holding the image reference used by the Docker runner. */
  readonly imageEnvVar: string;
  /** Directory under `services/` that builds the image. */
  readonly serviceDir: string;
  readonly description: string;
}

export const SCANNERS: Readonly<Record<ScannerId, ScannerDescriptor>> = {
  semgrep: {
    id: 'semgrep',
    displayName: 'Semgrep',
    category: 'security',
    imageEnvVar: 'SCANNER_IMAGE_SEMGREP',
    serviceDir: 'semgrep',
    description: 'Static analysis for insecure code patterns and known-bad APIs.',
  },
  gitleaks: {
    id: 'gitleaks',
    displayName: 'Gitleaks',
    category: 'secret',
    imageEnvVar: 'SCANNER_IMAGE_GITLEAKS',
    serviceDir: 'gitleaks',
    description: 'Secret and credential detection across a repository history.',
  },
  dependency: {
    id: 'dependency',
    displayName: 'Dependency Scanner',
    category: 'dependency',
    imageEnvVar: 'SCANNER_IMAGE_DEPENDENCY',
    serviceDir: 'dependency-scanner',
    description: 'Vulnerable, outdated and unmaintained third-party dependencies.',
  },
  'ai-analyzer': {
    id: 'ai-analyzer',
    displayName: 'AI Analyzer',
    category: 'ai-reasoning',
    imageEnvVar: 'SCANNER_IMAGE_AI_ANALYZER',
    serviceDir: 'ai-analyzer',
    description: 'LLM-assisted reasoning over findings and architectural tech debt.',
  },
} satisfies Record<ScannerId, ScannerDescriptor>;

export function isScannerId(value: string): value is ScannerId {
  return (SCANNER_IDS as readonly string[]).includes(value);
}
