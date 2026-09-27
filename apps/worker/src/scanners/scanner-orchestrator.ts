import type { NormalizedFinding } from '@aishield/shared';
import { childLogger } from '../logging/logger.js';
import type { SecurityScanner } from './security-scanner.interface.js';
import type { ScanOptions, ScannerResultEnvelope } from './types.js';

export interface OrchestrationReport {
  results: Record<string, ScannerResultEnvelope>;
  allFindings: NormalizedFinding[];
  durationMs: number;
  hasFailures: boolean;
}

export class ScannerOrchestrator {
  private readonly scanners = new Map<string, SecurityScanner>();
  private readonly log = childLogger({ component: 'scanner-orchestrator' });

  constructor(initialScanners: SecurityScanner[] = []) {
    for (const scanner of initialScanners) {
      this.registerScanner(scanner);
    }
  }

  registerScanner(scanner: SecurityScanner): void {
    this.scanners.set(scanner.getName(), scanner);
  }

  getScanner(name: string): SecurityScanner | undefined {
    return this.scanners.get(name);
  }

  getRegisteredScannerNames(): string[] {
    return Array.from(this.scanners.keys());
  }

  async runScanner(name: string, options: ScanOptions): Promise<ScannerResultEnvelope> {
    const scanner = this.scanners.get(name);
    if (!scanner) {
      return {
        scanner: name,
        status: 'skipped',
        durationMs: 0,
        findings: [],
        error: `Scanner "${name}" is not registered`,
      };
    }

    return scanner.scan(options);
  }

  /**
   * Runs all registered (or specified) scanners in parallel with full failure isolation.
   * If any scanner fails or times out, the remaining scanners complete without crashing.
   */
  async runAll(
    options: ScanOptions,
    selectedScanners?: readonly string[],
  ): Promise<OrchestrationReport> {
    const started = Date.now();
    const namesToRun = selectedScanners && selectedScanners.length > 0
      ? selectedScanners.filter((name) => this.scanners.has(name))
      : Array.from(this.scanners.keys());

    this.log.info({ scanners: namesToRun, targetPath: options.targetPath }, 'Orchestrating scanner suite');

    const tasks = namesToRun.map(async (name) => {
      const scanner = this.scanners.get(name)!;
      try {
        return await scanner.scan(options);
      } catch (err: unknown) {
        // Defensive double-guard: even if a scanner implementation throws, catch here
        const errorMsg = err instanceof Error ? err.message : String(err);
        this.log.error({ scanner: name, error: errorMsg }, 'Unhandled scanner exception caught by orchestrator');
        return {
          scanner: name,
          status: 'failed' as const,
          durationMs: Date.now() - started,
          findings: [],
          error: errorMsg,
        };
      }
    });

    const settledResults = await Promise.allSettled(tasks);
    const results: Record<string, ScannerResultEnvelope> = {};
    const allFindings: NormalizedFinding[] = [];
    let hasFailures = false;

    for (let i = 0; i < namesToRun.length; i++) {
      const name = namesToRun[i]!;
      const settled = settledResults[i];

      if (settled && settled.status === 'fulfilled') {
        results[name] = settled.value;
        if (settled.value.status === 'failed') {
          hasFailures = true;
        }
        allFindings.push(...settled.value.findings);
      } else {
        hasFailures = true;
        const reason = settled && settled.status === 'rejected' ? String(settled.reason) : 'Unknown error';
        results[name] = {
          scanner: name,
          status: 'failed',
          durationMs: Date.now() - started,
          findings: [],
          error: reason,
        };
      }
    }

    const durationMs = Date.now() - started;

    this.log.info(
      { durationMs, totalFindings: allFindings.length, hasFailures },
      'Scanner orchestration complete',
    );

    return {
      results,
      allFindings,
      durationMs,
      hasFailures,
    };
  }
}
