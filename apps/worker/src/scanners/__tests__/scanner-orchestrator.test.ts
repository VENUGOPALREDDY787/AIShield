import { describe, expect, it } from 'vitest';
import { ScannerOrchestrator } from '../scanner-orchestrator.js';
import type { SecurityScanner } from '../security-scanner.interface.js';
import type { NormalizedFinding } from '@aishield/shared';
import type { ScanOptions, ScannerResultEnvelope } from '../types.js';

describe('ScannerOrchestrator', () => {
  const dummyFinding: NormalizedFinding = {
    source: 'mock-scanner',
    ruleId: 'mock-rule-1',
    category: 'security',
    title: 'Mock Vulnerability',
    description: 'Test vulnerability description',
    severity: 'high',
    confidence: 1.0,
    file: 'src/app.ts',
    line: 10,
    cwe: 'CWE-20',
    fingerprint: 'a1b2c3d4e5f6',
    remediation: 'Apply validation',
    metadata: {},
  };

  it('orchestrates registered scanners and aggregates findings', async () => {
    const scannerA: SecurityScanner = {
      getName: () => 'scanner-a',
      getDisplayName: () => 'Scanner A',
      getVersion: async () => '1.0.0',
      scan: async () => ({
        scanner: 'scanner-a',
        status: 'succeeded',
        durationMs: 50,
        findings: [dummyFinding],
      }),
      normalizeResult: () => [dummyFinding],
    };

    const scannerB: SecurityScanner = {
      getName: () => 'scanner-b',
      getDisplayName: () => 'Scanner B',
      getVersion: async () => '2.0.0',
      scan: async () => ({
        scanner: 'scanner-b',
        status: 'succeeded',
        durationMs: 30,
        findings: [],
      }),
      normalizeResult: () => [],
    };

    const orchestrator = new ScannerOrchestrator([scannerA, scannerB]);
    const report = await orchestrator.runAll({ targetPath: '/dummy' });

    expect(report.hasFailures).toBe(false);
    expect(report.allFindings.length).toBe(1);
    expect(report.results['scanner-a']?.status).toBe('succeeded');
    expect(report.results['scanner-b']?.status).toBe('succeeded');
  });

  it('isolates scanner failures without crashing the orchestration run', async () => {
    const healthyScanner: SecurityScanner = {
      getName: () => 'healthy',
      getDisplayName: () => 'Healthy Scanner',
      getVersion: async () => '1.0.0',
      scan: async () => ({
        scanner: 'healthy',
        status: 'succeeded',
        durationMs: 40,
        findings: [dummyFinding],
      }),
      normalizeResult: () => [dummyFinding],
    };

    const brokenScanner: SecurityScanner = {
      getName: () => 'broken',
      getDisplayName: () => 'Broken Scanner',
      getVersion: async () => '0.0.1',
      scan: async () => {
        throw new Error('Fatal scanner crash: segfault in binary');
      },
      normalizeResult: () => [],
    };

    const orchestrator = new ScannerOrchestrator([healthyScanner, brokenScanner]);
    const report = await orchestrator.runAll({ targetPath: '/dummy' });

    expect(report.hasFailures).toBe(true);
    expect(report.results['healthy']?.status).toBe('succeeded');
    expect(report.results['healthy']?.findings.length).toBe(1);

    expect(report.results['broken']?.status).toBe('failed');
    expect(report.results['broken']?.error).toContain('Fatal scanner crash');
    expect(report.allFindings.length).toBe(1); // Healthy findings are preserved!
  });

  it('enforces timeout handling when scanner execution exceeds budget', async () => {
    const hangingScanner: SecurityScanner = {
      getName: () => 'hanging',
      getDisplayName: () => 'Hanging Scanner',
      getVersion: async () => '1.0.0',
      scan: async (opts: ScanOptions): Promise<ScannerResultEnvelope> => {
        return new Promise((resolve) => {
          const timeout = opts.timeoutMs ?? 100;
          setTimeout(() => {
            resolve({
              scanner: 'hanging',
              status: 'failed',
              durationMs: timeout,
              findings: [],
              error: `Execution timed out after ${timeout}ms`,
            });
          }, timeout);
        });
      },
      normalizeResult: () => [],
    };

    const orchestrator = new ScannerOrchestrator([hangingScanner]);
    const report = await orchestrator.runAll({ targetPath: '/dummy', timeoutMs: 50 });

    expect(report.results['hanging']?.status).toBe('failed');
    expect(report.results['hanging']?.error).toContain('timed out');
  });
});
