/**
 * Scan Worker unit tests.
 *
 * Tests the processScanJob function with mocked scanner dependencies.
 * All tests run without Redis or MongoDB connections.
 */
import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import type { Job } from 'bullmq';
import type { ScanJobData, ScanJobResult } from '@aishield/shared';
import { processScanJob } from '../scan-worker.js';
import type { ScannerOrchestrator } from '../../scanners/scanner-orchestrator.js';
import type { SecurityScanner } from '../../scanners/security-scanner.interface.js';
import type { FindingNormalizerEngine, EngineDeduplicationResult } from '../../engine/finding-normalizer-engine.js';
import type { SecurityDebtScoringEngine } from '../../engine/debt-scoring-engine.js';
import type { AIContextRunner } from '../../runners/ai-runner.js';

vi.mock('../../db/mongo.js', () => ({
  isMongoConnected: vi.fn().mockReturnValue(false),
  connectWorkerMongo: vi.fn().mockResolvedValue(undefined),
  disconnectWorkerMongo: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../db/models.js', () => ({
  ScanModel: {
    findByIdAndUpdate: vi.fn().mockResolvedValue(null),
    findOneAndUpdate: vi.fn().mockResolvedValue(null),
  },
  FindingModel: {
    findOneAndUpdate: vi.fn().mockResolvedValue({ _id: 'mock-finding-id' }),
  },
  SecurityDebtModel: {
    findOneAndUpdate: vi.fn().mockResolvedValue(null),
  },
}));

vi.mock('../../logging/logger.js', () => ({
  childLogger: vi.fn(() => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    child: vi.fn(() => ({
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
    })),
  })),
}));

function createMockJob(data: Partial<ScanJobData> = {}): Job<ScanJobData, ScanJobResult> {
  return {
    id: 'job-001',
    data: {
      scanId: 'scan-abc-123',
      repositoryUrl: 'https://github.com/example/repo',
      ref: 'abc1234def5678',
      commitSha: 'abc1234def5678',
      branch: 'main',
      scanners: ['semgrep', 'gitleaks', 'dependency'],
      requestedAt: new Date().toISOString(),
      ...data,
    },
    attemptsMade: 0,
    updateProgress: vi.fn().mockResolvedValue(undefined),
  } as unknown as Job<ScanJobData, ScanJobResult>;
}

function createMockScanner(name: string, findings: unknown[] = []): SecurityScanner {
  return {
    getName: vi.fn().mockReturnValue(name),
    getDisplayName: vi.fn().mockReturnValue(name),
    getVersion: vi.fn().mockResolvedValue('1.0.0-mock'),
    scan: vi.fn().mockResolvedValue({
      scanner: name,
      status: 'succeeded',
      durationMs: 100,
      findings,
    }),
    normalizeResult: vi.fn().mockReturnValue(findings),
  };
}

function createMockOrchestrator(scanners: SecurityScanner[]): ScannerOrchestrator {
  const map = new Map(scanners.map((s) => [s.getName(), s]));
  return {
    getScanner: vi.fn((name: string) => map.get(name) || null),
    getScanners: vi.fn(() => scanners),
    scan: vi.fn(),
  } as unknown as ScannerOrchestrator;
}

function createMockNormalizer(result: Partial<EngineDeduplicationResult> = {}): FindingNormalizerEngine {
  return {
    processFindings: vi.fn().mockReturnValue({
      unifiedFindings: [],
      totalRawFindings: 0,
      uniqueFindingsCount: 0,
      duplicatesRemoved: 0,
      correlatedFindingsCount: 0,
      confirmedScannerCount: 0,
      aiSuggestedCount: 0,
      byCategory: {},
      bySeverity: {},
      ...result,
    }),
    normalizeSingleFinding: vi.fn(),
  } as unknown as FindingNormalizerEngine;
}

type DebtResult = ReturnType<SecurityDebtScoringEngine['calculateDebt']>;

function createMockDebtEngine(result: Partial<DebtResult> = {}): SecurityDebtScoringEngine {
  return {
    calculateDebt: vi.fn().mockReturnValue({
      score: 15,
      riskLevel: 'LOW',
      previousScore: 10,
      delta: 5,
      newDebt: 5,
      resolvedDebt: 0,
      severityBreakdown: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
      categoryBreakdown: {},
      topContributors: [],
      totalDebtPoints: 15,
      formulaSummary: 'mock-formula',
      ...result,
    }),
  } as unknown as SecurityDebtScoringEngine;
}

function createMockAIRunner(status: 'succeeded' | 'failed' | 'skipped' = 'succeeded'): AIContextRunner {
  return {
    id: 'ai-analyzer',
    execute: vi.fn().mockResolvedValue({
      scanner: 'ai-analyzer',
      status,
      durationMs: 200,
      findings: [],
      error: status === 'failed' ? 'AI unavailable' : undefined,
    }),
  } as unknown as AIContextRunner;
}

describe('processScanJob', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('completes successfully with all scanners passing', async () => {
    const job = createMockJob();
    const deps = {
      orchestrator: createMockOrchestrator([
        createMockScanner('semgrep'),
        createMockScanner('gitleaks'),
        createMockScanner('dependency'),
      ]),
      normalizer: createMockNormalizer({ uniqueFindingsCount: 3 }),
      debtEngine: createMockDebtEngine({ score: 20 }),
      aiRunner: createMockAIRunner('skipped'),
    };

    const result = await processScanJob(job, deps);

    expect(result.status).toBe('succeeded');
    expect(result.findingCount).toBe(3);
    expect(result.debtScore).toBe(20);
    expect(result.componentStatuses?.semgrep).toBe('succeeded');
    expect(result.componentStatuses?.gitleaks).toBe('succeeded');
    expect(result.componentStatuses?.dependency).toBe('succeeded');
  });

  it('tolerates individual scanner failures and continues pipeline', async () => {
    const failingScanner: SecurityScanner = {
      getName: vi.fn().mockReturnValue('semgrep'),
      getDisplayName: vi.fn().mockReturnValue('Semgrep'),
      getVersion: vi.fn().mockResolvedValue('1.0.0'),
      scan: vi.fn().mockRejectedValue(new Error('Semgrep binary not found')),
      normalizeResult: vi.fn().mockReturnValue([]),
    };

    const job = createMockJob({ scanners: ['semgrep', 'gitleaks'] });
    const deps = {
      orchestrator: createMockOrchestrator([
        failingScanner,
        createMockScanner('gitleaks'),
      ]),
      normalizer: createMockNormalizer({ uniqueFindingsCount: 2 }),
      debtEngine: createMockDebtEngine(),
      aiRunner: createMockAIRunner('skipped'),
    };

    const result = await processScanJob(job, deps);

    // The pipeline should continue even though Semgrep failed
    expect(result.status).toBe('succeeded');
    expect(result.componentStatuses?.semgrep).toBe('failed');
    expect(result.componentStatuses?.gitleaks).toBe('succeeded');
    expect(result.error).toBeUndefined();
  });

  it('marks entire scan as failed only when ALL requested scanners fail', async () => {
    const failSemgrep: SecurityScanner = {
      getName: vi.fn().mockReturnValue('semgrep'),
      getDisplayName: vi.fn().mockReturnValue('Semgrep'),
      getVersion: vi.fn().mockResolvedValue('1.0.0'),
      scan: vi.fn().mockRejectedValue(new Error('semgrep crash')),
      normalizeResult: vi.fn().mockReturnValue([]),
    };

    const failGitleaks: SecurityScanner = {
      getName: vi.fn().mockReturnValue('gitleaks'),
      getDisplayName: vi.fn().mockReturnValue('Gitleaks'),
      getVersion: vi.fn().mockResolvedValue('1.0.0'),
      scan: vi.fn().mockRejectedValue(new Error('gitleaks crash')),
      normalizeResult: vi.fn().mockReturnValue([]),
    };

    const job = createMockJob({ scanners: ['semgrep', 'gitleaks'] });
    const deps = {
      orchestrator: createMockOrchestrator([failSemgrep, failGitleaks]),
      normalizer: createMockNormalizer(),
      debtEngine: createMockDebtEngine(),
      aiRunner: createMockAIRunner('skipped'),
    };

    const result = await processScanJob(job, deps);

    expect(result.status).toBe('failed');
    expect(result.componentStatuses?.semgrep).toBe('failed');
    expect(result.componentStatuses?.gitleaks).toBe('failed');
    expect(result.error).toBe('All requested scanners failed');
  });

  it('stores individual component statuses for each scanner', async () => {
    const job = createMockJob({ scanners: ['semgrep', 'gitleaks', 'dependency'] });
    const deps = {
      orchestrator: createMockOrchestrator([
        createMockScanner('semgrep', [{ title: 'SQL Injection', severity: 'HIGH' }]),
        createMockScanner('gitleaks', []),
        createMockScanner('dependency', [{ title: 'CVE-2024-1234', severity: 'CRITICAL' }]),
      ]),
      normalizer: createMockNormalizer({ uniqueFindingsCount: 2 }),
      debtEngine: createMockDebtEngine({ score: 55, riskLevel: 'HIGH' }),
      aiRunner: createMockAIRunner('skipped'),
    };

    const result = await processScanJob(job, deps);

    expect(result.componentStatuses).toBeDefined();
    expect(Object.keys(result.componentStatuses!)).toContain('semgrep');
    expect(Object.keys(result.componentStatuses!)).toContain('gitleaks');
    expect(Object.keys(result.componentStatuses!)).toContain('dependency');
    expect(result.riskLevel).toBe('HIGH');
  });

  it('includes AI analyzer status when ai-analyzer is in scanners list', async () => {
    const job = createMockJob({ scanners: ['semgrep', 'ai-analyzer'] });
    const deps = {
      orchestrator: createMockOrchestrator([createMockScanner('semgrep')]),
      normalizer: createMockNormalizer(),
      debtEngine: createMockDebtEngine(),
      aiRunner: createMockAIRunner('succeeded'),
    };

    const result = await processScanJob(job, deps);

    expect(result.componentStatuses?.['ai-analyzer']).toBe('succeeded');
    expect(result.status).toBe('succeeded');
  });

  it('does not crash when AI analyzer fails — scan still succeeds from deterministic scanners', async () => {
    const job = createMockJob({ scanners: ['semgrep', 'ai-analyzer'] });
    const deps = {
      orchestrator: createMockOrchestrator([createMockScanner('semgrep')]),
      normalizer: createMockNormalizer({ uniqueFindingsCount: 1 }),
      debtEngine: createMockDebtEngine(),
      aiRunner: createMockAIRunner('failed'),
    };

    const result = await processScanJob(job, deps);

    // Overall scan should still succeed because semgrep passed
    expect(result.status).toBe('succeeded');
    expect(result.componentStatuses?.['ai-analyzer']).toBe('failed');
    expect(result.componentStatuses?.semgrep).toBe('succeeded');
  });

  it('emits structured progress updates during execution', async () => {
    const job = createMockJob({ scanners: ['semgrep', 'gitleaks'] });
    const deps = {
      orchestrator: createMockOrchestrator([
        createMockScanner('semgrep'),
        createMockScanner('gitleaks'),
      ]),
      normalizer: createMockNormalizer(),
      debtEngine: createMockDebtEngine(),
      aiRunner: createMockAIRunner('skipped'),
    };

    await processScanJob(job, deps);

    // Progress should have been called at least once per scanner
    expect(job.updateProgress).toHaveBeenCalled();
    const calls = (job.updateProgress as ReturnType<typeof vi.fn>).mock.calls;
    // Each call should have stage info
    for (const [progressObj] of calls) {
      expect(progressObj).toHaveProperty('scanId');
      expect(progressObj).toHaveProperty('stage');
    }
  });

  it('records job ID and debt score in the result', async () => {
    const job = createMockJob({ scanners: ['semgrep'] });
    const deps = {
      orchestrator: createMockOrchestrator([createMockScanner('semgrep')]),
      normalizer: createMockNormalizer(),
      debtEngine: createMockDebtEngine({ score: 42, riskLevel: 'MEDIUM' }),
      aiRunner: createMockAIRunner('skipped'),
    };

    const result = await processScanJob(job, deps);

    expect(result.jobId).toBe('job-001');
    expect(result.debtScore).toBe(42);
    expect(result.riskLevel).toBe('MEDIUM');
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });
});
