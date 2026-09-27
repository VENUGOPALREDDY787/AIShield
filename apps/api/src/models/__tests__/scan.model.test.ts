import { describe, expect, it } from 'vitest';
import { ScanModel } from '../scan.model.js';
import { indexNamed, invalidPaths, oid } from './helpers.js';

const COMMIT_SHA = 'b'.repeat(40);
const STARTED_AT = new Date('2026-01-01T10:00:00.000Z');
const FINISHED_AT = new Date('2026-01-01T10:00:01.500Z');

const minimalScan = () => ({ repository: oid(), commitSha: COMMIT_SHA, branch: 'main' });

describe('Scan model', () => {
  it('accepts a minimal queued scan and applies defaults', () => {
    const scan = new ScanModel(minimalScan());

    expect(invalidPaths(scan)).toEqual([]);
    expect(scan.status).toBe('queued');
    expect(scan.trigger).toBe('manual');
    expect(scan.aiAnalysisStatus).toBe('not_requested');
    expect(scan.attempt).toBe(1);
    expect(scan.scannerResults).toEqual([]);
    expect(scan.findings).toEqual([]);
    expect(scan.enqueuedAt).toBeInstanceOf(Date);
    expect(scan.summary?.totalFindings).toBe(0);
  });

  it('requires a repository, a commit SHA and a branch', () => {
    expect(invalidPaths(new ScanModel({}))).toEqual(['branch', 'commitSha', 'repository']);
  });

  it('rejects a malformed commit SHA', () => {
    expect(invalidPaths(new ScanModel({ ...minimalScan(), commitSha: 'zzz' }))).toContain(
      'commitSha',
    );
  });

  it('accepts an abbreviated SHA', () => {
    expect(invalidPaths(new ScanModel({ ...minimalScan(), commitSha: 'b1c2d3e' }))).toEqual([]);
  });

  it('accepts a fully populated pull-request scan', () => {
    const scan = new ScanModel({
      ...minimalScan(),
      pullRequest: oid(),
      baseBranch: 'main',
      baseSha: 'c'.repeat(40),
      trigger: 'pull_request',
      status: 'succeeded',
      startedAt: STARTED_AT,
      finishedAt: FINISHED_AT,
      aiAnalysisStatus: 'completed',
      aiAnalysis: { provider: 'openai', model: 'gpt-4o', findingsAnalyzed: 3 },
      finalScore: { overall: 78, previous: 74, delta: 4, grade: 'C' },
      summary: { totalFindings: 3, newFindings: 1, resolvedFindings: 2 },
      scannerResults: [
        { source: 'semgrep', status: 'succeeded', findingCount: 2 },
        { source: 'gitleaks', status: 'succeeded' },
        { source: 'dependency', status: 'failed', error: 'registry timeout' },
        { source: 'ai-analyzer', status: 'skipped' },
      ],
      findings: [oid(), oid()],
    });

    expect(invalidPaths(scan)).toEqual([]);
    expect(scan.durationMs).toBe(1500);
  });

  describe('lifecycle invariants', () => {
    it('requires finishedAt once a scan reaches a terminal status', () => {
      const scan = new ScanModel({ ...minimalScan(), status: 'succeeded', startedAt: STARTED_AT });

      expect(invalidPaths(scan)).toContain('finishedAt');
    });

    it('forbids finishedAt while a scan is still in flight', () => {
      const scan = new ScanModel({
        ...minimalScan(),
        status: 'running',
        startedAt: STARTED_AT,
        finishedAt: FINISHED_AT,
      });

      expect(invalidPaths(scan)).toContain('finishedAt');
    });

    it('requires startedAt once a scan leaves the queued state', () => {
      expect(invalidPaths(new ScanModel({ ...minimalScan(), status: 'running' }))).toEqual([
        'startedAt',
      ]);
    });

    it('rejects a finishedAt that precedes startedAt', () => {
      const scan = new ScanModel({
        ...minimalScan(),
        status: 'failed',
        startedAt: FINISHED_AT,
        finishedAt: STARTED_AT,
      });

      expect(invalidPaths(scan)).toContain('finishedAt');
    });

    it('derives durationMs rather than trusting a caller value', () => {
      const scan = new ScanModel({
        ...minimalScan(),
        status: 'succeeded',
        startedAt: STARTED_AT,
        finishedAt: FINISHED_AT,
      });

      scan.validateSync();

      expect(scan.durationMs).toBe(1500);
    });

    it('rejects two results for the same scanner', () => {
      const scan = new ScanModel({
        ...minimalScan(),
        scannerResults: [{ source: 'semgrep' }, { source: 'semgrep' }],
      });

      expect(invalidPaths(scan)).toContain('scannerResults');
    });

    it('rejects an unknown scanner', () => {
      const scan = new ScanModel({
        ...minimalScan(),
        scannerResults: [{ source: 'not-a-scanner' }],
      });

      expect(invalidPaths(scan)).toContain('scannerResults.0.source');
    });

    it('rejects an unknown aiAnalysisStatus', () => {
      const scan = new ScanModel({ ...minimalScan(), aiAnalysisStatus: 'thinking' });

      expect(invalidPaths(scan)).toContain('aiAnalysisStatus');
    });
  });

  it('allows at most one in-flight scan per repository', () => {
    const index = indexNamed(ScanModel, 'one_active_scan_per_repository');

    expect(index?.key).toBe('repository:1');
    expect(index?.options.unique).toBe(true);
    expect(index?.options.partialFilterExpression).toEqual({
      status: { $in: ['queued', 'running'] },
    });
  });

  it('indexes the repository timeline and the queue view', () => {
    expect(indexNamed(ScanModel, 'repository_recent')?.key).toBe('repository:1,createdAt:-1');
    expect(indexNamed(ScanModel, 'repository_commit')?.key).toBe('repository:1,commitSha:1');
    expect(indexNamed(ScanModel, 'status_heartbeat')?.key).toBe('status:1,heartbeatAt:1');
  });

  it('keeps the pull request index sparse so push scans do not collide', () => {
    const index = indexNamed(ScanModel, 'pull_request_recent');

    expect(index?.options.sparse).toBe(true);
  });
});
