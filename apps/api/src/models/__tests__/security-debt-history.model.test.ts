import { describe, expect, it } from 'vitest';
import {
  HISTORY_APPEND_ONLY_MESSAGE,
  SecurityDebtHistoryModel,
  rejectHistoryMutation,
} from '../security-debt-history.model.js';
import { indexNamed, indexesOf, invalidPaths, oid } from './helpers.js';

const minimalEntry = () => ({ repository: oid(), overallScore: 68, event: 'scan_completed' });

describe('SecurityDebtHistory model', () => {
  it('accepts a minimal entry and applies defaults', () => {
    const entry = new SecurityDebtHistoryModel(minimalEntry());

    expect(invalidPaths(entry)).toEqual([]);
    expect(entry.recordedAt).toBeInstanceOf(Date);
    expect(entry.methodology).toBe('weighted-severity-v1');
    expect(entry.severityBreakdown?.critical).toBe(0);
    expect(entry.findingCounts?.open).toBe(0);
  });

  it('requires a repository, a score and an event', () => {
    expect(invalidPaths(new SecurityDebtHistoryModel({}))).toEqual([
      'event',
      'overallScore',
      'repository',
    ]);
  });

  it('bounds the recorded score', () => {
    expect(
      invalidPaths(new SecurityDebtHistoryModel({ ...minimalEntry(), overallScore: 101 })),
    ).toContain('overallScore');
  });

  it('accepts a baseline entry with no scan attached', () => {
    const entry = new SecurityDebtHistoryModel({ ...minimalEntry(), event: 'baseline' });

    expect(invalidPaths(entry)).toEqual([]);
    expect(entry.scan).toBeUndefined();
  });

  it('records the full breakdown so an old point on the chart still explains itself', () => {
    const entry = new SecurityDebtHistoryModel({
      ...minimalEntry(),
      scan: oid(),
      previousScore: 74,
      delta: -6,
      grade: 'D',
      trend: 'worsening',
      severityBreakdown: { critical: 3, high: 4 },
      categoryBreakdown: { dependency: 7 },
      findingCounts: { total: 12, open: 11, new: 4, resolved: 1 },
      scoreExplanation: { summary: 'Three new criticals in the auth module.' },
    });

    expect(invalidPaths(entry)).toEqual([]);
    expect(entry.findingCounts?.new).toBe(4);
    expect(entry.severityBreakdown?.critical).toBe(3);
  });

  describe('append-only guarantee', () => {
    it('exposes a guard that refuses mutation', () => {
      expect(() => rejectHistoryMutation()).toThrow(HISTORY_APPEND_ONLY_MESSAGE);
    });

    it('refuses to save a document that already exists', async () => {
      const entry = new SecurityDebtHistoryModel(minimalEntry());
      entry.isNew = false;

      await expect(entry.save()).rejects.toThrow(/append-only/);
    });

    it('refuses an update through the query API', async () => {
      await expect(
        SecurityDebtHistoryModel.updateOne({}, { $set: { overallScore: 1 } }),
      ).rejects.toThrow(/append-only/);
    });

    it('refuses a delete', async () => {
      await expect(SecurityDebtHistoryModel.deleteMany({})).rejects.toThrow(/append-only/);
    });
  });

  it('records one entry per scan without colliding on baselines', () => {
    const index = indexNamed(SecurityDebtHistoryModel, 'uniq_repository_scan');

    expect(index?.key).toBe('repository:1,scan:1');
    expect(index?.options.unique).toBe(true);
    // Sparse, so many entries with no scan (baselines) can coexist.
    expect(index?.options.sparse).toBe(true);
  });

  it('declares no TTL index: the ledger is the audit trail', () => {
    const withTtl = indexesOf(SecurityDebtHistoryModel).filter(
      (index) => index.options.expireAfterSeconds !== undefined,
    );

    expect(withTtl).toEqual([]);
  });

  it('indexes the trend-chart read path', () => {
    expect(indexNamed(SecurityDebtHistoryModel, 'repository_recent')?.key).toBe(
      'repository:1,recordedAt:-1',
    );
  });
});
