/**
 * Cross-model index audit.
 *
 * Indexes are the part of a data model that is cheapest to get wrong and most
 * expensive to discover in production: a missing one is a slow query, an
 * extra unique one is a write outage. These tests pin the whole index surface
 * of all eight collections so any change is a deliberate edit to this file.
 */
import { describe, expect, it } from 'vitest';
import {
  FindingModel,
  PullRequestModel,
  RemediationSuggestionModel,
  RepositoryModel,
  ScanModel,
  SecurityDebtHistoryModel,
  SecurityDebtModel,
  UserModel,
} from '../index.js';
import { type IndexedModel, indexesOf } from './helpers.js';

const MODELS: ReadonlyArray<{ name: string; model: IndexedModel }> = [
  { name: 'User', model: UserModel },
  { name: 'Repository', model: RepositoryModel },
  { name: 'PullRequest', model: PullRequestModel },
  { name: 'Scan', model: ScanModel },
  { name: 'Finding', model: FindingModel },
  { name: 'SecurityDebt', model: SecurityDebtModel },
  { name: 'SecurityDebtHistory', model: SecurityDebtHistoryModel },
  { name: 'RemediationSuggestion', model: RemediationSuggestionModel },
];

function qualifiedIndexNames(options: { uniqueOnly?: boolean } = {}): string[] {
  return MODELS.flatMap(({ name, model }) =>
    indexesOf(model)
      .filter((index) => !options.uniqueOnly || index.options.unique === true)
      .map((index) => `${name}.${String(index.options.name)}`),
  ).sort();
}

describe('index conventions', () => {
  it('names every index explicitly', () => {
    const unnamed: string[] = [];

    for (const { name, model } of MODELS) {
      for (const index of indexesOf(model)) {
        if (typeof index.options.name !== 'string' || index.options.name.length === 0) {
          unnamed.push(`${name}:${index.key}`);
        }
      }
    }

    // An auto-generated name cannot be referenced in a migration or an
    // explain() plan, so an unnamed index is treated as a defect.
    expect(unnamed).toEqual([]);
  });

  it('gives no model two indexes with the same name', () => {
    for (const { name, model } of MODELS) {
      const names = indexesOf(model).map((index) => index.options.name);

      expect(new Set(names).size, `${name} declares a duplicate index name`).toBe(names.length);
    }
  });

  it('declares no TTL index anywhere', () => {
    const withTtl = MODELS.flatMap(({ name, model }) =>
      indexesOf(model)
        .filter((index) => index.options.expireAfterSeconds !== undefined)
        .map((index) => `${name}.${String(index.options.name)}`),
    );

    // Findings and debt history are the product; they expire by triage, not by
    // a server-side timer that quietly deletes evidence.
    expect(withTtl).toEqual([]);
  });

  it('gives every collection a repository-scoped leading key or a documented exception', () => {
    const exceptions = new Set(['User', 'Repository']);

    for (const { name, model } of MODELS) {
      if (exceptions.has(name)) continue;

      const indexes = indexesOf(model);
      const repositoryScoped = indexes.filter((index) => index.key.startsWith('repository:1'));

      expect(repositoryScoped.length, `${name} has no repository-scoped index`).toBeGreaterThan(0);
    }
  });

  it('enforces exactly the intended unique constraints', () => {
    // Every entry here is a deliberate data-integrity guarantee. Adding one
    // silently can reject legitimate writes; removing one allows duplicates.
    expect(qualifiedIndexNames({ uniqueOnly: true })).toEqual(
      [
        'Finding.uniq_repository_fingerprint',
        'PullRequest.uniq_repository_number',
        'RemediationSuggestion.uniq_dedupe',
        'Repository.uniq_provider_full_name',
        'Repository.uniq_provider_repo',
        'Scan.one_active_scan_per_repository',
        'SecurityDebt.uniq_repository',
        'SecurityDebtHistory.uniq_repository_scan',
        'User.uniq_email',
        'User.uniq_provider_account',
      ].sort(),
    );
  });

  it('scopes the one-active-scan constraint to in-flight statuses only', () => {
    const scan = MODELS.find((entry) => entry.name === 'Scan');
    const index = indexesOf(scan!.model).find(
      (entry) => entry.options.name === 'one_active_scan_per_repository',
    );

    // Unscoped, this would allow a repository to ever have only one scan.
    expect(index?.options.partialFilterExpression).toEqual({
      status: { $in: ['queued', 'running'] },
    });
  });
});
