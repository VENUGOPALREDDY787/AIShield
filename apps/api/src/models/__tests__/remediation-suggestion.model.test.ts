import { describe, expect, it } from 'vitest';
import {
  PATCH_CONTENT_MAX_LENGTH,
  RemediationSuggestionModel,
} from '../remediation-suggestion.model.js';
import { indexNamed, invalidPaths, oid } from './helpers.js';

const minimalSuggestion = () => ({
  finding: oid(),
  repository: oid(),
  kind: 'patch',
  title: 'Use a parameterised query',
});

const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

describe('RemediationSuggestion model', () => {
  it('accepts a minimal suggestion and applies defaults', () => {
    const suggestion = new RemediationSuggestionModel(minimalSuggestion());

    expect(invalidPaths(suggestion)).toEqual([]);
    expect(suggestion.status).toBe('proposed');
    expect(suggestion.priority).toBe('medium');
    expect(suggestion.patch?.format).toBe('unified_diff');
    expect(suggestion.steps).toEqual([]);
    expect(suggestion.references).toEqual([]);
    expect(suggestion.generator?.generatedAt).toBeInstanceOf(Date);
  });

  it('requires a finding, a repository, a kind and a title', () => {
    expect(invalidPaths(new RemediationSuggestionModel({}))).toEqual([
      'finding',
      'kind',
      'repository',
      'title',
    ]);
  });

  describe('patch safety', () => {
    it('refuses a patch that contains a credential literal', () => {
      const suggestion = new RemediationSuggestionModel({
        ...minimalSuggestion(),
        patch: { content: `+const awsKey = "${AWS_KEY}";` },
      });

      expect(invalidPaths(suggestion)).toContain('patch.content');
    });

    it('accepts a patch that references the secret indirectly', () => {
      const suggestion = new RemediationSuggestionModel({
        ...minimalSuggestion(),
        patch: {
          format: 'unified_diff',
          content: '+const awsKey = process.env.AWS_ACCESS_KEY_ID;',
        },
      });

      expect(invalidPaths(suggestion)).toEqual([]);
      expect(suggestion.patch?.content).toContain('process.env.AWS_ACCESS_KEY_ID');
    });

    it('caps the patch size', () => {
      const suggestion = new RemediationSuggestionModel({
        ...minimalSuggestion(),
        patch: { content: 'x'.repeat(PATCH_CONTENT_MAX_LENGTH + 1) },
      });

      expect(invalidPaths(suggestion)).toContain('patch.content');
    });
  });

  describe('applied state', () => {
    it('requires appliedAt once applied', () => {
      const suggestion = new RemediationSuggestionModel({
        ...minimalSuggestion(),
        status: 'applied',
      });

      expect(invalidPaths(suggestion)).toContain('appliedAt');
    });

    it('requires the status to be "applied" once appliedAt is set', () => {
      const suggestion = new RemediationSuggestionModel({
        ...minimalSuggestion(),
        status: 'accepted',
        appliedAt: new Date(),
      });

      expect(invalidPaths(suggestion)).toContain('status');
    });

    it('accepts a consistent applied suggestion', () => {
      const suggestion = new RemediationSuggestionModel({
        ...minimalSuggestion(),
        status: 'applied',
        appliedAt: new Date('2026-01-03T00:00:00.000Z'),
        appliedCommitSha: 'd'.repeat(40),
      });

      expect(invalidPaths(suggestion)).toEqual([]);
    });
  });

  it('bounds the estimated score impact', () => {
    const suggestion = new RemediationSuggestionModel({
      ...minimalSuggestion(),
      estimatedImpact: { scorePoints: 150 },
    });

    expect(invalidPaths(suggestion)).toContain('estimatedImpact.scorePoints');
  });

  it('requires documentation references to be https', () => {
    const suggestion = new RemediationSuggestionModel({
      ...minimalSuggestion(),
      references: [{ title: 'OWASP guidance', url: 'http://owasp.org/example' }],
    });

    expect(invalidPaths(suggestion)).toContain('references.0.url');
  });

  it('makes generation idempotent through a unique dedupe hash', () => {
    const index = indexNamed(RemediationSuggestionModel, 'uniq_dedupe');

    expect(index?.key).toBe('dedupeHash:1');
    expect(index?.options.unique).toBe(true);
    expect(index?.options.sparse).toBe(true);
  });

  it('indexes the remediation backlog', () => {
    expect(indexNamed(RemediationSuggestionModel, 'repository_backlog')?.key).toBe(
      'repository:1,status:1,priority:1,createdAt:-1',
    );
  });
});
