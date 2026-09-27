import { describe, expect, it } from 'vitest';
import { PullRequestModel } from '../pull-request.model.js';
import { indexNamed, invalidPaths, oid } from './helpers.js';

const minimalPullRequest = () => ({
  repository: oid(),
  number: 42,
  title: 'Parameterise the user lookup',
  author: { login: 'octocat' },
  baseBranch: 'main',
  headBranch: 'fix/sql-injection',
});

const HEAD_SHA = 'a'.repeat(40);

describe('PullRequest model', () => {
  it('accepts a minimal pull request and applies defaults', () => {
    const pullRequest = new PullRequestModel(minimalPullRequest());

    expect(invalidPaths(pullRequest)).toEqual([]);
    expect(pullRequest.state).toBe('open');
    expect(pullRequest.isDraft).toBe(false);
    expect(pullRequest.scanStatus).toBe('queued');
    expect(pullRequest.findingsIntroduced).toBe(0);
    expect(pullRequest.findingsResolved).toBe(0);
    expect(pullRequest.scoreDelta).toBe(0);
    expect(pullRequest.openedAt).toBeInstanceOf(Date);
  });

  it('requires a repository, a number, a title and both branches', () => {
    expect(invalidPaths(new PullRequestModel({}))).toEqual([
      'author',
      'baseBranch',
      'headBranch',
      'number',
      'repository',
      'title',
    ]);
  });

  it('rejects a non-positive pull request number', () => {
    const pullRequest = new PullRequestModel({ ...minimalPullRequest(), number: 0 });

    expect(invalidPaths(pullRequest)).toContain('number');
  });

  it('validates commit SHAs', () => {
    expect(
      invalidPaths(new PullRequestModel({ ...minimalPullRequest(), headSha: HEAD_SHA })),
    ).toEqual([]);
    expect(
      invalidPaths(new PullRequestModel({ ...minimalPullRequest(), headSha: 'not-a-sha!' })),
    ).toContain('headSha');
  });

  describe('lifecycle invariants', () => {
    it('requires closedAt once merged', () => {
      const pullRequest = new PullRequestModel({
        ...minimalPullRequest(),
        state: 'merged',
        mergedAt: new Date('2026-01-02T00:00:00.000Z'),
      });

      expect(invalidPaths(pullRequest)).toContain('closedAt');
    });

    it('requires state to be "merged" when mergedAt is set', () => {
      const pullRequest = new PullRequestModel({
        ...minimalPullRequest(),
        state: 'closed',
        closedAt: new Date('2026-01-02T00:00:00.000Z'),
        mergedAt: new Date('2026-01-02T00:00:00.000Z'),
      });

      expect(invalidPaths(pullRequest)).toContain('state');
    });

    it('rejects a timeline that goes backwards', () => {
      const pullRequest = new PullRequestModel({
        ...minimalPullRequest(),
        openedAt: new Date('2026-01-10T00:00:00.000Z'),
        state: 'closed',
        closedAt: new Date('2026-01-01T00:00:00.000Z'),
      });

      expect(invalidPaths(pullRequest)).toContain('closedAt');
    });

    it('accepts a consistent merged timeline', () => {
      const pullRequest = new PullRequestModel({
        ...minimalPullRequest(),
        openedAt: new Date('2026-01-01T00:00:00.000Z'),
        state: 'merged',
        closedAt: new Date('2026-01-02T00:00:00.000Z'),
        mergedAt: new Date('2026-01-02T00:00:00.000Z'),
      });

      expect(invalidPaths(pullRequest)).toEqual([]);
    });
  });

  it('rejects an author login that is missing', () => {
    const pullRequest = new PullRequestModel({
      ...minimalPullRequest(),
      author: { providerAccountId: '1' },
    });

    expect(invalidPaths(pullRequest)).toContain('author.login');
  });

  it('declares a unique index on repository and number', () => {
    const index = indexNamed(PullRequestModel, 'uniq_repository_number');

    expect(index?.key).toBe('repository:1,number:1');
    expect(index?.options.unique).toBe(true);
  });

  it('indexes the head SHA so a scan can be attached to its pull request', () => {
    const index = indexNamed(PullRequestModel, 'repository_head_sha');

    expect(index?.key).toBe('repository:1,headSha:1');
  });
});
