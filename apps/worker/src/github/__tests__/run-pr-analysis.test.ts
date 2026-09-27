import { describe, expect, it, vi } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { GitHubClient } from '../github-client.js';
import {
  getDiffSafely,
  resolveConfigFromEnv,
  runPRAnalysis,
} from '../run-pr-analysis.js';

describe('GitHub Actions PR Analysis Runner', () => {
  it('resolves configuration correctly from mock GITHUB_EVENT_PATH', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'event-test-'));
    const eventPath = join(tempDir, 'event.json');

    const mockEvent = {
      pull_request: {
        number: 88,
        base: { sha: 'base-commit-sha-1' },
        head: { sha: 'head-commit-sha-2' },
      },
      repository: {
        full_name: 'testorg/testrepo',
      },
    };

    writeFileSync(eventPath, JSON.stringify(mockEvent), 'utf-8');

    const config = resolveConfigFromEnv({
      eventPath,
      githubToken: 'test-token',
      repository: 'testorg/testrepo',
    });

    expect(config.prNumber).toBe(88);
    expect(config.baseSha).toBe('base-commit-sha-1');
    expect(config.headSha).toBe('head-commit-sha-2');
    expect(config.repository).toBe('testorg/testrepo');
    expect(config.githubToken).toBe('test-token');

    rmSync(tempDir, { recursive: true, force: true });
  });

  it('runs analysis in dry-run mode without external network calls', async () => {
    const tempRepo = mkdtempSync(join(tmpdir(), 'repo-test-'));

    // Create a dummy file
    writeFileSync(join(tempRepo, 'index.ts'), 'console.log("hello world");\n', 'utf-8');

    const result = await runPRAnalysis({
      repoPath: tempRepo,
      dryRun: true,
      baseSha: 'base-sha',
      headSha: 'head-sha',
      prNumber: 12,
      repository: 'testorg/testrepo',
      diffContent: '',
    });

    expect(result.deltaResult).toBeDefined();
    expect(result.debtResult).toBeDefined();
    expect(result.deltaResult.baseCommit).toBe('base-sha');
    expect(result.deltaResult.headCommit).toBe('head-sha');
    expect(result.debtResult.score).toBeGreaterThanOrEqual(0);

    rmSync(tempRepo, { recursive: true, force: true });
  });

  describe('getDiffSafely', () => {
    it('uses GitHub API when client and PR number are provided', async () => {
      const mockDiff = 'diff --git a/index.ts b/index.ts\n+const a = 1;\n';
      const mockClient = {
        getPullRequestDiff: vi.fn().mockResolvedValue(mockDiff),
      } as unknown as GitHubClient;

      const diff = await getDiffSafely(
        mockClient,
        'owner',
        'repo',
        42,
        'baseSha',
        'headSha',
        process.cwd(),
      );

      expect(diff).toBe(mockDiff);
      expect(mockClient.getPullRequestDiff).toHaveBeenCalledWith('owner', 'repo', 42);
    });

    it('falls back gracefully when API diff throws and local git is unavailable', async () => {
      const mockClient = {
        getPullRequestDiff: vi.fn().mockRejectedValue(new Error('API rate limit')),
      } as unknown as GitHubClient;

      const nonExistentDir = join(tmpdir(), 'non-existent-dir-' + Date.now());

      const diff = await getDiffSafely(
        mockClient,
        'owner',
        'repo',
        42,
        'baseSha',
        'headSha',
        nonExistentDir,
      );

      // Returns empty string safely instead of crashing
      expect(diff).toBe('');
    });
  });
});
