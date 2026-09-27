import { describe, expect, it, vi } from 'vitest';
import { AISHIELD_COMMENT_MARKER } from '../comment-formatter.js';
import { GitHubApiError, GitHubClient } from '../github-client.js';

describe('GitHubClient', () => {
  it('throws an error if initialized with an empty token', () => {
    expect(() => new GitHubClient({ token: '' })).toThrow(/GitHub token is required/);
    expect(() => new GitHubClient({ token: '   ' })).toThrow(/GitHub token is required/);
  });

  it('redacts the auth token from error messages', () => {
    const secretToken = 'ghp_secretTokenThatMustNeverLeak123';
    const err = new GitHubApiError(
      401,
      `Bad credentials with ${secretToken} in response`,
      secretToken,
    );

    expect(err.message).not.toContain(secretToken);
    expect(err.message).toContain('[REDACTED_TOKEN]');
    expect(err.isPermissionError).toBe(true);
  });

  it('fetches pull request details safely', async () => {
    const mockResponse = {
      number: 42,
      title: 'Fix auth bug',
      base: { sha: 'base-sha-123', ref: 'main' },
      head: { sha: 'head-sha-456', ref: 'feature-branch' },
      html_url: 'https://github.com/owner/repo/pull/42',
      head_repo: { fork: false },
    };

    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'application/json' }),
      json: async () => mockResponse,
    });

    const client = new GitHubClient({
      token: 'fake-token',
      customFetch: mockFetch as unknown as typeof fetch,
    });

    const pr = await client.getPullRequest('owner', 'repo', 42);

    expect(pr.number).toBe(42);
    expect(pr.base.sha).toBe('base-sha-123');
    expect(pr.head.sha).toBe('head-sha-456');
    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.github.com/repos/owner/repo/pulls/42',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer fake-token',
          Accept: 'application/vnd.github+json',
        }),
      }),
    );
  });

  it('fetches pull request unified diff with correct headers', async () => {
    const mockDiff = 'diff --git a/file.ts b/file.ts\n--- a/file.ts\n+++ b/file.ts\n@@ -1 +1 @@\n-old\n+new\n';
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: new Headers({ 'content-type': 'text/plain' }),
      text: async () => mockDiff,
    });

    const client = new GitHubClient({
      token: 'fake-token',
      customFetch: mockFetch as unknown as typeof fetch,
    });

    const diff = await client.getPullRequestDiff('owner', 'repo', 10);

    expect(diff).toBe(mockDiff);
    expect(mockFetch).toHaveBeenCalledWith(
      'https://api.github.com/repos/owner/repo/pulls/10',
      expect.objectContaining({
        headers: expect.objectContaining({
          Accept: 'application/vnd.github.v3.diff',
        }),
      }),
    );
  });

  describe('upsertStickyComment', () => {
    it('creates a new comment if no existing comment contains the marker', async () => {
      const existingComments = [
        { id: 101, body: 'Hello world', user: { login: 'user1' } },
        { id: 102, body: 'Code looks good', user: { login: 'reviewer' } },
      ];

      const mockFetch = vi.fn()
        // 1st call: listComments
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => existingComments,
        })
        // 2nd call: createComment
        .mockResolvedValueOnce({
          ok: true,
          status: 201,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ id: 200, html_url: 'https://github.com/c/200' }),
        });

      const client = new GitHubClient({
        token: 'fake-token',
        customFetch: mockFetch as unknown as typeof fetch,
      });

      const result = await client.upsertStickyComment(
        'owner',
        'repo',
        7,
        `${AISHIELD_COMMENT_MARKER}\n# Report`,
      );

      expect(result.action).toBe('created');
      expect(result.commentId).toBe(200);
      expect(mockFetch).toHaveBeenCalledTimes(2);

      // Verify POST call was made to create comment
      const postCall = mockFetch.mock.calls[1];
      expect(postCall).toBeDefined();
      expect(postCall?.[0]).toBe('https://api.github.com/repos/owner/repo/issues/7/comments');
      expect((postCall?.[1] as RequestInit | undefined)?.method).toBe('POST');
    });

    it('updates existing comment when matching marker is found, preventing duplicates', async () => {
      const existingComments = [
        { id: 101, body: 'Irrelevant comment' },
        { id: 105, body: `${AISHIELD_COMMENT_MARKER}\n# Previous Old AIShield Report` },
      ];

      const mockFetch = vi.fn()
        // 1st call: listComments
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => existingComments,
        })
        // 2nd call: updateComment
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          headers: new Headers({ 'content-type': 'application/json' }),
          json: async () => ({ id: 105, html_url: 'https://github.com/c/105' }),
        });

      const client = new GitHubClient({
        token: 'fake-token',
        customFetch: mockFetch as unknown as typeof fetch,
      });

      const newBody = `${AISHIELD_COMMENT_MARKER}\n# Updated AIShield Report`;
      const result = await client.upsertStickyComment('owner', 'repo', 7, newBody);

      expect(result.action).toBe('updated');
      expect(result.commentId).toBe(105);
      expect(mockFetch).toHaveBeenCalledTimes(2);

      // Verify PATCH call was made to comment 105
      const patchCall = mockFetch.mock.calls[1];
      expect(patchCall).toBeDefined();
      expect(patchCall?.[0]).toBe('https://api.github.com/repos/owner/repo/issues/comments/105');
      const patchOptions = patchCall?.[1] as RequestInit | undefined;
      expect(patchOptions?.method).toBe('PATCH');
      expect(JSON.parse((patchOptions?.body as string) || '{}')).toEqual({ body: newBody });
    });
  });

  describe('createCheckRun', () => {
    it('creates a check run with provided payload', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 201,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({
          id: 555,
          name: 'AIShield Security Debt',
          head_sha: 'sha1',
          status: 'completed',
          conclusion: 'success',
        }),
      });

      const client = new GitHubClient({
        token: 'fake-token',
        customFetch: mockFetch as unknown as typeof fetch,
      });

      const res = await client.createCheckRun('owner', 'repo', {
        name: 'AIShield Security Debt',
        head_sha: 'sha1',
        status: 'completed',
        conclusion: 'success',
        output: {
          title: 'All Good',
          summary: 'No issues found',
        },
      });

      expect(res.id).toBe(555);
      expect(res.conclusion).toBe('success');
    });

    it('identifies HTTP 403 permission errors on forked PRs with read-only tokens', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        statusText: 'Forbidden',
        headers: new Headers(),
        text: async () => 'Resource not accessible by integration',
      });

      const client = new GitHubClient({
        token: 'fake-token',
        customFetch: mockFetch as unknown as typeof fetch,
      });

      await expect(
        client.createCheckRun('owner', 'repo', {
          name: 'AIShield',
          head_sha: 'sha1',
          status: 'completed',
          output: { title: 'Test', summary: 'Test' },
        }),
      ).rejects.toMatchObject({
        status: 403,
        isPermissionError: true,
      });
    });
  });

  describe('Security Invariants', () => {
    it('strictly does not contain any automatic merge or auto-approval methods', () => {
      const proto = Object.getOwnPropertyNames(GitHubClient.prototype);
      const forbiddenTerms = ['merge', 'approve', 'automerge', 'acceptpr'];

      for (const prop of proto) {
        for (const term of forbiddenTerms) {
          expect(prop.toLowerCase()).not.toContain(term);
        }
      }
    });
  });
});
