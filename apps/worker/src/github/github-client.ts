import type {
  GitHubCheckRunPayload,
  UpsertCommentResult,
} from '@aishield/shared';
import { AISHIELD_COMMENT_MARKER } from './comment-formatter.js';

export interface GitHubClientOptions {
  readonly token: string;
  readonly baseUrl?: string;
  readonly userAgent?: string;
  readonly customFetch?: typeof fetch;
}

export interface GitHubPRDetails {
  readonly number: number;
  readonly title: string;
  readonly base: {
    readonly sha: string;
    readonly ref: string;
  };
  readonly head: {
    readonly sha: string;
    readonly ref: string;
  };
  readonly html_url: string;
  readonly isFork?: boolean;
}

export interface GitHubComment {
  readonly id: number;
  readonly body?: string;
  readonly user?: {
    readonly login: string;
    readonly type?: string;
  };
  readonly created_at: string;
  readonly updated_at: string;
  readonly html_url?: string;
}

export interface GitHubCheckRunResponse {
  readonly id: number;
  readonly name: string;
  readonly head_sha: string;
  readonly status: string;
  readonly conclusion: string | null;
  readonly html_url?: string;
}

interface RawGitHubPullRequest {
  readonly number: number;
  readonly title: string;
  readonly base: {
    readonly sha: string;
    readonly ref: string;
  };
  readonly head: {
    readonly sha: string;
    readonly ref: string;
    readonly repo?: {
      readonly fork?: boolean;
    };
  };
  readonly html_url: string;
}

export class GitHubApiError extends Error {
  public readonly status: number;
  public readonly isPermissionError: boolean;

  constructor(status: number, message: string, tokenToRedact?: string) {
    let sanitizedMessage = message;
    if (tokenToRedact && tokenToRedact.length > 3) {
      sanitizedMessage = sanitizedMessage.split(tokenToRedact).join('[REDACTED_TOKEN]');
    }
    super(`GitHub API Error (${status}): ${sanitizedMessage}`);
    this.name = 'GitHubApiError';
    this.status = status;
    this.isPermissionError = status === 403 || status === 401;
  }
}

/**
 * Robust GitHub API Client implementing least-privilege operations.
 *
 * Security Principles:
 * - Never prints or leaks GitHub tokens in errors or logs.
 * - Handles fork PR permissions (HTTP 403) gracefully.
 * - Strict Invariant: Contains ZERO auto-merge or approval methods.
 */
export class GitHubClient {
  private readonly token: string;
  private readonly baseUrl: string;
  private readonly userAgent: string;
  private readonly fetchFn: typeof fetch;

  constructor(options: GitHubClientOptions) {
    if (!options.token || options.token.trim().length === 0) {
      throw new Error('GitHub token is required to initialize GitHubClient');
    }
    this.token = options.token.trim();
    this.baseUrl = (options.baseUrl || 'https://api.github.com').replace(/\/+$/, '');
    this.userAgent = options.userAgent || 'AIShield-Security-Action';
    this.fetchFn = options.customFetch || globalThis.fetch;
  }

  /**
   * Internal request helper ensuring safe headers and token redaction.
   */
  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
  ): Promise<{ data: T; status: number }> {
    const url = `${this.baseUrl}${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;

    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${this.token}`,
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': this.userAgent,
      ...(options.headers as Record<string, string> | undefined),
    };

    let response: Response;
    try {
      response = await this.fetchFn(url, {
        ...options,
        headers,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new GitHubApiError(0, `Network request failed: ${msg}`, this.token);
    }

    if (!response.ok) {
      const errorText = await response.text().catch(() => '');
      throw new GitHubApiError(response.status, errorText || response.statusText, this.token);
    }

    if (response.status === 204) {
      return { data: undefined as unknown as T, status: response.status };
    }

    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const data = (await response.json()) as T;
      return { data, status: response.status };
    }

    const textData = (await response.text()) as unknown as T;
    return { data: textData, status: response.status };
  }

  /**
   * Fetches details of a Pull Request.
   */
  async getPullRequest(
    owner: string,
    repo: string,
    pullNumber: number,
  ): Promise<GitHubPRDetails> {
    const { data } = await this.request<RawGitHubPullRequest>(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls/${pullNumber}`,
    );

    return {
      number: data.number,
      title: data.title,
      base: {
        sha: data.base.sha,
        ref: data.base.ref,
      },
      head: {
        sha: data.head.sha,
        ref: data.head.ref,
      },
      html_url: data.html_url,
      isFork: data.head.repo?.fork ?? false,
    };
  }

  /**
   * Fetches the unified diff of a Pull Request safely.
   */
  async getPullRequestDiff(
    owner: string,
    repo: string,
    pullNumber: number,
  ): Promise<string> {
    const { data } = await this.request<string>(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/pulls/${pullNumber}`,
      {
        headers: {
          Accept: 'application/vnd.github.v3.diff',
        },
      },
    );
    return data;
  }

  /**
   * Lists comments on a Pull Request / Issue.
   */
  async listComments(
    owner: string,
    repo: string,
    issueNumber: number,
  ): Promise<GitHubComment[]> {
    const { data } = await this.request<GitHubComment[]>(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${issueNumber}/comments?per_page=100`,
    );
    return data;
  }

  /**
   * Creates a new comment on a Pull Request.
   */
  async createComment(
    owner: string,
    repo: string,
    issueNumber: number,
    body: string,
  ): Promise<GitHubComment> {
    const { data } = await this.request<GitHubComment>(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/${issueNumber}/comments`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ body }),
      },
    );
    return data;
  }

  /**
   * Updates an existing comment on a Pull Request.
   */
  async updateComment(
    owner: string,
    repo: string,
    commentId: number,
    body: string,
  ): Promise<GitHubComment> {
    const { data } = await this.request<GitHubComment>(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/issues/comments/${commentId}`,
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ body }),
      },
    );
    return data;
  }

  /**
   * Sticky PR Comment pattern:
   * Finds existing AIShield comment using hidden marker and updates it in place.
   * If none exists, creates a new comment.
   */
  async upsertStickyComment(
    owner: string,
    repo: string,
    issueNumber: number,
    body: string,
    marker: string = AISHIELD_COMMENT_MARKER,
  ): Promise<UpsertCommentResult> {
    const comments = await this.listComments(owner, repo, issueNumber);
    const existing = comments.find((c) => c.body && c.body.includes(marker));

    if (existing) {
      const updated = await this.updateComment(owner, repo, existing.id, body);
      return {
        commentId: updated.id,
        action: 'updated',
        url: updated.html_url,
      };
    }

    const created = await this.createComment(owner, repo, issueNumber, body);
    return {
      commentId: created.id,
      action: 'created',
      url: created.html_url,
    };
  }

  /**
   * Creates a Check Run on the commit.
   */
  async createCheckRun(
    owner: string,
    repo: string,
    payload: GitHubCheckRunPayload,
  ): Promise<GitHubCheckRunResponse> {
    const { data } = await this.request<GitHubCheckRunResponse>(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/check-runs`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      },
    );
    return data;
  }

  /**
   * Updates an existing Check Run.
   */
  async updateCheckRun(
    owner: string,
    repo: string,
    checkRunId: number,
    payload: Partial<GitHubCheckRunPayload>,
  ): Promise<GitHubCheckRunResponse> {
    const { data } = await this.request<GitHubCheckRunResponse>(
      `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/check-runs/${checkRunId}`,
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      },
    );
    return data;
  }
}
