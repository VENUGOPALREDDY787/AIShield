import { describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type {
  PRDeltaAnalysisResult,
  SecurityDebtResult,
} from '@aishield/shared';
import { GitHubApiError, type GitHubClient } from '../github-client.js';
import { PRReporter } from '../pr-reporter.js';

function createMockDelta(): PRDeltaAnalysisResult {
  return {
    baseCommit: 'base123',
    headCommit: 'head456',
    baseScore: 10,
    headScore: 25,
    newDebt: 0,
    resolvedDebt: 0,
    netDebtChange: 0,
    findingsIntroduced: [],
    findingsResolved: [],
    findingsModified: [],
    findingsUnchanged: [],
    totalHeadFindings: 1,
    totalBaseFindings: 1,
    changedFilesCount: 1,
    summary: 'PR introduced 1 issue',
  };
}

function createMockDebt(): SecurityDebtResult {
  return {
    score: 25,
    riskLevel: 'MEDIUM',
    previousScore: 10,
    delta: 15,
    newDebt: 15,
    resolvedDebt: 0,
    severityBreakdown: {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 1,
      LOW: 0,
      INFO: 0,
    },
    categoryBreakdown: {
      injection: 0,
      authentication: 0,
      authorization: 0,
      secrets: 0,
      cryptography: 0,
      data_exposure: 0,
      dependency: 0,
      input_validation: 1,
      command_execution: 0,
      configuration: 0,
      business_logic: 0,
      other: 0,
    },
    topContributors: [],
    totalDebtPoints: 12,
    formulaSummary: 'Deterministic debt formula',
  };
}

describe('PRReporter', () => {
  it('publishes PR comment, creates Check Run, and writes step summary', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'aishield-step-'));
    const stepSummaryPath = join(tempDir, 'summary.md');

    const mockClient = {
      upsertStickyComment: vi.fn().mockResolvedValue({
        commentId: 101,
        action: 'created',
        url: 'https://github.com/owner/repo/pull/5#issuecomment-101',
      }),
      createCheckRun: vi.fn().mockResolvedValue({
        id: 777,
        name: 'AIShield Security Debt',
        conclusion: 'success',
      }),
    } as unknown as GitHubClient;

    const reporter = new PRReporter(mockClient);

    const result = await reporter.reportPullRequest(
      createMockDelta(),
      createMockDebt(),
      {
        owner: 'octocat',
        repo: 'hello-world',
        pullNumber: 5,
        headSha: 'head456',
        stepSummaryPath,
      },
    );

    expect(result.commentResult?.commentId).toBe(101);
    expect(result.checkRunId).toBe(777);
    expect(result.conclusion).toBe('success');
    expect(result.stepSummaryWritten).toBe(true);
    expect(result.warnings).toHaveLength(0);

    const summaryContent = readFileSync(stepSummaryPath, 'utf-8');
    expect(summaryContent).toContain('AIShield Security Report');
    expect(summaryContent).toContain('Overall Security Debt:');
    expect(summaryContent).toContain('25/100');

    rmSync(tempDir, { recursive: true, force: true });
  });

  it('tolerates permission errors gracefully on forked PRs with read-only tokens', async () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'aishield-fork-'));
    const stepSummaryPath = join(tempDir, 'summary.md');

    const permError = new GitHubApiError(
      403,
      'Resource not accessible by integration',
    );

    const mockClient = {
      upsertStickyComment: vi.fn().mockRejectedValue(permError),
      createCheckRun: vi.fn().mockRejectedValue(permError),
    } as unknown as GitHubClient;

    const reporter = new PRReporter(mockClient);

    const result = await reporter.reportPullRequest(
      createMockDelta(),
      createMockDebt(),
      {
        owner: 'octocat',
        repo: 'hello-world',
        pullNumber: 5,
        headSha: 'head456',
        stepSummaryPath,
      },
    );

    // Verifies the reporter did NOT throw or crash
    expect(result.warnings).toHaveLength(2);
    expect(result.warnings[0]).toContain('Token lacks pull-requests write permissions');
    expect(result.warnings[1]).toContain('Token lacks checks write permissions');
    expect(result.stepSummaryWritten).toBe(true);

    // Summary was still written despite API 403
    const summaryContent = readFileSync(stepSummaryPath, 'utf-8');
    expect(summaryContent).toContain('AIShield Security Report');

    rmSync(tempDir, { recursive: true, force: true });
  });
});
