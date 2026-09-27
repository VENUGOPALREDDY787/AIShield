import { describe, expect, it } from 'vitest';
import { AIContextualAnalyzer, MockProvider } from '@aishield/ai-analyzer';
import type { NormalizedFinding } from '@aishield/shared';
import { AIContextRunner } from '../ai-runner.js';

describe('AIContextRunner', () => {
  it('reports correct identity and display name', () => {
    const runner = new AIContextRunner();
    expect(runner.id).toBe('ai-analyzer');
    expect(runner.displayName).toBe('AI Contextual Logic & Risk Analyzer');
  });

  it('executes AI contextual analysis and returns normalized findings', async () => {
    const mockFinding = {
      category: 'security' as const,
      title: 'Missing Authorization Check on Role Assignment',
      description: 'Admins role can be self-assigned by arbitrary users.',
      severity: 'critical' as const,
      confidence: 0.95,
      file: 'src/routes/roles.ts',
      line: 30,
      evidence: 'user.roles.push(req.body.role);',
      remediation: 'Verify caller has admin permission before assigning privileged roles.',
      reasoning_summary: 'Role endpoint lacks authorization middleware check.',
    };

    const mockProvider = new MockProvider({
      mockResponse: JSON.stringify({ findings: [mockFinding] }),
    });

    const analyzer = new AIContextualAnalyzer(mockProvider);
    const runner = new AIContextRunner(analyzer);

    const result = await runner.execute({
      scanId: 'scan-ai-1',
      repoPath: 'owner/repo',
      diffContent: '+ user.roles.push(req.body.role);',
    });

    expect(result.scanner).toBe('ai-analyzer');
    expect(result.status).toBe('succeeded');
    expect(result.findings.length).toBe(1);

    const f = result.findings[0] as NormalizedFinding;
    expect(f.source).toBe('ai-analyzer');
    expect(f.title).toBe('Missing Authorization Check on Role Assignment');
    expect(f.severity).toBe('critical');
    expect(f.file).toBe('src/routes/roles.ts');
    expect(f.line).toBe(30);
  });

  it('tolerates analyzer failure gracefully without throwing', async () => {
    const mockProvider = new MockProvider({
      shouldFail: true,
      failureError: new Error('API key invalid'),
    });

    const analyzer = new AIContextualAnalyzer(mockProvider);
    const runner = new AIContextRunner(analyzer);

    const result = await runner.execute({
      scanId: 'scan-ai-fail',
      repoPath: 'owner/repo',
      diffContent: '+ const x = 1;',
    });

    expect(result.scanner).toBe('ai-analyzer');
    expect(result.status).toBe('failed');
    expect(result.findings).toEqual([]);
    expect(result.error).toContain('API key invalid');
  });
});
