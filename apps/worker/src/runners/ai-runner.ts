import { AIContextualAnalyzer } from '@aishield/ai-analyzer';
import type { IScannerRunner, ScannerExecutionContext, ScannerExecutionResult } from './types.js';

export class AIContextRunner implements IScannerRunner {
  readonly id = 'ai-analyzer';
  readonly displayName = 'AI Contextual Logic & Risk Analyzer';
  private readonly analyzer: AIContextualAnalyzer;

  constructor(analyzer?: AIContextualAnalyzer) {
    this.analyzer = analyzer || new AIContextualAnalyzer();
  }

  async execute(ctx: ScannerExecutionContext): Promise<ScannerExecutionResult> {
    const started = Date.now();

    try {
      // Run AI contextual security analysis
      const res = await this.analyzer.analyzeAndNormalize({
        scanId: ctx.scanId,
        diffContent: ctx.diffContent || '',
        deterministicFindings: ctx.deterministicFindings || [],
        repositoryContext: {
          repoName: ctx.repoPath,
        },
      });

      return {
        scanner: this.id,
        status: res.status as 'succeeded' | 'failed' | 'skipped',
        durationMs: Date.now() - started,
        findings: res.findings,
        error: res.error,
      };
    } catch (err) {
      return {
        scanner: this.id,
        status: 'failed',
        durationMs: Date.now() - started,
        findings: [],
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
