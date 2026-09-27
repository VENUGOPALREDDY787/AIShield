import type { IScannerRunner, ScannerExecutionContext, ScannerExecutionResult } from './types.js';

export class GitleaksRunner implements IScannerRunner {
  readonly id = 'gitleaks';
  readonly displayName = 'Gitleaks Secret Scanner';

  async execute(_ctx: ScannerExecutionContext): Promise<ScannerExecutionResult> {
    const started = Date.now();
    // Stub execution contract: will scan git history / diff for committed credentials
    return {
      scanner: this.id,
      status: 'succeeded',
      durationMs: Date.now() - started,
      findings: [],
    };
  }
}
