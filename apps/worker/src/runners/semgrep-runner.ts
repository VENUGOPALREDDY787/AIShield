import type { IScannerRunner, ScannerExecutionContext, ScannerExecutionResult } from './types.js';

export class SemgrepRunner implements IScannerRunner {
  readonly id = 'semgrep';
  readonly displayName = 'Semgrep SAST Scanner';

  async execute(_ctx: ScannerExecutionContext): Promise<ScannerExecutionResult> {
    const started = Date.now();
    // Stub execution contract: will spawn docker semgrep container or run local binary
    return {
      scanner: this.id,
      status: 'succeeded',
      durationMs: Date.now() - started,
      findings: [],
    };
  }
}
