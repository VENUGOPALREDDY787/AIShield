import type { IScannerRunner, ScannerExecutionContext, ScannerExecutionResult } from './types.js';

export class OSVRunner implements IScannerRunner {
  readonly id = 'dependency';
  readonly displayName = 'OSV Dependency Vulnerability Scanner';

  async execute(_ctx: ScannerExecutionContext): Promise<ScannerExecutionResult> {
    const started = Date.now();
    // Stub execution contract: will scan package manifests (lockfiles) against OSV database
    return {
      scanner: this.id,
      status: 'succeeded',
      durationMs: Date.now() - started,
      findings: [],
    };
  }
}
