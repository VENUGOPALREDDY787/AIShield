export * from './types.js';
export * from './security-scanner.interface.js';
export * from './base-scanner.js';
export * from './command-executor.js';
export * from './semgrep-scanner.js';
export * from './gitleaks-scanner.js';
export * from './dependency-scanner.js';
export * from './scanner-orchestrator.js';

import { SemgrepScanner } from './semgrep-scanner.js';
import { GitleaksScanner } from './gitleaks-scanner.js';
import { DependencyScanner } from './dependency-scanner.js';
import { ScannerOrchestrator } from './scanner-orchestrator.js';

/**
 * Creates a pre-configured ScannerOrchestrator with standard adapters.
 */
export function createDefaultOrchestrator(): ScannerOrchestrator {
  return new ScannerOrchestrator([
    new SemgrepScanner(),
    new GitleaksScanner(),
    new DependencyScanner(),
  ]);
}
