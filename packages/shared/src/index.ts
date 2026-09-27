/**
 * @aishield/shared
 *
 * The single source of truth for contracts crossing a process or package
 * boundary: queue names, scanner descriptors, scan domain models and HTTP
 * envelopes. It contains types and pure constants only — no I/O, no side
 * effects — so it is safe to import from the API, the worker, the scanner
 * images and the browser bundle alike.
 */

export * from './constants/queues.js';
export * from './constants/scanners.js';
export * from './constants/scoring.js';
export * from './types/api.js';
export * from './types/debt.js';
export * from './types/finding.js';
export * from './types/github.js';
export * from './types/job.js';
export * from './types/policy.js';
export * from './types/pr-delta.js';
export * from './types/scan.js';
export * from './utils/redaction.js';
export * from './utils/security.js';
