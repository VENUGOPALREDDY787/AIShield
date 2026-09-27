/**
 * Canonical queue identifiers.
 *
 * These strings are a contract between the API (producer) and the worker
 * (consumer). They live in the shared package so a rename can never silently
 * desynchronise the two sides.
 */

/** Fallback prefix when `QUEUE_PREFIX` is not configured. */
export const QUEUE_PREFIX_DEFAULT = 'aishield';

/** Main scan orchestration queue. */
export const SCAN_QUEUE_NAME = 'scan';

/** Job name used for "scan a repository" work items. */
export const SCAN_JOB_NAME = 'scan:repository';

/** Queue that receives jobs which exhausted their retries, for triage. */
export const SCAN_DEAD_LETTER_QUEUE_NAME = 'scan-dead-letter';

export type ScanJobName = typeof SCAN_JOB_NAME;
