/**
 * Enumerations that belong to the persistence layer only.
 *
 * Values that cross a process boundary (severities, scan statuses, scanner ids,
 * finding categories) live in `@aishield/shared` and are imported directly from
 * there — duplicating them here would let the API and the worker drift apart.
 */

/** What kicked off a scan. */
export const SCAN_TRIGGERS = ['manual', 'push', 'pull_request', 'schedule', 'api'] as const;
export type ScanTrigger = (typeof SCAN_TRIGGERS)[number];

/** Progress of the AI analysis stage, tracked separately from the scan itself. */
export const AI_ANALYSIS_STATUSES = [
  'not_requested',
  'queued',
  'running',
  'completed',
  'failed',
  'skipped',
] as const;
export type AiAnalysisStatus = (typeof AI_ANALYSIS_STATUSES)[number];

/** Triage state of a durable finding. */
export const FINDING_STATUSES = [
  'open',
  'fixed',
  'false_positive',
  'ignored',
  'risk_accepted',
] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

/** Terminal statuses: no further scanning will flip these back to `open`. */
export const CLOSED_FINDING_STATUSES: readonly FindingStatus[] = [
  'fixed',
  'false_positive',
  'ignored',
  'risk_accepted',
];

export const REPOSITORY_PROVIDERS = ['github', 'gitlab', 'bitbucket'] as const;
export type RepositoryProvider = (typeof REPOSITORY_PROVIDERS)[number];

export const USER_ROLES = ['viewer', 'member', 'maintainer', 'admin', 'owner'] as const;
export type UserRole = (typeof USER_ROLES)[number];

export const USER_STATUSES = ['active', 'invited', 'suspended', 'deleted'] as const;
export type UserStatus = (typeof USER_STATUSES)[number];

export const PULL_REQUEST_STATES = ['open', 'closed', 'merged', 'draft'] as const;
export type PullRequestState = (typeof PULL_REQUEST_STATES)[number];

export const RISK_LEVELS = ['low', 'medium', 'high'] as const;
export type RiskLevel = (typeof RISK_LEVELS)[number];

export const REACHABILITY = ['reachable', 'unreachable', 'unknown'] as const;
export type Reachability = (typeof REACHABILITY)[number];

export const REMEDIATION_KINDS = [
  'patch',
  'explanation',
  'dependency_upgrade',
  'config_change',
  'test',
] as const;
export type RemediationKind = (typeof REMEDIATION_KINDS)[number];

export const REMEDIATION_STATUSES = [
  'proposed',
  'accepted',
  'rejected',
  'applied',
  'superseded',
  'failed',
] as const;
export type RemediationStatus = (typeof REMEDIATION_STATUSES)[number];

export const REMEDIATION_EFFORTS = ['trivial', 'small', 'medium', 'large'] as const;
export type RemediationEffort = (typeof REMEDIATION_EFFORTS)[number];

export const PATCH_FORMATS = ['unified_diff', 'snippet', 'json_patch'] as const;
export type PatchFormat = (typeof PATCH_FORMATS)[number];

/** Dependency ecosystems understood by the dependency scanner. */
export const DEPENDENCY_ECOSYSTEMS = [
  'npm',
  'pypi',
  'maven',
  'go',
  'cargo',
  'nuget',
  'composer',
  'rubygems',
  'other',
] as const;
export type DependencyEcosystem = (typeof DEPENDENCY_ECOSYSTEMS)[number];

/** Why a `SecurityDebtHistory` row was written. */
export const DEBT_HISTORY_EVENTS = [
  'baseline',
  'scan_completed',
  'manual_recalculation',
  'remediation_applied',
] as const;
export type DebtHistoryEvent = (typeof DEBT_HISTORY_EVENTS)[number];

/** Direction of travel of the debt score, derived from the delta. */
export const DEBT_TRENDS = ['improving', 'stable', 'worsening'] as const;
export type DebtTrend = (typeof DEBT_TRENDS)[number];
