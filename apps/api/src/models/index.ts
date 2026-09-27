/**
 * Model registry.
 *
 * Importing this module registers all eight schemas on the mongoose connection,
 * which is what makes `ref` population work: a `ref: 'Finding'` is only
 * resolvable once `FindingModel` has been created.
 *
 * ## Relationship map
 *
 * ```
 * User ──owns──────────────────────────────┐
 *                                          ▼
 * Repository ──has many──▶ PullRequest ──┐
 *     │                                  │
 *     ├──has many──▶ Scan ◀──────────────┘   (Scan.pullRequest)
 *     │                │  ▲
 *     │                │  └── firstSeenScan / lastSeenScan ──┐
 *     │                ▼                                      │
 *     │           Finding ◀──────────────────────────────────┘
 *     │                │
 *     │                └──has many──▶ RemediationSuggestion
 *     │
 *     ├──has one──▶ SecurityDebt
 *     └──has many─▶ SecurityDebtHistory
 * ```
 *
 * Cardinality summary:
 *  - `Repository` → `SecurityDebt` is **1:1** (unique index on `repository`).
 *  - `Repository` → `Scan` is **1:N**; at most one scan may be in flight
 *    (partial unique index).
 *  - `Scan` → `Finding` is **N:M in time**: a finding is a durable issue keyed
 *    by `(repository, fingerprint)`, so a scan observes it rather than owning
 *    it. `Scan.findings` records the observations.
 *  - `Finding` → `RemediationSuggestion` is **1:N** (several models/versions may
 *    propose a fix for the same issue).
 *  - `SecurityDebt` → `SecurityDebtHistory` is **1:N** and time-ordered.
 */
export * from './enums.js';
export * from './validators.js';

export * from './user.model.js';
export * from './repository.model.js';
export * from './pull-request.model.js';
export * from './scan.model.js';
export * from './finding.model.js';
export * from './security-debt.model.js';
export * from './security-debt-history.model.js';
export * from './remediation-suggestion.model.js';

export { defineModel } from './registry.js';
export { toJsonPlugin } from './plugins/to-json.plugin.js';
