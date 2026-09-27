# GitHub Branch Protection & AIShield Policy Configuration Guide

This guide documents how repository administrators can configure **GitHub Branch Protection Rules** and **AIShield Security Policy Thresholds** to enforce automated security gates on Pull Requests.

---

## 1. Security Check Verdicts

AIShield evaluates every pull request against configurable policy thresholds and publishes a GitHub Check Run (`AIShield Security Debt`):

| Verdict | GitHub Conclusion | Behavior & Merge Gate Impact |
| :--- | :--- | :--- |
| **`PASS`** | `success` | **All policy conditions met.** No critical findings, no exposed secrets, and security debt change is within acceptable thresholds. The check turns **green** and GitHub branch protection allows merging. |
| **`WARN`** | `neutral` | **Review recommended.** Advisory conditions triggered (e.g. medium or high findings requiring human review, or debt increase exceeding the advisory warning threshold). GitHub displays a **neutral/advisory** check. Merging is permitted unless branch protection requires strict approval. |
| **`FAIL`** | `failure` | **Policy threshold breached.** Severe issues introduced (e.g. critical vulnerability, exposed credentials/secrets, or debt threshold exceeded). The check turns **red** and GitHub branch protection **blocks the pull request from being merged**. |

---

## 2. Important Architectural Invariant: Zero Auto-Merges

> [!IMPORTANT]
> **AIShield never automatically merges pull requests.**
> 
> AIShield operates exclusively as an automated security advisor. Merge decisions are always owned by repository administrators, code owners, and developers. Merge gating is enforced via **GitHub's native Branch Protection Rules or Repository Rulesets**, which prevent merging when a required check reports `FAIL`.

---

## 3. Configuring GitHub Branch Protection (Step-by-Step)

Repository administrators can require the AIShield check to pass before any PR can be merged into protected branches (e.g., `main`, `master`, `production`).

### Method A: Using Classical Branch Protection Rules

1. **Navigate to Repository Settings:**
   - In your GitHub repository, click on the **Settings** tab.
2. **Access Branch Protection:**
   - In the left sidebar under *Code and automation*, click **Branches**.
3. **Add or Edit Protection Rule:**
   - Click **Add branch protection rule** (or click **Edit** next to an existing rule for `main`).
   - In **Branch name pattern**, enter your target branch (e.g. `main` or `release/*`).
4. **Require Status Checks to Pass Before Merging:**
   - Check the box: `Require status checks to pass before merging`.
   - **Recommended:** Check `Require branches to be up to date before merging` (ensures the PR was tested against the latest base commit).
5. **Select the AIShield Status Check:**
   - In the search box labeled *Search for status checks in the last week for this repository*, search for:
     ```text
     AIShield Security Debt
     ```
   - Check the checkbox next to `AIShield Security Debt`.
6. **Enforce Administrative Rules:**
   - **Recommended:** Check `Do not allow bypassing the above settings` to ensure administrators and bot accounts follow the same security standards.
7. **Save Changes:**
   - Scroll down and click **Create** or **Save changes**.

---

### Method B: Using Modern GitHub Repository Rulesets (GitHub Enterprise & Public Repos)

1. Go to repository **Settings** -> **Rules** -> **Rulesets**.
2. Click **New ruleset** -> **New branch ruleset**.
3. Enter Ruleset name: `Enforce AIShield Security Gate`.
4. Set **Enforcement status** to `Active`.
5. Under **Target branches**, select *Include default branch* (or specify inclusion patterns).
6. Under **Rules**, check **Require status checks to pass**:
   - Click **Add checks**.
   - Search for and add:
     ```text
     AIShield Security Debt
     ```
7. Click **Save changes**.

---

## 4. Configurable Policy Thresholds (`.aishieldrc.json`)

AIShield does **not** hardcode a single, universal definition of "safe". Different teams, projects, and lifecycles require different risk tolerances.

You can configure thresholds by adding a `.aishieldrc.json` or `.aishield.json` file to the root of your repository (or in `.github/aishield-policy.json`).

### 4.1 Configuration Schema & Reference

```json
{
  "$schema": "https://aishield.dev/schemas/policy.json",
  "policyName": "Custom Team Policy",
  "checkName": "AIShield Security Debt",
  "maxAllowedNewFindings": {
    "maxCriticalAllowed": 0,
    "maxHighAllowed": 0,
    "maxMediumAllowed": 5
  },
  "maxNewDebtPoints": 15.0,
  "maxNetDebtChange": 10.0,
  "maxHeadScore": 70.0,
  "failOnSecrets": true,
  "requireConfirmedScannerForFail": false,
  "warnOnHigh": true,
  "warnOnMedium": true,
  "warnDebtDeltaThreshold": 5.0,
  "warnHeadScoreThreshold": 40.0
}
```

### Parameter Reference

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `policyName` | `string` | `"Standard Policy"` | Human-readable name displayed in check summaries. |
| `checkName` | `string` | `"AIShield Security Debt"` | Name of the GitHub Check Run. Must match the branch protection rule check name. |
| `maxAllowedNewFindings.maxCriticalAllowed` | `number` | `0` | Maximum new CRITICAL findings permitted in a PR before failing. |
| `maxAllowedNewFindings.maxHighAllowed` | `number` | `0` | Maximum new HIGH findings permitted before failing. |
| `maxAllowedNewFindings.maxMediumAllowed` | `number` | `undefined` | Optional ceiling on new MEDIUM findings before failing. |
| `maxNetDebtChange` | `number` | `undefined` | Maximum allowed increase in net security debt (`headScore - baseScore`) before failing. |
| `maxNewDebtPoints` | `number` | `undefined` | Maximum raw debt points introduced by PR before failing. |
| `maxHeadScore` | `number` | `undefined` | Absolute debt ceiling (0-100) allowed in repository. |
| `failOnSecrets` | `boolean` | `true` | Immediately FAIL if exposed credentials or secrets are introduced. |
| `requireConfirmedScannerForFail` | `boolean` | `false` | If `true`, only deterministic scanner findings trigger FAIL; AI findings trigger WARN. |
| `warnOnHigh` | `boolean` | `true` | Trigger WARN when new HIGH issues require review (if under FAIL threshold). |
| `warnOnMedium` | `boolean` | `true` | Trigger WARN when new MEDIUM issues are introduced. |
| `warnDebtDeltaThreshold` | `number` | `undefined` | Debt increase delta that triggers an advisory review warning (e.g. `+5.0`). |
| `warnHeadScoreThreshold` | `number` | `undefined` | Absolute debt score that triggers an advisory warning (e.g. `40.0`). |

---

## 5. Policy Templates by Team Profile

### 5.1 Strict Production Policy (Zero-Tolerance)
Recommended for critical infrastructure, financial services, and security-sensitive repositories.

```json
{
  "policyName": "Strict Production Policy",
  "maxAllowedNewFindings": {
    "maxCriticalAllowed": 0,
    "maxHighAllowed": 0,
    "maxMediumAllowed": 0
  },
  "maxNetDebtChange": 0,
  "failOnSecrets": true,
  "warnOnMedium": true
}
```

### 5.2 Balanced Engineering Policy (Recommended Default)
Recommended for standard agile web applications and backend services. Zero tolerance for criticals and credentials, with review warnings for medium issues and debt changes.

```json
{
  "policyName": "Balanced Engineering Policy",
  "maxAllowedNewFindings": {
    "maxCriticalAllowed": 0,
    "maxHighAllowed": 0
  },
  "maxNetDebtChange": 10.0,
  "failOnSecrets": true,
  "warnOnHigh": true,
  "warnOnMedium": true,
  "warnDebtDeltaThreshold": 5.0
}
```

### 5.3 Legacy Migration & Debt Burn-Down Policy
Recommended for legacy codebases undergoing gradual refactoring. Allows existing debt while preventing large regressions and requiring review.

```json
{
  "policyName": "Legacy Burn-Down Policy",
  "maxAllowedNewFindings": {
    "maxCriticalAllowed": 0,
    "maxHighAllowed": 2
  },
  "maxNetDebtChange": 20.0,
  "failOnSecrets": true,
  "requireConfirmedScannerForFail": true,
  "warnOnHigh": true,
  "warnOnMedium": false,
  "warnDebtDeltaThreshold": 10.0
}
```

---

## 6. Environment Variable Overrides for Workflows

You can also override thresholds dynamically in `.github/workflows/aishield-pr-analysis.yml`:

```yaml
- name: Run AIShield PR Security Analysis
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    GITHUB_EVENT_PATH: ${{ github.event_path }}
    AISHIELD_MAX_CRITICAL: '0'
    AISHIELD_MAX_HIGH: '0'
    AISHIELD_MAX_NET_DEBT: '10'
    AISHIELD_WARN_DEBT_DELTA: '5'
    AISHIELD_FAIL_ON_SECRETS: 'true'
  run: |
    node apps/worker/dist/github/run-pr-analysis.js
```
