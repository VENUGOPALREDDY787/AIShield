import React, { useEffect, useState } from 'react';
import { Badge } from '../components/common/Badge.js';
import { FindingsTable } from '../components/findings/FindingsTable.js';
import { fetchPullRequestById, fetchRepositoryFindings } from '../services/api.js';
import type { DisplayFinding, PageRoute, PullRequestSummary } from '../types/index.js';

interface PullRequestPageProps {
  prId: string;
  onNavigate: (route: PageRoute) => void;
}

export const PullRequestPage: React.FC<PullRequestPageProps> = ({ prId, onNavigate }) => {
  const [loading, setLoading] = useState(true);
  const [pr, setPr] = useState<PullRequestSummary | null>(null);
  const [findings, setFindings] = useState<DisplayFinding[]>([]);

  useEffect(() => {
    async function loadPRData() {
      setLoading(true);
      try {
        const prData = await fetchPullRequestById(prId);
        setPr(prData);
        if (prData) {
          const allFindings = await fetchRepositoryFindings(prData.repositoryId);
          // Highlight findings associated with this PR
          setFindings(allFindings);
        }
      } catch (err) {
        console.error('Failed to load PR data:', err);
      } finally {
        setLoading(false);
      }
    }

    loadPRData();
  }, [prId]);

  if (loading || !pr) {
    return (
      <div className="page-content loading-state">
        <div className="spinner"></div>
        <p>Loading pull request security analysis...</p>
      </div>
    );
  }

  const prIntroducedFindings = findings.filter((f) => f.isNewInPr);
  const isFail = (pr.checkStatus || (pr.findingsIntroduced > 0 ? 'FAIL' : 'PASS')) === 'FAIL';

  return (
    <div className="page-content">
      {/* Breadcrumbs */}
      <div className="breadcrumb-nav">
        <button className="breadcrumb-link" onClick={() => onNavigate({ name: 'dashboard' })}>
          Dashboard
        </button>
        <span className="breadcrumb-separator">/</span>
        <button
          className="breadcrumb-link"
          onClick={() => onNavigate({ name: 'repository', repoId: pr.repositoryId })}
        >
          {pr.repositoryName}
        </button>
        <span className="breadcrumb-separator">/</span>
        <span className="breadcrumb-current">PR #{pr.number}</span>
      </div>

      {/* PR Header Banner */}
      <div className="pr-detail-banner card">
        <div className="pr-header-left">
          <div className="pr-status-row">
            <span className="pr-hero-number">#{pr.number}</span>
            <h2>{pr.title}</h2>
            <Badge label={pr.status.toUpperCase()} variant="neutral" />
          </div>

          <div className="pr-meta-row">
            <span>Author: <strong>@{pr.author}</strong></span>
            <span>•</span>
            <span>
              Merging <code>{pr.sourceBranch}</code> into <code>{pr.targetBranch}</code>
            </span>
            <span>•</span>
            <span>Commit: <code>{pr.headSha?.slice(0, 7)}</code></span>
          </div>
        </div>

        <div className="pr-check-verdict">
          <span className="verdict-label">AIShield Security Check</span>
          <div className={`verdict-badge ${isFail ? 'verdict-fail' : 'verdict-pass'}`}>
            {isFail ? '❌ FAIL' : '✅ PASS'}
          </div>
          <span className="verdict-explanation">
            {isFail
              ? 'Critical/High security debt introduced. Branch protection requires resolution before merge.'
              : 'Security debt is within allowable policy threshold.'}
          </span>
        </div>
      </div>

      {/* Debt Delta & Impact Metrics Grid */}
      <div className="dashboard-grid-cards">
        <div className="card stat-card">
          <span className="stat-label">Net Security Debt Delta</span>
          <div className={`delta-big-number ${pr.scoreDelta > 0 ? 'text-green' : pr.scoreDelta < 0 ? 'text-red' : ''}`}>
            {pr.scoreDelta > 0 ? `+${pr.scoreDelta} pts` : `${pr.scoreDelta} pts`}
          </div>
          <span className="stat-subtext">Change in repository health score</span>
        </div>

        <div className="card stat-card">
          <span className="stat-label">New Weaknesses Introduced</span>
          <div className="stat-big-number text-red">+{pr.findingsIntroduced}</div>
          <span className="stat-subtext">Detected in changed files / diff</span>
        </div>

        <div className="card stat-card">
          <span className="stat-label">Vulnerabilities Resolved</span>
          <div className="stat-big-number text-green">-{pr.findingsResolved}</div>
          <span className="stat-subtext">Security debt eliminated in PR</span>
        </div>

        <div className="card stat-card">
          <span className="stat-label">Files Analyzed in PR</span>
          <div className="stat-big-number">{pr.changedFilesCount || 7}</div>
          <span className="stat-subtext">Checked by Semgrep, Gitleaks, OSV, AI</span>
        </div>
      </div>

      {/* Changed Files with Security Findings */}
      <div className="card section-block">
        <div className="card-header">
          <h3>Modified Files in PR</h3>
          <span className="count-pill">{pr.changedFilesCount || 7} files</span>
        </div>
        <div className="files-changed-list">
          <div className="file-row">
            <span className="file-status-icon modified">M</span>
            <code className="file-path">src/services/query-builder.ts</code>
            <Badge label="1 CRITICAL" variant="critical" size="sm" />
          </div>
          <div className="file-row">
            <span className="file-status-icon modified">M</span>
            <code className="file-path">src/controllers/export.controller.ts</code>
            <Badge label="1 HIGH" variant="high" size="sm" />
          </div>
          <div className="file-row">
            <span className="file-status-icon modified">M</span>
            <code className="file-path">tests/fixtures/ci-config.json</code>
            <Badge label="1 HIGH (SECRET)" variant="high" size="sm" />
          </div>
          <div className="file-row">
            <span className="file-status-icon modified">M</span>
            <code className="file-path">package.json</code>
            <Badge label="CLEAN" variant="success" size="sm" />
          </div>
        </div>
      </div>

      {/* PR Findings Table with Remediation Links */}
      <div className="section-block">
        <FindingsTable
          findings={prIntroducedFindings.length > 0 ? prIntroducedFindings : findings}
          title="Security Findings Introduced by This PR"
          onSelectFinding={(findingId) => onNavigate({ name: 'finding-details', findingId })}
        />
      </div>
    </div>
  );
};
