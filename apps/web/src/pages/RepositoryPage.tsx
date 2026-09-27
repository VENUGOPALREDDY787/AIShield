import React, { useEffect, useState } from 'react';
import { DebtScoreCard } from '../components/debt/DebtScoreCard.js';
import { DebtTrendChart } from '../components/debt/DebtTrendChart.js';
import { PullRequestTable } from '../components/pull-requests/PullRequestTable.js';
import { FindingsTable } from '../components/findings/FindingsTable.js';
import {
  fetchDebtHistory,
  fetchPullRequests,
  fetchRepositories,
  fetchRepositoryById,
  fetchRepositoryFindings,
  triggerScan,
} from '../services/api.js';
import type {
  DebtHistoryEntry,
  DisplayFinding,
  PageRoute,
  PullRequestSummary,
  RepositorySummary,
} from '../types/index.js';

interface RepositoryPageProps {
  repoId?: string;
  onNavigate: (route: PageRoute) => void;
}

export const RepositoryPage: React.FC<RepositoryPageProps> = ({ repoId, onNavigate }) => {
  const [loading, setLoading] = useState(true);
  const [repositories, setRepositories] = useState<RepositorySummary[]>([]);
  const [currentRepo, setCurrentRepo] = useState<RepositorySummary | null>(null);
  const [history, setHistory] = useState<DebtHistoryEntry[]>([]);
  const [pullRequests, setPullRequests] = useState<PullRequestSummary[]>([]);
  const [findings, setFindings] = useState<DisplayFinding[]>([]);
  const [scanTriggering, setScanTriggering] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);

  useEffect(() => {
    async function loadRepoData() {
      setLoading(true);
      try {
        const repos = await fetchRepositories();
        setRepositories(repos);

        const targetId = repoId || repos[0]?.id || '';
        const repo = await fetchRepositoryById(targetId);
        setCurrentRepo(repo);

        if (targetId) {
          const [histData, prsData, findingsData] = await Promise.all([
            fetchDebtHistory(targetId),
            fetchPullRequests(targetId),
            fetchRepositoryFindings(targetId),
          ]);
          setHistory(histData);
          setPullRequests(prsData);
          setFindings(findingsData);
        }
      } catch (err) {
        console.error('Failed to load repository data:', err);
      } finally {
        setLoading(false);
      }
    }

    loadRepoData();
  }, [repoId]);

  const handleTriggerScan = async () => {
    if (!currentRepo) return;
    setScanTriggering(true);
    setScanMessage(null);
    try {
      const res = await triggerScan(currentRepo.id, 'HEAD', currentRepo.defaultBranch);
      setScanMessage(`Scan job successfully enqueued! Job ID: ${res.jobId}`);
    } catch {
      setScanMessage('Scan triggered in demo mode.');
    } finally {
      setScanTriggering(false);
    }
  };

  if (loading || !currentRepo) {
    return (
      <div className="page-content loading-state">
        <div className="spinner"></div>
        <p>Loading repository security details...</p>
      </div>
    );
  }

  return (
    <div className="page-content">
      {/* Breadcrumbs */}
      <div className="breadcrumb-nav">
        <button className="breadcrumb-link" onClick={() => onNavigate({ name: 'dashboard' })}>
          Dashboard
        </button>
        <span className="breadcrumb-separator">/</span>
        <span className="breadcrumb-current">Repositories</span>
        <span className="breadcrumb-separator">/</span>
        <span className="breadcrumb-current">{currentRepo.name}</span>
      </div>

      {/* Repository Header Card */}
      <div className="repo-detail-header card">
        <div className="repo-title-row">
          <div>
            <div className="repo-badge-row">
              <h2>{currentRepo.fullName}</h2>
              <span className="badge badge-neutral">{currentRepo.primaryLanguage || 'TypeScript'}</span>
              <span className="badge badge-success">Branch: {currentRepo.defaultBranch}</span>
            </div>
            <p className="repo-meta-text">
              Last scanned: {currentRepo.lastScannedAt ? new Date(currentRepo.lastScannedAt).toLocaleString() : 'Never'}
            </p>
          </div>

          <div className="repo-header-actions">
            <select
              className="filter-select"
              value={currentRepo.id}
              onChange={(e) => onNavigate({ name: 'repository', repoId: e.target.value })}
            >
              {repositories.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.fullName}
                </option>
              ))}
            </select>

            <button
              className="btn btn-primary"
              disabled={scanTriggering}
              onClick={handleTriggerScan}
            >
              {scanTriggering ? 'Enqueuing Scan...' : '▶ Trigger Full Scan'}
            </button>
          </div>
        </div>

        {scanMessage && <div className="scan-alert-banner">{scanMessage}</div>}
      </div>

      {/* Current Score & Historical Trend Section */}
      <div className="repo-grid-two-col">
        <DebtScoreCard
          score={currentRepo.currentScore}
          grade={currentRepo.currentGrade}
          riskLevel={currentRepo.criticalFindingsCount > 0 ? 'CRITICAL' : 'MEDIUM'}
          totalPoints={currentRepo.totalDebtPoints}
          activeFindings={findings.length}
        />

        <DebtTrendChart history={history} />
      </div>

      {/* Pull Request History Section */}
      <div className="section-block">
        <PullRequestTable
          pullRequests={pullRequests}
          onSelectPR={(prId) => onNavigate({ name: 'pull-request', prId })}
        />
      </div>

      {/* Open Security Findings Section */}
      <div className="section-block">
        <FindingsTable
          findings={findings}
          title={`Open Security Findings for ${currentRepo.name}`}
          onSelectFinding={(findingId) => onNavigate({ name: 'finding-details', findingId })}
        />
      </div>
    </div>
  );
};
