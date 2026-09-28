import React, { useEffect, useState } from 'react';
import { DebtScoreCard } from '../components/debt/DebtScoreCard.js';
import { DebtTrendCard } from '../components/debt/DebtTrendCard.js';
import { SeverityBreakdownCard } from '../components/debt/SeverityBreakdownCard.js';
import { CategoryBreakdownCard } from '../components/debt/CategoryBreakdownCard.js';
import { DebtTrendChart } from '../components/debt/DebtTrendChart.js';
import { PullRequestTable } from '../components/pull-requests/PullRequestTable.js';
import { ScansTable } from '../components/scans/ScansTable.js';
import { FindingsTable } from '../components/findings/FindingsTable.js';
import {
  fetchDebtHistory,
  fetchPullRequests,
  fetchRepositories,
  fetchRepositoryFindings,
  fetchScans,
} from '../services/api.js';
import type {
  DebtHistoryEntry,
  DisplayFinding,
  PageRoute,
  PullRequestSummary,
  RepositorySummary,
  ScanDetails,
} from '../types/index.js';

import { QuickScanModal } from '../components/scans/QuickScanModal.js';

interface DashboardPageProps {
  onNavigate: (route: PageRoute) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  const [loading, setLoading] = useState(true);
  const [repositories, setRepositories] = useState<RepositorySummary[]>([]);
  const [selectedRepoId, setSelectedRepoId] = useState<string>('');
  const [pullRequests, setPullRequests] = useState<PullRequestSummary[]>([]);
  const [scans, setScans] = useState<ScanDetails[]>([]);
  const [findings, setFindings] = useState<DisplayFinding[]>([]);
  const [history, setHistory] = useState<DebtHistoryEntry[]>([]);
  const [showQuickScan, setShowQuickScan] = useState<boolean>(false);

  useEffect(() => {
    async function loadDashboardData() {
      setLoading(true);
      try {
        const [reposData, prsData, scansData, historyData] = await Promise.all([
          fetchRepositories(),
          fetchPullRequests(),
          fetchScans(),
          fetchDebtHistory(),
        ]);

        setRepositories(reposData);
        const activeRepo = reposData[0];
        const repoId = activeRepo?.id || '';
        setSelectedRepoId(repoId);

        setPullRequests(prsData);
        setScans(scansData);
        setHistory(historyData);

        if (repoId) {
          const findingsData = await fetchRepositoryFindings(repoId);
          setFindings(findingsData);
        }
      } catch (err) {
        console.error('Failed to load dashboard data:', err);
      } finally {
        setLoading(false);
      }
    }

    loadDashboardData();
  }, []);

  const currentRepo = repositories.find((r) => r.id === selectedRepoId) || repositories[0];

  // Aggregate metrics across active findings
  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = findings.filter((f) => f.severity === 'MEDIUM').length;
  const lowCount = findings.filter((f) => f.severity === 'LOW').length;

  const newFindingsCount = findings.filter((f) => f.isNewInPr).length;
  const resolvedFindingsCount = scans[0]?.summary?.resolvedFindings ?? 1;

  // Category breakdown calculation
  const categoryCounts: Record<string, number> = {};
  for (const f of findings) {
    categoryCounts[f.category] = (categoryCounts[f.category] || 0) + 1;
  }

  const riskLevel =
    criticalCount > 0 ? 'CRITICAL' : highCount > 0 ? 'HIGH' : mediumCount > 0 ? 'MEDIUM' : 'LOW';

  return (
    <div className="page-content">
      {/* Repository Selection & Quick Action Bar */}
      <div className="repo-banner">
        <div className="repo-meta-col">
          <span className="section-eyebrow">MONITORED REPOSITORY</span>
          <div className="repo-select-wrapper">
            <select
              className="repo-dropdown"
              value={selectedRepoId}
              onChange={(e) => {
                const id = e.target.value;
                setSelectedRepoId(id);
                fetchRepositoryFindings(id).then(setFindings);
              }}
            >
              {repositories.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.fullName} ({r.defaultBranch})
                </option>
              ))}
            </select>
            <span className="language-badge">{currentRepo?.primaryLanguage || 'TypeScript'}</span>
          </div>
        </div>

        <div className="repo-actions">
          <button
            className="btn btn-primary"
            style={{ backgroundColor: '#238636', borderColor: '#238636', fontWeight: 'bold' }}
            onClick={() => setShowQuickScan(true)}
          >
            ⚡ Scan Custom Path / Repo
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => onNavigate({ name: 'repository', repoId: selectedRepoId })}
          >
            Repository View →
          </button>
          <button
            className="btn btn-primary"
            onClick={() => {
              if (scans[0]) onNavigate({ name: 'scan-details', scanId: scans[0].id });
            }}
          >
            Latest Scan Report
          </button>
        </div>
      </div>

      <QuickScanModal
        isOpen={showQuickScan}
        onClose={() => setShowQuickScan(false)}
        onScanComplete={(res) => {
          console.log('Scanned:', res);
          // Dynamically prepend new findings
          if (res.findings.length > 0) {
            setFindings((prev) => [...res.findings, ...prev]);
          }
        }}
      />

      {loading ? (
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Loading security debt analytics...</p>
        </div>
      ) : (
        <>
          {/* Top Metric Cards: Score, Trend, Severity, Categories */}
          <div className="dashboard-grid-cards">
            <DebtScoreCard
              score={currentRepo?.currentScore ?? 78.5}
              grade={currentRepo?.currentGrade ?? 'B'}
              riskLevel={riskLevel}
              totalPoints={currentRepo?.totalDebtPoints ?? 21.5}
              activeFindings={findings.length}
            />

            <DebtTrendCard
              trend={currentRepo?.trend ?? 'improving'}
              delta={currentRepo?.scoreDelta ?? 6.5}
              newFindingsCount={newFindingsCount}
              resolvedFindingsCount={resolvedFindingsCount}
            />

            <SeverityBreakdownCard
              critical={criticalCount}
              high={highCount}
              medium={mediumCount}
              low={lowCount}
            />

            <CategoryBreakdownCard categories={categoryCounts} />
          </div>

          {/* Longitudinal Trend Chart */}
          <div className="section-block">
            <DebtTrendChart history={history} />
          </div>

          {/* Active Pull Requests Analysis */}
          <div className="section-block">
            <PullRequestTable
              pullRequests={pullRequests}
              onSelectPR={(prId) => onNavigate({ name: 'pull-request', prId })}
            />
          </div>

          {/* Recent Scans Pipeline */}
          <div className="section-block">
            <ScansTable
              scans={scans}
              onSelectScan={(scanId) => onNavigate({ name: 'scan-details', scanId })}
            />
          </div>

          {/* Open Findings List */}
          <div className="section-block">
            <FindingsTable
              findings={findings}
              onSelectFinding={(findingId) => onNavigate({ name: 'finding-details', findingId })}
            />
          </div>
        </>
      )}
    </div>
  );
};
