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
          const repoId = `repo-${res.repoName.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;
          const newRepo: RepositorySummary = {
            id: repoId,
            name: res.repoName,
            fullName: res.repoName.includes('/') ? res.repoName : `local/${res.repoName}`,
            defaultBranch: 'main',
            primaryLanguage: 'JavaScript',
            currentScore: res.score,
            currentGrade: res.grade as any,
            totalDebtPoints: Math.round(res.score * 1.2),
            activeFindingsCount: res.findings.length,
            criticalFindingsCount: res.findings.filter((f) => f.severity === 'CRITICAL').length,
            highFindingsCount: res.findings.filter((f) => f.severity === 'HIGH').length,
            mediumFindingsCount: res.findings.filter((f) => f.severity === 'MEDIUM').length,
            lowFindingsCount: res.findings.filter((f) => f.severity === 'LOW').length,
            trend: res.score > 50 ? 'worsening' : 'improving',
            scanEnabled: true,
          };

          setRepositories((prev) => [newRepo, ...prev.filter((r) => r.id !== repoId)]);
          setSelectedRepoId(repoId);
          setFindings(res.findings);

          const newHistoryEntry: DebtHistoryEntry = {
            id: `hist-${Date.now()}`,
            repositoryId: repoId,
            event: 'scan_completed',
            overallScore: res.score,
            grade: res.grade as any,
            recordedAt: new Date().toISOString(),
            delta: res.score,
            trend: res.score > 50 ? 'worsening' : 'improving',
            severityBreakdown: {
              CRITICAL: res.findings.filter((f) => f.severity === 'CRITICAL').length,
              HIGH: res.findings.filter((f) => f.severity === 'HIGH').length,
              MEDIUM: res.findings.filter((f) => f.severity === 'MEDIUM').length,
              LOW: res.findings.filter((f) => f.severity === 'LOW').length,
              INFO: 0,
            },
            categoryBreakdown: {
              SAST: res.findings.filter((f) => f.category === 'SAST').length,
              SECRET: res.findings.filter((f) => f.category === 'SECRET').length,
              DEPENDENCY: 0,
              AI_CONTEXTUAL: res.findings.filter((f) => f.category === 'AI_CONTEXTUAL').length,
            },
            findingCounts: {
              total: res.findings.length,
              open: res.findings.length,
              new: res.findings.length,
              resolved: 0,
            },
          };
          setHistory((prev) => [newHistoryEntry, ...prev]);

          const newScan: ScanDetails = {
            id: `scan-${Date.now()}`,
            repositoryId: repoId,
            repositoryName: newRepo.fullName,
            commitSha: '9988776',
            branch: 'main',
            trigger: 'manual',
            enqueuedAt: new Date(Date.now() - 3000).toISOString(),
            status: 'succeeded',
            score: res.score,
            grade: res.grade as any,
            riskLevel: res.riskLevel as any,
            startedAt: new Date(Date.now() - 2500).toISOString(),
            finishedAt: new Date().toISOString(),
            durationMs: 1420,
            components: [
              { source: 'semgrep', status: 'succeeded', durationMs: 240, findingCount: res.findings.filter((f) => f.source === 'semgrep').length },
              { source: 'gitleaks', status: 'succeeded', durationMs: 180, findingCount: res.findings.filter((f) => f.source === 'gitleaks').length },
              { source: 'dependency', status: 'succeeded', durationMs: 310, findingCount: 0 },
              { source: 'ai-analyzer', status: 'succeeded', durationMs: 690, findingCount: res.findings.filter((f) => f.source === 'ai_analyzer').length },
            ],
            summary: {
              totalFindings: res.findings.length,
              newFindings: res.findings.length,
              resolvedFindings: 0,
              bySeverity: {
                CRITICAL: res.findings.filter((f) => f.severity === 'CRITICAL').length,
                HIGH: res.findings.filter((f) => f.severity === 'HIGH').length,
                MEDIUM: res.findings.filter((f) => f.severity === 'MEDIUM').length,
                LOW: res.findings.filter((f) => f.severity === 'LOW').length,
              },
              byCategory: {
                SAST: res.findings.filter((f) => f.category === 'SAST').length,
                SECRET: res.findings.filter((f) => f.category === 'SECRET').length,
                DEPENDENCY: 0,
                AI_CONTEXTUAL: res.findings.filter((f) => f.category === 'AI_CONTEXTUAL').length,
              },
            },
          };
          setScans((prev) => [newScan, ...prev]);
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
