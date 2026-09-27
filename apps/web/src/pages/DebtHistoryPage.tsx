import React, { useEffect, useState } from 'react';
import { Badge } from '../components/common/Badge.js';
import { DebtTrendChart } from '../components/debt/DebtTrendChart.js';
import { fetchDebtHistory, fetchRepositories } from '../services/api.js';
import type { DebtHistoryEntry, PageRoute, RepositorySummary } from '../types/index.js';

interface DebtHistoryPageProps {
  repoId?: string;
  onNavigate: (route: PageRoute) => void;
}

export const DebtHistoryPage: React.FC<DebtHistoryPageProps> = ({ repoId, onNavigate }) => {
  const [loading, setLoading] = useState(true);
  const [repositories, setRepositories] = useState<RepositorySummary[]>([]);
  const [selectedRepoId, setSelectedRepoId] = useState<string>(repoId || '');
  const [history, setHistory] = useState<DebtHistoryEntry[]>([]);

  useEffect(() => {
    async function loadHistory() {
      setLoading(true);
      try {
        const repos = await fetchRepositories();
        setRepositories(repos);
        const targetId = selectedRepoId || repos[0]?.id || '';
        if (!selectedRepoId && targetId) {
          setSelectedRepoId(targetId);
        }

        const hist = await fetchDebtHistory(targetId);
        setHistory(hist);
      } catch (err) {
        console.error('Failed to load history:', err);
      } finally {
        setLoading(false);
      }
    }

    loadHistory();
  }, [selectedRepoId]);

  return (
    <div className="page-content">
      {/* Breadcrumbs */}
      <div className="breadcrumb-nav">
        <button className="breadcrumb-link" onClick={() => onNavigate({ name: 'dashboard' })}>
          Dashboard
        </button>
        <span className="breadcrumb-separator">/</span>
        <span className="breadcrumb-current">Security Debt History Ledger</span>
      </div>

      {/* Header Selector */}
      <div className="repo-banner">
        <div>
          <h2>Security Debt Historical Audit Ledger</h2>
          <span className="branch-indicator">
            Append-only immutable record of score changes, scans, and remediations.
          </span>
        </div>

        <div className="repo-actions">
          <select
            className="filter-select"
            value={selectedRepoId}
            onChange={(e) => setSelectedRepoId(e.target.value)}
          >
            {repositories.map((r) => (
              <option key={r.id} value={r.id}>
                {r.fullName}
              </option>
            ))}
          </select>
        </div>
      </div>

      {loading ? (
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Loading historical ledger...</p>
        </div>
      ) : (
        <>
          {/* Trend Chart */}
          <div className="section-block">
            <DebtTrendChart history={history} height={220} />
          </div>

          {/* Audit Event Ledger Table */}
          <div className="card section-block">
            <div className="card-header">
              <h3>Immutable Change Events Ledger</h3>
              <span className="count-pill">{history.length} recorded change events</span>
            </div>

            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Event Type</th>
                    <th>Score</th>
                    <th>Delta</th>
                    <th>Grade</th>
                    <th>Open Issues</th>
                    <th>Breakdown (C/H/M/L)</th>
                    <th>Linked Context</th>
                  </tr>
                </thead>
                <tbody>
                  {history.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="empty-state">
                        No historical entries recorded yet.
                      </td>
                    </tr>
                  ) : (
                    history.map((entry) => {
                      const isPositive = (entry.delta ?? 0) > 0;
                      const isNegative = (entry.delta ?? 0) < 0;

                      return (
                        <tr key={entry.id}>
                          <td>
                            <strong>{new Date(entry.recordedAt).toLocaleString()}</strong>
                          </td>
                          <td>
                            <span className="category-tag">{entry.event.replace('_', ' ').toUpperCase()}</span>
                          </td>
                          <td>
                            <strong className="score-number-cell">
                              {Math.round(entry.overallScore * 10) / 10}
                            </strong>
                            <span className="score-denom-sub">/100</span>
                          </td>
                          <td>
                            {entry.delta !== undefined ? (
                              <span
                                className={`delta-badge ${
                                  isPositive ? 'debt-better' : isNegative ? 'debt-worse' : 'debt-neutral'
                                }`}
                              >
                                {isPositive ? `+${entry.delta}` : `${entry.delta}`}
                              </span>
                            ) : (
                              <span className="text-muted">-</span>
                            )}
                          </td>
                          <td>
                            <Badge
                              label={`Grade ${entry.grade || 'B'}`}
                              variant={entry.grade === 'A' ? 'success' : entry.grade === 'B' ? 'info' : 'warning'}
                              size="sm"
                            />
                          </td>
                          <td>
                            <span>{entry.findingCounts?.open ?? 0} active</span>
                          </td>
                          <td>
                            <span className="severity-counts-inline">
                              <span className="count-crit">{entry.severityBreakdown?.CRITICAL ?? 0}C</span> •{' '}
                              <span className="count-hi">{entry.severityBreakdown?.HIGH ?? 0}H</span> •{' '}
                              <span className="count-med">{entry.severityBreakdown?.MEDIUM ?? 0}M</span> •{' '}
                              <span className="count-lo">{entry.severityBreakdown?.LOW ?? 0}L</span>
                            </span>
                          </td>
                          <td>
                            {entry.scanId && (
                              <button
                                className="btn-link"
                                onClick={() => onNavigate({ name: 'scan-details', scanId: entry.scanId! })}
                              >
                                Scan Report →
                              </button>
                            )}
                            {entry.pullRequestId && (
                              <button
                                className="btn-link"
                                onClick={() => onNavigate({ name: 'pull-request', prId: entry.pullRequestId! })}
                              >
                                PR Review →
                              </button>
                            )}
                            {!entry.scanId && !entry.pullRequestId && (
                              <span className="text-muted">Repository Baseline</span>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
