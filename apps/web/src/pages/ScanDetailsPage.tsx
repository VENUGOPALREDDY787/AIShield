import React, { useEffect, useState } from 'react';
import { Badge } from '../components/common/Badge.js';
import { FindingsTable } from '../components/findings/FindingsTable.js';
import { fetchRepositoryFindings, fetchScanById } from '../services/api.js';
import type { DisplayFinding, PageRoute, ScanDetails } from '../types/index.js';

interface ScanDetailsPageProps {
  scanId: string;
  onNavigate: (route: PageRoute) => void;
}

export const ScanDetailsPage: React.FC<ScanDetailsPageProps> = ({ scanId, onNavigate }) => {
  const [loading, setLoading] = useState(true);
  const [scan, setScan] = useState<ScanDetails | null>(null);
  const [findings, setFindings] = useState<DisplayFinding[]>([]);

  useEffect(() => {
    async function loadScanData() {
      setLoading(true);
      try {
        const scanData = await fetchScanById(scanId);
        setScan(scanData);
        if (scanData) {
          const findingsData = await fetchRepositoryFindings(scanData.repositoryId);
          setFindings(findingsData);
        }
      } catch (err) {
        console.error('Failed to load scan details:', err);
      } finally {
        setLoading(false);
      }
    }

    loadScanData();
  }, [scanId]);

  if (loading || !scan) {
    return (
      <div className="page-content loading-state">
        <div className="spinner"></div>
        <p>Loading scan execution details...</p>
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
        <button
          className="breadcrumb-link"
          onClick={() => onNavigate({ name: 'repository', repoId: scan.repositoryId })}
        >
          {scan.repositoryName}
        </button>
        <span className="breadcrumb-separator">/</span>
        <span className="breadcrumb-current">Scan {scan.id}</span>
      </div>

      {/* Scan Header Card */}
      <div className="card scan-detail-header">
        <div className="scan-title-row">
          <div>
            <div className="scan-status-line">
              <Badge label={scan.status.toUpperCase()} variant={scan.status} />
              <h2>Scan Execution Report</h2>
            </div>
            <p className="scan-meta-details">
              <span>Trigger: <strong>{scan.trigger}</strong></span> •{' '}
              <span>Branch: <code>{scan.branch}</code></span> •{' '}
              <span>Commit: <code>{scan.commitSha?.slice(0, 7)}</code></span> •{' '}
              <span>Duration: <strong>{scan.durationMs ? `${Math.round(scan.durationMs / 1000)}s` : 'N/A'}</strong></span>
            </p>
          </div>

          <div className="scan-score-badge-box">
            <span className="score-denom-label">DEBT SCORE</span>
            <div className="scan-final-score">
              {scan.score !== undefined ? Math.round(scan.score) : '-'}
              <span className="score-max">/100</span>
            </div>
            <Badge label={`Grade ${scan.grade || 'B'}`} variant={scan.grade === 'A' ? 'success' : scan.grade === 'B' ? 'info' : 'warning'} />
          </div>
        </div>
      </div>

      {/* Multi-Scanner Component Status Grid */}
      <div className="section-block">
        <h3 className="section-title">Scanner Pipeline Component Statuses</h3>
        <div className="component-cards-grid">
          {scan.components.map((comp) => (
            <div key={comp.source} className="card component-card">
              <div className="component-card-header">
                <span className="component-name">
                  {comp.source === 'semgrep' && '🔍 Semgrep SAST'}
                  {comp.source === 'gitleaks' && '🔑 Gitleaks Secret Scanner'}
                  {comp.source === 'dependency' && '📦 OSV Dependency Scanner'}
                  {comp.source === 'ai-analyzer' && '🧠 AI Contextual Security Analyzer'}
                </span>
                <Badge label={comp.status.toUpperCase()} variant={comp.status} size="sm" />
              </div>

              <div className="component-card-body">
                <div className="component-stat-row">
                  <span className="text-secondary">Version:</span>
                  <code>{comp.toolVersion || 'embedded'}</code>
                </div>
                <div className="component-stat-row">
                  <span className="text-secondary">Duration:</span>
                  <span>{Math.round(comp.durationMs / 100) / 10}s</span>
                </div>
                <div className="component-stat-row">
                  <span className="text-secondary">Findings Detected:</span>
                  <strong className={comp.findingCount > 0 ? 'text-red' : 'text-green'}>
                    {comp.findingCount} issues
                  </strong>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Debt Calculation Breakdown */}
      <div className="card section-block">
        <div className="card-header">
          <h3>Security Debt Scoring Derivation</h3>
          <span className="info-tooltip">Deterministic & Auditable Formula</span>
        </div>
        <div className="formula-box">
          <code>{scan.formulaSummary || 'Score = 100 - Sum(Weighted Penalties) / Saturation Scale'}</code>
        </div>
        <div className="score-breakdown-details">
          <p>
            Deterministic scanners (Semgrep, Gitleaks, OSV) remain authoritative for concrete CVEs and patterns.
            The AI analyzer provided contextual risk assessment, evaluating authorization boundaries and multi-tenant logic.
          </p>
        </div>
      </div>

      {/* Observed Findings in this scan */}
      <div className="section-block">
        <FindingsTable
          findings={findings}
          title="Findings Captured in this Scan"
          onSelectFinding={(findingId) => onNavigate({ name: 'finding-details', findingId })}
        />
      </div>
    </div>
  );
};
